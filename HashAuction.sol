// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * HASH-BASED COMMIT-REVEAL AUCTION WITH RSA-ENCRYPTED PRIZE
 * ===========================================================
 * Hackathon - Security & Privacy - UPF 2025-26
 *
 * BUG FIXES vs previous version
 * ───────────────────────────────
 * 1. _buildRanking() is now idempotent (guarded by rankingBuilt flag).
 *    Previously it could push duplicate entries on multiple autoAdvance calls.
 *
 * 2. getRankedBidders() computes ranking in memory (view) if the reveal phase
 *    is over but rankingBuilt is still false. The frontend now always gets the
 *    correct ranking even if tickPhase() was never explicitly called.
 *
 * 3. currentPhase() is a pure view based on block.timestamp, not the stored
 *    enum. The stored enum only updates on write txs; this view is always correct.
 */
contract HashAuctionWithPrize {

    enum Phase { BIDDING, REVEAL, CLAIM, ENDED }

    struct Bidder {
        bytes32 bidHash;
        uint256 revealedValue;
        uint256 deposit;
        bool    revealed;
        bool    refunded;
    }

    address public organizer;
    uint256 public depositAmount;
    uint256 public minimumBid;

    // RSA prize — organizer side
    bytes  public encryptedPrize;
    string public organizerRsaPublicKeyN;
    string public organizerRsaPublicKeyE;

    // RSA prize — winner side
    bytes  public prizeForWinner;
    string public winnerRsaPublicKeyN;
    string public winnerRsaPublicKeyE;
    bool   public prizeDelivered;

    uint256 public biddingEnd;
    uint256 public revealEnd;
    uint256 public claimEnd;
    Phase   public phase;

    mapping(address => Bidder) public bidders;
    address[] public bidderList;

    address[] public rankedBidders;
    bool      public rankingBuilt;
    uint256   public claimIndex;
    bool      public prizeClaimed;

    event AuctionCreated(address indexed organizer, uint256 deposit, uint256 minimumBid, uint256 biddingEnd);
    event BidCommitted(address indexed bidder, bytes32 bidHash);
    event BidRevealed(address indexed bidder, uint256 amount);
    event RevealFailed(address indexed bidder);
    event PrizeClaimed(address indexed winner, uint256 winningBid);
    event DepositRefunded(address indexed bidder, uint256 amount);
    event PhaseAdvanced(Phase newPhase);
    event WinnerPublicKeyRegistered(address indexed winner, string rsaN, string rsaE);
    event PrizeDelivered(address indexed winner);

    constructor(
        uint256        _depositAmount,
        uint256        _minimumBid,
        uint256        _biddingDuration,
        uint256        _revealDuration,
        uint256        _claimDuration,
        bytes   memory _encryptedPrize,
        string  memory _organizerRsaPublicKeyN,
        string  memory _organizerRsaPublicKeyE
    ) {
        require(_encryptedPrize.length > 0, "Prize ciphertext required");
        organizer              = msg.sender;
        depositAmount          = _depositAmount;
        minimumBid             = _minimumBid;
        biddingEnd             = block.timestamp + _biddingDuration;
        revealEnd              = biddingEnd + _revealDuration;
        claimEnd               = revealEnd  + _claimDuration;
        encryptedPrize         = _encryptedPrize;
        organizerRsaPublicKeyN = _organizerRsaPublicKeyN;
        organizerRsaPublicKeyE = _organizerRsaPublicKeyE;
        phase                  = Phase.BIDDING;
        emit AuctionCreated(msg.sender, _depositAmount, _minimumBid, biddingEnd);
    }

    modifier autoAdvance() { _advancePhase(); _; }

    function _advancePhase() internal {
        if (phase == Phase.BIDDING && block.timestamp >= biddingEnd) {
            phase = Phase.REVEAL;
            emit PhaseAdvanced(Phase.REVEAL);
        }
        if (phase == Phase.REVEAL && block.timestamp >= revealEnd) {
            _buildRanking();
            phase = Phase.CLAIM;
            emit PhaseAdvanced(Phase.CLAIM);
        }
        if (phase == Phase.CLAIM && block.timestamp >= claimEnd) {
            phase = Phase.ENDED;
            emit PhaseAdvanced(Phase.ENDED);
        }
    }

    function tickPhase() external { _advancePhase(); }

    // ── BIDDING ───────────────────────────────────────────────────────────────

    function bid(bytes32 _bidHash) external payable autoAdvance {
        require(phase == Phase.BIDDING,           "Not bidding phase");
        require(msg.value == depositAmount,       "Wrong deposit");
        require(bidders[msg.sender].deposit == 0, "Already bid");
        require(_bidHash != bytes32(0),           "Empty hash");
        bidders[msg.sender] = Bidder(_bidHash, 0, msg.value, false, false);
        bidderList.push(msg.sender);
        emit BidCommitted(msg.sender, _bidHash);
    }

    // ── REVEAL ────────────────────────────────────────────────────────────────

    function reveal(uint256 _amount, string calldata _password) external autoAdvance {
        require(phase == Phase.REVEAL, "Not reveal phase");
        Bidder storage b = bidders[msg.sender];
        require(b.deposit > 0, "No active bid");
        require(!b.revealed,   "Already revealed");
        bytes32 check = keccak256(abi.encodePacked(_amount, _password));
        if (check == b.bidHash) {
            if (_amount < minimumBid) {
                // Valid hash but bid is below minimum — forfeit deposit
                b.deposit = 0;
                emit RevealFailed(msg.sender);
            } else {
                b.revealedValue = _amount;
                b.revealed      = true;
                emit BidRevealed(msg.sender, _amount);
            }
        } else {
            b.deposit = 0;
            emit RevealFailed(msg.sender);
        }
    }

    // ── Ranking ───────────────────────────────────────────────────────────────

    function _buildRanking() internal {
        if (rankingBuilt) return;
        rankingBuilt = true;

        for (uint256 i = 0; i < bidderList.length; i++) {
            if (bidders[bidderList[i]].revealed) {
                rankedBidders.push(bidderList[i]);
            }
        }
        uint256 n = rankedBidders.length;
        for (uint256 i = 1; i < n; i++) {
            address key    = rankedBidders[i];
            uint256 keyVal = bidders[key].revealedValue;
            int256  j      = int256(i) - 1;
            while (j >= 0 && bidders[rankedBidders[uint256(j)]].revealedValue < keyVal) {
                rankedBidders[uint256(j + 1)] = rankedBidders[uint256(j)];
                j--;
            }
            rankedBidders[uint256(j + 1)] = key;
        }
    }

    // ── CLAIM ─────────────────────────────────────────────────────────────────

    function claimPrize(uint256 _amount, string calldata _password) external autoAdvance {
        require(phase == Phase.CLAIM,                    "Not claim phase");
        require(!prizeClaimed,                           "Already claimed");
        require(rankedBidders.length > 0,                "No valid bids");
        require(claimIndex < rankedBidders.length,       "No more claimants");
        require(msg.sender == rankedBidders[claimIndex], "Not your turn");
        bytes32 check = keccak256(abi.encodePacked(_amount, _password));
        require(check == bidders[msg.sender].bidHash, "Hash mismatch");
        prizeClaimed = true;
        phase        = Phase.ENDED;
        emit PrizeClaimed(msg.sender, bidders[msg.sender].revealedValue);
        emit PhaseAdvanced(Phase.ENDED);
    }

    function skipClaimant() external autoAdvance {
        require(phase == Phase.CLAIM,              "Not claim phase");
        require(!prizeClaimed,                     "Already claimed");
        require(claimIndex < rankedBidders.length, "No more claimants");
        claimIndex++;
    }

    // ── PRIZE DELIVERY ────────────────────────────────────────────────────────

    function registerWinnerPublicKey(
        string calldata _rsaN,
        string calldata _rsaE
    ) external autoAdvance {
        require(phase == Phase.ENDED,                   "Auction not ended");
        require(prizeClaimed,                           "Prize not claimed yet");
        require(msg.sender == rankedBidders[0],         "Not the winner");
        require(bytes(winnerRsaPublicKeyN).length == 0, "Key already registered");
        require(bytes(_rsaN).length > 0 && bytes(_rsaE).length > 0, "Invalid key");
        winnerRsaPublicKeyN = _rsaN;
        winnerRsaPublicKeyE = _rsaE;
        emit WinnerPublicKeyRegistered(msg.sender, _rsaN, _rsaE);
    }

    function deliverPrize(bytes calldata _prizeForWinner) external {
        require(msg.sender == organizer,               "Only organizer");
        require(phase == Phase.ENDED,                  "Auction not ended");
        require(prizeClaimed,                          "Prize not claimed");
        require(bytes(winnerRsaPublicKeyN).length > 0, "Winner key not registered");
        require(!prizeDelivered,                       "Already delivered");
        require(_prizeForWinner.length > 0,            "Empty ciphertext");
        prizeForWinner = _prizeForWinner;
        prizeDelivered = true;
        emit PrizeDelivered(rankedBidders[0]);
    }

    // ── ENDED ─────────────────────────────────────────────────────────────────

    function refund() external autoAdvance {
        require(phase == Phase.ENDED, "Not ended");
        require(prizeClaimed,         "Prize not claimed yet");
        Bidder storage b = bidders[msg.sender];
        require(b.revealed,   "Did not reveal - no refund");
        require(!b.refunded,  "Already refunded");
        require(b.deposit > 0,"Nothing to refund");
        b.refunded    = true;
        uint256 amount = b.deposit;
        b.deposit      = 0;
        (bool ok,) = payable(msg.sender).call{value: amount}("");
        require(ok, "Transfer failed");
        emit DepositRefunded(msg.sender, amount);
    }

    function withdrawForfeited() external autoAdvance {
        require(msg.sender == organizer, "Only organizer");
        require(phase == Phase.ENDED,    "Not ended");
        uint256 total = 0;
        for (uint256 i = 0; i < bidderList.length; i++) {
            Bidder storage b = bidders[bidderList[i]];
            if (!b.revealed && !b.refunded && b.deposit > 0) {
                total    += b.deposit;
                b.deposit = 0;
            }
        }
        require(total > 0, "Nothing to withdraw");
        (bool ok,) = payable(organizer).call{value: total}("");
        require(ok, "Transfer failed");
    }

    // ── View helpers ──────────────────────────────────────────────────────────

    /**
     * @notice Real-time phase based on block.timestamp.
     *         Never stale — does not depend on stored enum.
     */
    function currentPhase() external view returns (string memory) {
        if (block.timestamp < biddingEnd) return "BIDDING";
        if (block.timestamp < revealEnd)  return "REVEAL";
        if (prizeClaimed)                 return "ENDED";
        if (block.timestamp < claimEnd)   return "CLAIM";
        return "ENDED";
    }

    /**
     * @notice Returns ranked bidders. If reveal phase is over but ranking was
     *         not yet written to storage (tickPhase not called), computes it
     *         in memory so the frontend always gets correct data.
     */
    function getRankedBidders() external view returns (address[] memory) {
        if (rankingBuilt) return rankedBidders;

        if (block.timestamp >= revealEnd) {
            uint256 count = 0;
            for (uint256 i = 0; i < bidderList.length; i++) {
                if (bidders[bidderList[i]].revealed) count++;
            }
            address[] memory tmp = new address[](count);
            uint256 idx = 0;
            for (uint256 i = 0; i < bidderList.length; i++) {
                if (bidders[bidderList[i]].revealed) tmp[idx++] = bidderList[i];
            }
            for (uint256 i = 1; i < tmp.length; i++) {
                address key    = tmp[i];
                uint256 keyVal = bidders[key].revealedValue;
                int256  j      = int256(i) - 1;
                while (j >= 0 && bidders[tmp[uint256(j)]].revealedValue < keyVal) {
                    tmp[uint256(j + 1)] = tmp[uint256(j)];
                    j--;
                }
                tmp[uint256(j + 1)] = key;
            }
            return tmp;
        }

        return rankedBidders;
    }

    function getBidderList() external view returns (address[] memory) {
        return bidderList;
    }

    function computeBidHash(
        uint256 _amount,
        string calldata _password
    ) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(_amount, _password));
    }

    function getPrizeStatus() external view returns (
        bool    _prizeClaimed,
        bool    _winnerKeyRegistered,
        bool    _prizeDelivered,
        address _winner
    ) {
        address winner = (rankingBuilt && rankedBidders.length > 0) ? rankedBidders[0] : address(0);
        return (
            prizeClaimed,
            bytes(winnerRsaPublicKeyN).length > 0,
            prizeDelivered,
            winner
        );
    }
}
