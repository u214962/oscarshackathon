// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * HASH-BASED COMMIT-REVEAL AUCTION
 * ==================================
 * Hackathon - Security & Privacy - UPF 2025-26
 *
 * CRYPTOGRAPHIC PRIMITIVES
 * ========================
 *
 * PRIMITIVE 1: keccak256 hash function (single layer, two parameters)
 * ---------------------------------------------------------------------
 * Every bid is stored on-chain as:
 *
 *   bidHash = keccak256(abi.encodePacked(amount, password))
 *
 * where:
 *   amount   = the bid value in wei (uint256)
 *   password = a secret string chosen by the bidder (string)
 *
 * Security properties of this scheme:
 *   - Pre-image resistance: given bidHash on-chain, nobody can
 *     recover amount or password without trying all combinations.
 *   - Hiding: the actual bid value is invisible during the BIDDING phase.
 *   - Binding: the bidder cannot change amount or password after committing
 *     (changing either produces a completely different hash).
 *   - Front-running resistance: miners/observers see only the hash, not the value.
 *
 * Attack still possible (small input space):
 *   If amount is small and known (e.g. 1-100 ETH), an attacker could
 *   brute-force keccak256(amount, password) for all amounts.
 *   Mitigation: the password adds entropy making brute-force infeasible
 *   as long as the password is strong.
 *
 * PRIMITIVE 2: RSA-OAEP (off-chain, Node.js)
 * -------------------------------------------
 * The organizer encrypts personal data (DNI) with their RSA public key
 * before deploying. Only the ciphertext goes on-chain.
 * Public key components (n, e) are stored for auditability.
 *
 * FLOW
 * ====
 *  BIDDING : bid(keccak256(amount, password)) + deposit
 *  REVEAL  : reveal(amount, password) -> contract recomputes hash and checks
 *  CLAIM   : claimPrize(amount, password) -> winner re-verifies to claim
 *  ENDED   : refund() for all bidders who revealed correctly
 */
contract HashAuction {

    // ----------------------------------------------------------------
    //  Enums & Structs
    // ----------------------------------------------------------------

    enum Phase { BIDDING, REVEAL, CLAIM, ENDED }

    struct Bidder {
        bytes32 bidHash;       // keccak256(abi.encodePacked(amount, password))
        uint256 revealedValue; // populated after successful reveal
        uint256 deposit;       // ETH held as collateral
        bool    revealed;      // true after correct reveal
        bool    refunded;      // true after deposit returned
    }

    // ----------------------------------------------------------------
    //  Storage
    // ----------------------------------------------------------------

    address public organizer;
    string  public prizeKey;        // off-chain prize identifier
    uint256 public depositAmount;   // required collateral per bidder (wei)

    // RSA-encrypted organizer personal data
    bytes  public encryptedOrganizerData; // RSA-OAEP ciphertext (hex bytes)
    string public rsaPublicKeyN;          // modulus (hex string)
    string public rsaPublicKeyE;          // exponent (hex string)

    // Phase timestamps
    uint256 public biddingEnd;
    uint256 public revealEnd;
    uint256 public claimEnd;

    Phase public phase;

    mapping(address => Bidder) public bidders;
    address[] public bidderList;

    // Ranking built at end of REVEAL phase (sorted descending by revealedValue)
    address[] public rankedBidders;
    uint256   public claimIndex;
    bool      public prizeClaimed;

    // ----------------------------------------------------------------
    //  Events
    // ----------------------------------------------------------------

    event AuctionCreated(address indexed organizer, uint256 deposit, uint256 biddingEnd);
    event BidCommitted(address indexed bidder, bytes32 bidHash);
    event BidRevealed(address indexed bidder, uint256 amount);
    event RevealFailed(address indexed bidder);
    event PrizeClaimed(address indexed winner, uint256 winningBid);
    event DepositRefunded(address indexed bidder, uint256 amount);
    event PhaseAdvanced(Phase newPhase);

    // ----------------------------------------------------------------
    //  Constructor
    // ----------------------------------------------------------------

    /**
     * @param _prizeKey               Off-chain prize identifier string
     * @param _depositAmount          Wei required as deposit from each bidder
     * @param _biddingDuration        Seconds the bidding phase lasts
     * @param _revealDuration         Seconds the reveal phase lasts
     * @param _claimDuration          Seconds the claim phase lasts
     * @param _encryptedOrganizerData RSA-OAEP ciphertext of organizer personal data
     * @param _rsaPublicKeyN          RSA modulus as hex string
     * @param _rsaPublicKeyE          RSA exponent as hex string
     */
    constructor(
        string  memory _prizeKey,
        uint256        _depositAmount,
        uint256        _biddingDuration,
        uint256        _revealDuration,
        uint256        _claimDuration,
        bytes   memory _encryptedOrganizerData,
        string  memory _rsaPublicKeyN,
        string  memory _rsaPublicKeyE
    ) {
        organizer              = msg.sender;
        prizeKey               = _prizeKey;
        depositAmount          = _depositAmount;
        biddingEnd             = block.timestamp + _biddingDuration;
        revealEnd              = biddingEnd      + _revealDuration;
        claimEnd               = revealEnd       + _claimDuration;
        encryptedOrganizerData = _encryptedOrganizerData;
        rsaPublicKeyN          = _rsaPublicKeyN;
        rsaPublicKeyE          = _rsaPublicKeyE;
        phase                  = Phase.BIDDING;

        emit AuctionCreated(msg.sender, _depositAmount, biddingEnd);
    }

    // ----------------------------------------------------------------
    //  Phase advancement
    // ----------------------------------------------------------------

    modifier autoAdvance() {
        _advancePhase();
        _;
    }

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

    /// Anyone can call this to push the contract into the correct phase.
    function tickPhase() external {
        _advancePhase();
    }

    // ----------------------------------------------------------------
    //  BIDDING phase
    // ----------------------------------------------------------------

    /**
     * Submit a hashed bid.
     *
     * The bidder computes OFF-CHAIN:
     *   bidHash = keccak256(abi.encodePacked(amount, password))
     *
     * and calls this function with that hash + exactly depositAmount wei.
     *
     * Nothing about the actual bid is visible on-chain during this phase.
     */
    function bid(bytes32 _bidHash) external payable autoAdvance {
        require(phase == Phase.BIDDING,          "Not bidding phase");
        require(msg.value == depositAmount,      "Wrong deposit");
        require(bidders[msg.sender].deposit == 0,"Already bid");
        require(_bidHash != bytes32(0),          "Empty hash");

        bidders[msg.sender] = Bidder({
            bidHash:       _bidHash,
            revealedValue: 0,
            deposit:       msg.value,
            revealed:      false,
            refunded:      false
        });
        bidderList.push(msg.sender);

        emit BidCommitted(msg.sender, _bidHash);
    }

    // ----------------------------------------------------------------
    //  REVEAL phase
    // ----------------------------------------------------------------

    /**
     * Reveal the bid by submitting the original amount and password.
     *
     * The contract recomputes:
     *   check = keccak256(abi.encodePacked(_amount, _password))
     *
     * and compares it to the stored bidHash.
     * If they match  -> bid is accepted, value recorded.
     * If they differ -> deposit is forfeited (prevents fake ghost bids).
     */
    function reveal(uint256 _amount, string calldata _password) external autoAdvance {
        require(phase == Phase.REVEAL, "Not reveal phase");

        Bidder storage b = bidders[msg.sender];
        require(b.deposit > 0,  "No active bid");
        require(!b.revealed,    "Already revealed");

        bytes32 check = keccak256(abi.encodePacked(_amount, _password));

        if (check == b.bidHash) {
            b.revealedValue = _amount;
            b.revealed      = true;
            emit BidRevealed(msg.sender, _amount);
        } else {
            // Hash mismatch: deposit forfeited
            b.deposit = 0;
            emit RevealFailed(msg.sender);
        }
    }

    // ----------------------------------------------------------------
    //  Internal: build sorted ranking after reveal phase
    // ----------------------------------------------------------------

    function _buildRanking() internal {
        for (uint256 i = 0; i < bidderList.length; i++) {
            if (bidders[bidderList[i]].revealed) {
                rankedBidders.push(bidderList[i]);
            }
        }
        // Insertion sort descending by revealedValue
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

    // ----------------------------------------------------------------
    //  CLAIM phase
    // ----------------------------------------------------------------

    /**
     * Claim the prize.
     *
     * The winner must re-verify their bid:
     *   keccak256(abi.encodePacked(_amount, _password)) == stored bidHash
     *
     * This second hash check acts as authentication: only the person who
     * knows the original (amount, password) pair can claim.
     *
     * If the current top bidder does not claim, anyone can call
     * skipClaimant() to advance to the next eligible bidder.
     */
    function claimPrize(uint256 _amount, string calldata _password) external autoAdvance {
        require(phase == Phase.CLAIM,                    "Not claim phase");
        require(!prizeClaimed,                           "Already claimed");
        require(rankedBidders.length > 0,                "No valid bids");
        require(claimIndex < rankedBidders.length,       "No more claimants");
        require(msg.sender == rankedBidders[claimIndex], "Not your turn");

        // Re-verify: same hash check as reveal
        bytes32 check = keccak256(abi.encodePacked(_amount, _password));
        require(check == bidders[msg.sender].bidHash, "Hash mismatch");

        prizeClaimed = true;
        phase        = Phase.ENDED;

        emit PrizeClaimed(msg.sender, bidders[msg.sender].revealedValue);
        emit PhaseAdvanced(Phase.ENDED);
    }

    /**
     * Advance to the next claimant if the current one does not claim.
     * Can be called by anyone.
     */
    function skipClaimant() external autoAdvance {
        require(phase == Phase.CLAIM, "Not claim phase");
        require(!prizeClaimed,        "Already claimed");
        require(claimIndex < rankedBidders.length, "No more claimants");
        claimIndex++;
    }

    // ----------------------------------------------------------------
    //  ENDED phase
    // ----------------------------------------------------------------

    /**
     * Recover deposit.
     * Available to all bidders who correctly revealed their bid,
     * once the prize has been claimed.
     */
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

    /**
     * Organizer collects forfeited deposits from bidders who did not reveal.
     */
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

    // ----------------------------------------------------------------
    //  View helpers
    // ----------------------------------------------------------------

    function currentPhase() external view returns (string memory) {
        if (phase == Phase.BIDDING) return "BIDDING";
        if (phase == Phase.REVEAL)  return "REVEAL";
        if (phase == Phase.CLAIM)   return "CLAIM";
        return "ENDED";
    }

    function getRankedBidders() external view returns (address[] memory) {
        return rankedBidders;
    }

    function getBidderList() external view returns (address[] memory) {
        return bidderList;
    }

    /**
     * Helper: compute the bid hash off-chain equivalent.
     * Call this from Remix to verify your hash before submitting.
     *
     *   bidHash = keccak256(abi.encodePacked(amount, password))
     */
    function computeBidHash(
        uint256 _amount,
        string calldata _password
    ) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(_amount, _password));
    }
}
