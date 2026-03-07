// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BlindAuctionNoFee {
    address public owner;
    uint256 public minimumBid;

    uint256 public commitDeadline;
    uint256 public revealDeadline;

    bool public auctionEnded;
    address public winner;
    uint256 public winningBid;

    struct BidCommitment {
        bytes32 commitment;
        uint256 commitTime;
        bool revealed;
    }

    mapping(address => BidCommitment) public bidCommits;
    address[] public bidders;

    event BidCommitted(address indexed bidder, bytes32 commitment);
    event BidRevealed(address indexed bidder, uint256 amount);
    event AuctionEnded(address indexed winner, uint256 winningBid);

    constructor(
        uint256 _minimumBid,
        uint256 _commitDurationSeconds,
        uint256 _revealDurationSeconds
    ) {
        owner = msg.sender;
        minimumBid = _minimumBid;
        commitDeadline = block.timestamp + _commitDurationSeconds;
        revealDeadline = commitDeadline + _revealDurationSeconds;
    }

    function commitBid(bytes32 _commitment) external {
        require(block.timestamp < commitDeadline, "Commit phase ended");
        require(bidCommits[msg.sender].commitment == bytes32(0), "Already committed");

        bidCommits[msg.sender] = BidCommitment({
            commitment: _commitment,
            commitTime: block.timestamp,
            revealed: false
        });

        bidders.push(msg.sender);

        emit BidCommitted(msg.sender, _commitment);
    }

    function revealBid(uint256 _amount, string calldata _secret) external {
        require(block.timestamp >= commitDeadline, "Reveal phase not started");
        require(block.timestamp < revealDeadline, "Reveal phase ended");

        BidCommitment storage bidData = bidCommits[msg.sender];

        require(bidData.commitment != bytes32(0), "No commitment");
        require(!bidData.revealed, "Already revealed");
        require(_amount >= minimumBid, "Bid below minimum");

        bytes32 calculatedHash = keccak256(
            abi.encodePacked(msg.sender, _amount, _secret)
        );

        require(calculatedHash == bidData.commitment, "Invalid reveal");

        bidData.revealed = true;

        if (_amount > winningBid) {
            winningBid = _amount;
            winner = msg.sender;
        } else if (_amount == winningBid && winner != address(0)) {
            if (bidData.commitTime < bidCommits[winner].commitTime) {
                winner = msg.sender;
            }
        }

        emit BidRevealed(msg.sender, _amount);
    }

    function endAuction() external {
        require(block.timestamp >= revealDeadline, "Reveal phase not ended");
        require(!auctionEnded, "Auction already ended");

        auctionEnded = true;
        emit AuctionEnded(winner, winningBid);
    }

    // El usuario solo pone amount y secret.
    // La address se toma automaticamente de msg.sender.
    function getMyCommitment(
        uint256 _amount,
        string calldata _secret
    ) external view returns (bytes32) {
        return keccak256(abi.encodePacked(msg.sender, _amount, _secret));
    }

    function getCurrentPhase() external view returns (string memory) {
        if (block.timestamp < commitDeadline) {
            return "COMMIT";
        } else if (block.timestamp < revealDeadline) {
            return "REVEAL";
        } else {
            return "ENDED";
        }
    }

    function getBiddersCount() external view returns (uint256) {
        return bidders.length;
    }
}
