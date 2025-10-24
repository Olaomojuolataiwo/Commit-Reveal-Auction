// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./utils/ISimpleAuction.sol";

/// @notice SecureAuction enforces requiredConfirmations (measured in blocks) before a revealed
/// bid can be considered during finalization. This makes finalization resistant to short reorgs
/// as it ignores reveals that are not at least `requiredConfirmations` blocks deep.
contract SecureAuction is ISimpleAuction {
    struct Reveal {
        bytes32 commitHash;
        bool revealed;
        uint256 amount;
        uint256 revealBlock;
    }

    uint256 private immutable _requiredConfirmations;
    mapping(uint256 => mapping(address => Reveal)) public reveals; // auctionId => bidder => reveal
    mapping(uint256 => bool) private _finalized;
    mapping(uint256 => address) private _winner;

    event Committed(uint256 indexed auctionId, address indexed bidder, bytes32 commitHash);
    event Revealed(uint256 indexed auctionId, address indexed bidder, uint256 amount, uint256 revealBlock);
    event Finalized(uint256 indexed auctionId, address indexed winner);

    constructor(uint256 requiredConfirmations_) {
        _requiredConfirmations = requiredConfirmations_;
    }

    // ---- External interface ----
    function requiredConfirmations() external view returns (uint256) {
        return _requiredConfirmations;
    }

    function commit(uint256 auctionId, bytes32 commitHash) external {
        reveals[auctionId][msg.sender].commitHash = commitHash;
        emit Committed(auctionId, msg.sender, commitHash);
    }

    function reveal(uint256 auctionId, uint256 amount, bytes32 salt) external {
        Reveal storage r = reveals[auctionId][msg.sender];
        require(r.commitHash != bytes32(0), "NoCommit");
        require(!r.revealed, "AlreadyRevealed");
        bytes32 expected = keccak256(abi.encodePacked(amount, salt));
        require(expected == r.commitHash, "CommitMismatch");

        r.revealed = true;
        r.amount = amount;
        r.revealBlock = block.number; // record inclusion block
        emit Revealed(auctionId, msg.sender, amount, r.revealBlock);
    }

    /// @notice Finalize using explicit candidates. Only considers reveals that are
    /// sufficiently deep (revealBlock + requiredConfirmations <= block.number).
    function finalizeWithCandidates(uint256 auctionId, address[] calldata candidates) external {
        require(!_finalized[auctionId], "AlreadyFinalized");

        address best;
        uint256 bestAmount;
        bool anyConfirmed = false;

        for (uint i = 0; i < candidates.length; i++) {
            address bidder = candidates[i];
            Reveal storage r = reveals[auctionId][bidder];
            if (!r.revealed) continue;

            // Secure check: require reveal to be deep enough (block confirmations)
            if (block.number < r.revealBlock + _requiredConfirmations) {
                // skip insecure/unsafe reveals that might be orphaned
                continue;
            }

            anyConfirmed = true;
            if (r.amount > bestAmount) {
                bestAmount = r.amount;
                best = bidder;
            }
        }

        require(anyConfirmed, "NotEnoughConfirmationsOrNoReveals");

        _finalized[auctionId] = true;
        _winner[auctionId] = best;
        emit Finalized(auctionId, best);
    }

    // ---- View helpers for tests ----
    function isFinalized(uint256 auctionId) external view returns (bool) {
        return _finalized[auctionId];
    }

    function winnerOf(uint256 auctionId) external view returns (address) {
        return _winner[auctionId];
    }

    function revealBlock(uint256 auctionId, address bidder) external view returns (uint256) {
        return reveals[auctionId][bidder].revealBlock;
    }
}
