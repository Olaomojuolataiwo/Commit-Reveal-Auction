// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title MaliciousConditional
/// @notice Acts as a bidder forwarder and reverts on every N-th received call (default every 3rd).

import "src/utils/ApproveHelper.sol";

contract MaliciousConditional is ApproveHelper {
    uint256 public calls;
    uint256 public revertEvery; // e.g. 3 => revert every 3rd call

    constructor(uint256 _revertEvery) {
        require(_revertEvery > 0, "revertEvery>0");
        revertEvery = _revertEvery;
        calls = 0;
        
	}
    /// @notice Conditional revert behavior: increments call count and reverts on the configured cadence.
    receive() external payable {
        calls += 1;
        if (calls % revertEvery == 0) {
            revert("MaliciousConditional: reverting on cadence");
        }
        // otherwise accept funds (no-op)
        }


    // -------------------------
    // Forwarding helpers (controller EOA calls these so this contract is msg.sender on auction)
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
