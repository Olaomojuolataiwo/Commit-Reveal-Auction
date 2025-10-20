// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title MaliciousConditional
/// @notice Acts as a bidder forwarder and reverts on every N-th received call (default every 3rd).

import "src/utils/ApproveHelper.sol";
import "../utils/IAuctions.sol";

contract MaliciousConditional is ApproveHelper {
    uint256 public calls;
    uint256 public revertEvery; // e.g. 3 => revert every 3rd call
    address public token;       // ERC20 token used for deposits

    constructor(address _token, uint256 _revertEvery) {
        require(_revertEvery > 0, "revertEvery>0");
        require(_token != address(0), "token=0");
        token = _token;
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

    /// Allow the controller EOA to ask this contract to approve a spender for `amount` tokens.
    /// The ERC20 sees the approval coming from THIS contract (so approve sets allowance[thisContract][spender]).
    function approveToken(address spender, uint256 amount) external returns (bool) {
        bool ok = IERC20Approve(token).approve(spender, amount);
        require(ok, "approveToken failed");
        return ok;
    }

    /// Forward a commit to VulnerableAuction variant (with deposit param).
    /// Approves the auction to pull depositAmount from THIS contract before calling commit.
    function forwardCommitVulnerable(
        address auction,
        uint256 auctionId,
        bytes32 commitHash,
        uint256 depositAmount
    ) external {
        require(IERC20Approve(token).approve(auction, depositAmount), "approve failed");

        (bool ok, ) = auction.call(
            abi.encodeWithSignature("commit(uint256,bytes32,uint256)", auctionId, commitHash, depositAmount)
        );
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
