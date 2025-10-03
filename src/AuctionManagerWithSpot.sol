// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./VulnerableSealedBidAuctionWithSpot.sol";
import "./HardenedSealedBidAuctionWithSpot.sol";

/// @title AuctionManagerWithSpot
/// @notice Factory + proxy manager for both vulnerable and hardened spot-price auctions.
contract AuctionManagerWithSpot {
    struct AuctionInfo {
        address auction;
        string auctionType; // "vulnerable" or "hardened"
        address priceSource;
    }

    mapping(uint256 => AuctionInfo) public auctions;
    uint256 public auctionCount;

    event AuctionCreated(uint256 indexed id, address auction, string auctionType, address priceSource);

    // ----------------------------
    // Create auctions
    // ----------------------------
    function createVulnerableAuction(
        address beneficiary,
        address paymentToken,
        uint256 commitEndBlock,
        uint256 revealEndBlock,
        uint256 depositAmount,
        address priceSource
    ) external returns (uint256 auctionId) {
        VulnerableSealedBidAuctionWithSpot auction = new VulnerableSealedBidAuctionWithSpot(
            msg.sender, beneficiary, paymentToken, commitEndBlock, revealEndBlock, depositAmount, priceSource
        );
        auctionId = ++auctionCount;
        auctions[auctionId] = AuctionInfo(address(auction), "vulnerable", priceSource);
        emit AuctionCreated(auctionId, address(auction), "vulnerable", priceSource);
    }

    function createHardenedAuction(
        address beneficiary,
        address paymentToken,
        uint256 commitEndBlock,
        uint256 revealEndBlock,
        uint256 depositAmount,
        address priceSource
    ) external returns (uint256 auctionId) {
        HardenedSealedBidAuctionWithSpot auction = new HardenedSealedBidAuctionWithSpot(
            msg.sender, beneficiary, paymentToken, commitEndBlock, revealEndBlock, depositAmount, priceSource
        );
        auctionId = ++auctionCount;
        auctions[auctionId] = AuctionInfo(address(auction), "hardened", priceSource);
        emit AuctionCreated(auctionId, address(auction), "hardened", priceSource);
    }

    // ----------------------------
    // Proxy helpers
    // ----------------------------
    function commit(uint256 auctionId, bytes32 commitment) external payable {
        (bool ok,) =
            auctions[auctionId].auction.call{value: msg.value}(abi.encodeWithSignature("commit(bytes32)", commitment));
        require(ok, "commit failed");
    }

    function reveal(uint256 auctionId, uint256 amount, bytes32 nonce) external payable {
        (bool ok,) = auctions[auctionId].auction.call{value: msg.value}(
            abi.encodeWithSignature("reveal(uint256,bytes32)", amount, nonce)
        );
        require(ok, "reveal failed");
    }

    function finalize(uint256 auctionId) external {
        (bool ok,) = auctions[auctionId].auction.call(abi.encodeWithSignature("finalize()"));
        require(ok, "finalize failed");
    }

    function withdraw(uint256 auctionId) external {
        (bool ok,) = auctions[auctionId].auction.call(abi.encodeWithSignature("withdraw()"));
        require(ok, "withdraw failed");
    }

    // ----------------------------
    // View helpers
    // ----------------------------
    function getAuction(uint256 auctionId) external view returns (AuctionInfo memory) {
        return auctions[auctionId];
    }
}
