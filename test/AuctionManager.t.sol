// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/AuctionManager.sol";
import "../src/MockERC20.sol";

contract AuctionManagerTest is Test {
    AuctionManager manager;
    MockERC20 token;
    address beneficiary = address(0xBEEF);

    function setUp() public {
        // Deploy a mock ERC20
        token = new MockERC20("TestToken", "TTK", 18);

        // Deploy AuctionManager
        manager = new AuctionManager();
    }

    function testCreateAuction() public {
        // Params for auction creation
        uint256 commitBlocks = block.number + 5;
        uint256 revealBlocks = block.number + 10;
        uint256 deposit = 1 ether;

        // Create auction
        address auctionAddr = manager.createAuction(beneficiary, address(token), commitBlocks, revealBlocks, deposit);

        // Check auction is not zero address
        assertTrue(auctionAddr != address(0), "Auction address should not be zero");

        // Check it is stored in manager
        address[] memory auctions = manager.getAllAuctions();
        assertEq(auctions.length, 1, "Should have 1 auction");
        assertEq(auctions[0], auctionAddr, "Stored auction should match created auction");
    }
}
