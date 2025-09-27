// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/MockERC20.sol";
import "../src/AuctionManager.sol";
import "../src/SealedBidAuction.sol";

contract SealedBidAuctionERC20Test is Test {
    MockERC20 token;
    AuctionManager manager;

    address alice = address(uint160(uint256(keccak256("alice"))));
    address bob   = address(uint160(uint256(keccak256("bob"))));
    address beneficiary = address(0xBEEF);

    function setUp() public {
        // deploy token & manager
        token = new MockERC20("Test Token", "TTK", 1_000_000 ether);
        manager = new AuctionManager();

        // distribute tokens to bidders
        token.transfer(alice, 1_000 ether);
        token.transfer(bob, 1_000 ether);

        // quick sanity
        assertEq(token.balanceOf(alice), 1_000 ether);
        assertEq(token.balanceOf(bob), 1_000 ether);
    }

    function testERC20AuctionHappyPath() public {
        // auction params (absolute block numbers)
        uint256 commitEnd = block.number + 5;
        uint256 revealEnd = commitEnd + 5;
        uint256 deposit = 10 ether; // deposit in token units

        // create auction via manager (returns auction address)
        address auctionAddr = manager.createAuction(
            beneficiary,
            address(token),
            commitEnd,
            revealEnd,
            deposit
        );
        SealedBidAuction auction = SealedBidAuction(payable(auctionAddr));

        // bidders approve auction to spend deposit + max bid
        uint256 aliceBid = 100 ether;
        uint256 bobBid = 150 ether;
        uint256 approveAmountAlice = deposit + aliceBid;
        uint256 approveAmountBob = deposit + bobBid;

        vm.prank(alice);
        token.approve(auctionAddr, approveAmountAlice);

        vm.prank(bob);
        token.approve(auctionAddr, approveAmountBob);

        // compute commitments (client-side would keep nonces secret)
        bytes32 aliceNonce = keccak256(abi.encodePacked("alice-secret"));
        bytes32 bobNonce   = keccak256(abi.encodePacked("bob-secret"));

        bytes32 commitAlice = keccak256(abi.encodePacked(uint256(aliceBid), alice, aliceNonce));
        bytes32 commitBob   = keccak256(abi.encodePacked(uint256(bobBid), bob, bobNonce));

        // commit phase: both commit (this will call transferFrom to collect deposit)
        vm.prank(alice);
        auction.commit(commitAlice); // ERC20 branch collects depositAmount via transferFrom

        vm.prank(bob);
        auction.commit(commitBob);

        // fast-forward into reveal phase
        vm.roll(commitEnd + 1);

        // reveal: bidders transfer their bid amount via transferFrom inside reveal()
        vm.prank(alice);
        auction.reveal(aliceBid, aliceNonce);

        vm.prank(bob);
        auction.reveal(bobBid, bobNonce);

        // fast-forward past reveal window
        vm.roll(revealEnd + 1);

        // finalize auction (transfers winner bid to beneficiary)
        auction.finalize();

        // beneficiary should have received the winning bid (bobBid)
        assertEq(token.balanceOf(beneficiary), bobBid);

        // alice (loser) withdraws her bid + deposit => back to original alice balance
        uint256 aliceBefore = token.balanceOf(alice);
        vm.prank(alice);
        auction.withdraw();
        uint256 aliceAfter = token.balanceOf(alice);
        // aliceAfter should equal aliceBefore + aliceBid + deposit
        assertEq(aliceAfter, aliceBefore + aliceBid + deposit);

        // bob (winner) attempted withdraw should revert (winner funds already paid)
        vm.prank(bob);
        vm.expectRevert("winner cannot withdraw (funds already paid)");
        auction.withdraw();

        // final sanity: total supply unchanged
        assertEq(token.totalSupply(), 1_000_000 ether);
    }
}
