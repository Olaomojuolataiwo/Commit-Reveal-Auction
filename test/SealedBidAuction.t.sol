// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/SealedBidAuction.sol";

contract SealedBidAuctionTest is Test {
    SealedBidAuction auction;

    address alice = address(0xA11CE);
    address bob = address(0xB0B);
    address beneficiary = address(0xBEEF);

    // test params
    uint256 deposit = 0.01 ether;
    uint256 commitBlocks = 10;
    uint256 revealBlocks = 10;

    function setUp() public {
        // give Alice and Bob ETH
        vm.deal(alice, 1 ether);
        vm.deal(bob, 1 ether);
        vm.deal(beneficiary, 0 ether);

        auction = new SealedBidAuction(
            address(this),
            beneficiary,
            address(0), // use native ETH
            block.number + commitBlocks,
            block.number + commitBlocks + revealBlocks,
            deposit
        );
    }

    function testFullAuctionFlow() public {
        // Alice commits
        bytes32 nonceAlice = keccak256("alice-secret");
        bytes32 commitAlice = keccak256(abi.encodePacked(uint256(0.5 ether), alice, nonceAlice));
        vm.prank(alice);
        auction.commit{value: deposit}(commitAlice);

        // Bob commits
        bytes32 nonceBob = keccak256("bob-secret");
        bytes32 commitBob = keccak256(abi.encodePacked(uint256(0.8 ether), bob, nonceBob));
        vm.prank(bob);
        auction.commit{value: deposit}(commitBob);

        // move forward into reveal phase
        vm.roll(block.number + commitBlocks + 1);

        // Alice reveals
        vm.prank(alice);
        auction.reveal{value: 0.5 ether}(0.5 ether, nonceAlice);

        // Bob reveals
        vm.prank(bob);
        auction.reveal{value: 0.8 ether}(0.8 ether, nonceBob);

        // move forward past reveal
        vm.roll(block.number + revealBlocks + 1);

        // finalize
        auction.finalize();

        // Alice (loser) withdraws deposit
        uint256 balBefore = alice.balance;
        vm.prank(alice);
        auction.withdraw();
        assertGt(alice.balance, balBefore);

        // Bob (winner) withdraws deposit, then pays bid
        balBefore = bob.balance;
        vm.expectRevert("winner cannot withdraw (funds already paid)");
        vm.prank(bob);
        auction.withdraw();
        assertEq(bob.balance, balBefore);

        // Beneficiary should have Bob’s bid
        assertEq(beneficiary.balance, 0.8 ether);
    }
}
