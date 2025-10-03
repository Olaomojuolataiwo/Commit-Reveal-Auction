// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/MockERC20.sol";
import "../src/AuctionManager.sol";
import "../src/SealedBidAuction.sol";

contract CommitPhase is Script {
    MockERC20 token;
    AuctionManager manager;
    SealedBidAuction auction;

    address deployer;
    address alice;
    address attacker;
    address beneficiary;

    uint256 deposit = 10 ether;
    uint256 aliceBid = 100 ether;
    uint256 attackerBid = 90 ether;

    bytes32 aliceNonce;
    bytes32 attackerNonce;

    function run() external {
        deployer = vm.envAddress("DEPLOYER");
        alice = vm.envAddress("ALICE");
        attacker = vm.envAddress("ATTACKER");
        beneficiary = vm.envAddress("BENEFICIARY");
        uint256 deployerPk = vm.envUint("DEPLOYER_PK");
        uint256 alicePk = vm.envUint("ALICE_PK");
        uint256 attackerPk = vm.envUint("ATTACKER_PK");
        require(deployerPk != 0 && alicePk != 0 && attackerPk != 0, "set DEPLOYER_PK, ALICE_PK, ATTACKER_PK");
        address managerAddr = vm.envOr("MANAGER_ADDR", address(0));
        address tokenAddr = vm.envOr("MOCK_TOKEN_ADDR", address(0));
        MockERC20 token = MockERC20(tokenAddr);

        // Deploy fresh manager
        vm.startBroadcast(deployerPk);
        manager = new AuctionManager();

        uint256 commitBlocks = 10;
        uint256 revealBlocks = 20;
        uint256 commitEnd = block.number + commitBlocks;
        uint256 revealEnd = commitEnd + revealBlocks;

        address auctionAddr = manager.createAuction(payable(beneficiary), address(token), commitEnd, revealEnd, deposit);
        auction = SealedBidAuction(payable(auctionAddr));
        console.log("Created auction at:", auctionAddr);
        console.log("commitEndBlock:", commitEnd, "revealEndBlock:", revealEnd);

        // Fund Alice & attacker
        address aliceAddr = vm.addr(alicePk);
        address attackerAddr = vm.addr(attackerPk);

        token.transfer(aliceAddr, aliceBid + deposit + 1 ether);
        token.transfer(attackerAddr, attackerBid + deposit + 1 ether);
        console.log("Funded alice:", aliceAddr, "and attacker:", attackerAddr);

        vm.stopBroadcast();

        // Approvals
        vm.startBroadcast(alicePk);
        token.approve(address(auction), deposit + aliceBid);
        vm.stopBroadcast();

        vm.startBroadcast(attackerPk);
        token.approve(address(auction), deposit + attackerBid);
        vm.stopBroadcast();

        // Commit phase
        aliceNonce = keccak256(abi.encodePacked("alice-secret-grief"));
        attackerNonce = keccak256(abi.encodePacked("attacker-secret-grief"));

        bytes32 commitAlice = keccak256(abi.encodePacked(aliceBid, alice, aliceNonce));
        bytes32 commitAttacker = keccak256(abi.encodePacked(attackerBid, attacker, attackerNonce));

        vm.startBroadcast(alicePk);
        auction.commit(commitAlice);
        vm.stopBroadcast();

        vm.startBroadcast(attackerPk);
        auction.commit(commitAttacker);
        vm.stopBroadcast();

        // Assertions (sanity checks)
        bytes32 storedAlice = auction.commitments(aliceAddr);
        bytes32 storedAttacker = auction.commitments(attackerAddr);

        require(auction.commitments(alice) == commitAlice, "Alice commitment mismatch");
        require(auction.commitments(attacker) == commitAttacker, "Attacker commitment mismatch");

        console.log("Auction deployed at:", address(auction));
        console.log("Commit phase complete. CommitEnd:", auction.commitEndBlock());
        console.log("RevealEnd:", auction.revealEndBlock());
    }
}
