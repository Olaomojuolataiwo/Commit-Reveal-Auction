// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/MockERC20.sol";
import "../src/AuctionManager.sol";
import "../src/SealedBidAuction.sol";

contract RevealFinalize is Script {
    SealedBidAuction auction;
    MockERC20 token;

    address deployer;
    address alice;
    address attacker;
    address beneficiary;

    uint256 aliceBid = 100 ether;
    bytes32 aliceNonce = keccak256(abi.encodePacked("alice-secret-grief"));

    function run() external {
        deployer = vm.envAddress("DEPLOYER");
        alice = vm.envAddress("ALICE");
        attacker = vm.envAddress("ATTACKER");
        beneficiary = vm.envAddress("BENEFICIARY");

	
	uint256 alicePk = vm.envUint("ALICE_PK");
        uint256 finalizerPk = vm.envUint("DEPLOYER_PK");
	require(alicePk != 0 && finalizerPk != 0, "set ALICE_PK and DEPLOYER_PK");
	
	address managerAddr = vm.envOr("MANAGER_ADDR", address(0));
	address auctionAddr = vm.envOr("AUCTION_ADDR", address(0));
        address tokenAddr = vm.envOr("MOCK_TOKEN_ADDR", address(0));

	// Validate addresses are set
	require(auctionAddr != address(0), "AUCTION_ADDR not set");
	require(tokenAddr != address(0), "MOCK_TOKEN_ADDR not set");
	
	auction = SealedBidAuction(payable(auctionAddr));
	MockERC20 token = MockERC20(tokenAddr);
	
	console.log("Auction and token instances initialized:");
	console.log("Auction:", auctionAddr);
	console.log("Token:", tokenAddr);

        uint256 commitEnd = auction.commitEndBlock();
        uint256 revealEnd = auction.revealEndBlock();

        console.log("Reveal phase window:", commitEnd, "to", revealEnd);
        console.log("Current block:", block.number);

        // Alice reveals, attacker intentionally does NOT
        address aliceAddr = vm.addr(alicePk);
	vm.startBroadcast(alicePk);
        // Ensure approval exists (attempt approve; will succeed only if alice holds tokens)
        try token.approve(address(auction), aliceBid) {
        } catch {}
        
	auction.reveal(aliceBid, aliceNonce);
        vm.stopBroadcast();

        require(
            auction.revealedBid(alice) == aliceBid,
            "Alice reveal mismatch"
        );

        
	// Beneficiary balance before finalize
        uint256 benBefore = token.balanceOf(beneficiary);

        // Finalize (anyone can call)
	// vm.startBroadcast(finalizerPk);
        // auction.finalize();
        // vm.stopBroadcast();

        // uint256 benAfter = token.balanceOf(beneficiary);

        // console.log("Beneficiary received:", benAfter - benBefore);

        // Assertions
	//        require(
        //    benAfter - benBefore == auction.depositAmount() + aliceBid,
        //    "Beneficiary did not receive correct funds"
        // );
        // require(
        //   auction.deposits(attacker) == 0,
        //    "Attacker deposit not slashed"
	//        );
    }
}
