// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;


import "forge-std/console.sol";
import "forge-std/Script.sol";
import "forge-std/console.sol";
import "../src/MockERC20.sol";
import "../src/AuctionManager.sol";
import "../src/SealedBidAuction.sol";

contract ImpersonationOnchain is Script {
    function run() external {
        // ----------------------
        // Load env
        // ----------------------

        string memory rpc = vm.envString("RPC_URL_SEPOLIA"); // optional for logging
        uint256 deployerPk = vm.envUint("DEPLOYER_PK");
        uint256 alicePk = vm.envUint("ALICE_PK");
        uint256 attackerPk = vm.envUint("ATTACKER_PK");

        address mockTokenAddr = vm.envOr("MOCK_TOKEN_ADDR", address (0));
        address auctionAddr = vm.envOr("AUCTION_ADDR", address(0));
        address managerAddr = vm.envOr("MANAGER_ADDR", address(0));

        // amounts (adjust if you like)
        uint256 fundAmount = 1_000 ether;       // token units to send to bidders
        uint256 deposit = 10 ether;             // deposit required by auction
        uint256 aliceBid = 100 ether;           // alice planned bid
        uint256 attackerBid = 90 ether;         // attacker planned bid (not used to win)

        // nonces (pre-agreed for the reveal)
        bytes32 aliceNonce = keccak256(abi.encodePacked("alice-secret-onchain"));
        bytes32 attackerNonce = keccak256(abi.encodePacked("attacker-secret-onchain"));


        // If token not provided, deploy one using deployer key
        if (mockTokenAddr == address(0)) {
            vm.startBroadcast(deployerPk);
            MockERC20 t = new MockERC20("Test Token", "TTK", 1_000_000 ether);
            mockTokenAddr = address(t);
            vm.stopBroadcast();
            console.log("Deployed MockERC20 at:", mockTokenAddr);
        } else {
            console.log("Using existing MockERC20 at:", mockTokenAddr);
        }
        MockERC20 token = MockERC20(mockTokenAddr);

        // If auction address not provided, create via manager (use deployer key)
        if (auctionAddr == address(0)) {
            // deploy manager if not set
            if (managerAddr == address(0)) {
                vm.startBroadcast(deployerPk);
                AuctionManager m = new AuctionManager();
                managerAddr = address(m);
                vm.stopBroadcast();
                console.log("Deployed AuctionManager at:", managerAddr);
            } else {
                console.log("Using existing AuctionManager at:", managerAddr);
            }

            AuctionManager manager = AuctionManager(managerAddr);

            // choose short windows to make testing practical
            uint256 commitBlocks = 8;
            uint256 revealBlocks = 200;
            uint256 commitEnd = block.number + commitBlocks;
            uint256 revealEnd = commitEnd + revealBlocks;

            vm.startBroadcast(deployerPk);
            auctionAddr = manager.createAuction(
                payable(address(0xBEEF)), // beneficiary (you can change)
                mockTokenAddr,
                commitEnd,
                revealEnd,
                deposit
            );
            vm.stopBroadcast();

            console.log("Created auction at:", auctionAddr);
            console.log("commitEnd:", commitEnd, "revealEnd:", revealEnd);
        } else {
            console.log("Using existing Auction at:", auctionAddr);
        }

        SealedBidAuction auction = SealedBidAuction(payable(auctionAddr));

        // Read windows from the auction (sanity)
        uint256 commitEndBlock = auction.commitEndBlock();
        uint256 revealEndBlock = auction.revealEndBlock();
        console.log("Auction windows read from contract -> commitEnd:", commitEndBlock, "revealEnd:", revealEndBlock);

        // Stage 1: distribution, approvals, commits
        
            // 1) Deployer funds alice/attacker with tokens
            vm.startBroadcast(deployerPk);
            address deployerAddr = msg.sender;
            // If deployer already has token supply; transfer to alice and attacker
            // We will transfer fundAmount to both (2 transfers)
            // Use deterministic addresses derived from their private keys:
            address aliceAddr = vm.addr(alicePk);
            address attackerAddr = vm.addr(attackerPk);

            // Transfer tokens (from deployer)
            token.transfer(aliceAddr, fundAmount);
            token.transfer(attackerAddr, fundAmount);
            vm.stopBroadcast();

            console.log("Transferred", fundAmount, "TTK to alice:", aliceAddr);
            console.log("Transferred", fundAmount, "TTK to attacker:", attackerAddr);

            // 2) Each bidder approves the auction for deposit + bid
            // Alice approve
            vm.startBroadcast(alicePk);
            token.approve(auctionAddr, deposit + aliceBid);
            vm.stopBroadcast();
            console.log("Alice approved auction for", deposit + aliceBid);

            // Attacker approve
            vm.startBroadcast(attackerPk);
            token.approve(auctionAddr, deposit + attackerBid);
            vm.stopBroadcast();
            console.log("Attacker approved auction for", deposit + attackerBid);

            // 3) Compute commits and submit commits (from bidder accounts)
            bytes32 commitAlice = keccak256(abi.encodePacked(aliceBid, vm.addr(alicePk), aliceNonce));
            bytes32 commitAttacker = keccak256(abi.encodePacked(attackerBid, vm.addr(attackerPk), attackerNonce));

	    bool aliceCommitted = auction.commitments(vm.addr(alicePk)) != bytes32(0);
	    bool attackerCommitted = auction.commitments(vm.addr(attackerPk)) != bytes32(0);


	    uint256 currentBlock = block.number;
	    if (currentBlock > commitEndBlock) {
    	     console.log("ERROR: Commit phase ended. commitEndBlock:", commitEndBlock, "current block:", currentBlock);
    	     return; // exit script to prevent sending TX
	     } else {
    	     console.log("Within commit phase. Current block:", currentBlock, "Commit window ends at:", commitEndBlock);
	     }
	     
	     // Only commit if not already committed
	       if (!aliceCommitted) {
    	       vm.startBroadcast(alicePk);
    	       auction.commit(commitAlice);
    	       vm.stopBroadcast();
    	       console.log("Alice committed (hash):");
	       console.logBytes32(commitAlice);
	       } 
	      else {
    	      console.log("Alice already committed. Skipping commit.");
		}

		if (!attackerCommitted) {
    	        vm.startBroadcast(attackerPk);
    		auction.commit(commitAttacker);
    		vm.stopBroadcast();
    		console.log("Attacker committed (hash):");
		console.logBytes32(commitAttacker);
		} else {
    		console.log("Attacker already committed. Skipping commit.");
		}


	     // Check if Alice already committed
	     if (auction.commitments(vm.addr(alicePk)) == bytes32(0)) {
    	     vm.startBroadcast(alicePk);
    	     auction.commit(commitAlice);
    	     vm.stopBroadcast();
    	     console.log("Alice committed (hash):");
    	     console.logBytes32(commitAlice);
	     } else {
    	     console.log("Alice already committed, skipping.");
	     }

	     // Check if Attacker already committed
	     if (auction.commitments(vm.addr(attackerPk)) == bytes32(0)) {
    	     vm.startBroadcast(attackerPk);
    	     auction.commit(commitAttacker);
    	     vm.stopBroadcast();
    	     console.log("Attacker committed (hash):");
    	     console.logBytes32(commitAttacker);
	     } else {
    	          console.log("Attacker already committed, skipping.");
	          }

	

            console.log("\nStage 1 complete.");
            console.log("Now wait until block >", commitEndBlock, "run script 2 to perform reveal attempts and finalize.");
	    return;
        }

}
