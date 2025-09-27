// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/console2.sol";
import "forge-std/Script.sol";
import "../src/MockERC20.sol";
import "../src/SealedBidAuction.sol";

	/// Foundry script used as small single-purpose entry functions for shell orchestration.
	
	contract ScenarioActions is Script {
        function _makeCommitment(uint256 amount, address bidder, bytes32 nonce) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(amount, bidder, nonce));
        }

          // -------------------------
         // deploy: deploy token (if missing) and auction
        // -------------------------
        function deploy() external {
        uint256 deployerPk = vm.envUint("DEPLOYER_PK");
        address tokenAddr = address(0);

        if (bytes(vm.envString("MOCK_TOKEN_ADDR")).length != 0) {
            tokenAddr = vm.envAddress("MOCK_TOKEN_ADDR");
            console.log("Using provided MOCK_TOKEN_ADDR", tokenAddr);
        }

        vm.startBroadcast(deployerPk);

        if (tokenAddr == address(0)) {
            MockERC20 token = new MockERC20("TestToken", "TT", 1_000_000 ether);
            tokenAddr = address(token);
            console.log("Deployed MockERC20", tokenAddr);
        }

        uint256 commitBlocks = 5;
        uint256 revealBlocks = 5;
        if (bytes(vm.envString("COMMIT_BLOCKS")).length != 0) commitBlocks = vm.envUint("COMMIT_BLOCKS");
        if (bytes(vm.envString("REVEAL_BLOCKS")).length != 0) revealBlocks = vm.envUint("REVEAL_BLOCKS");

        uint256 currentBlock = block.number;
        uint256 commitEndBlock = currentBlock + commitBlocks;
        uint256 revealEndBlock = commitEndBlock + revealBlocks;

        uint256 deposit = 0;
        if (bytes(vm.envString("DEPOSIT_AMOUNT")).length != 0) deposit = vm.envUint("DEPOSIT_AMOUNT");

        address beneficiary = vm.addr(vm.envUint("DEPLOYER_PK"));
        if (bytes(vm.envString("BENEFICIARY")).length != 0) beneficiary = vm.envAddress("BENEFICIARY");

        SealedBidAuction auction = new SealedBidAuction(
            msg.sender,
            beneficiary,
            tokenAddr,
            commitEndBlock,
            revealEndBlock,
            deposit
        );

        console.log("Deployed Auction", address(auction));
        console.log("Payment token", tokenAddr);
        console.log("commitEndBlock", commitEndBlock);
        console.log("revealEndBlock", revealEndBlock);

        vm.stopBroadcast();
        }

         // -------------------------
        // commitBoth: bidders approve and commit commitments (one action)
       // -------------------------
        function commitBoth() external {
        require(bytes(vm.envString("AUCTION_ADDR")).length != 0, "AUCTION_ADDR missing");
        address payable auctionAddr = payable (vm.envAddress("AUCTION_ADDR"));
        address tokenAddr = address(0);
        if (bytes(vm.envString("MOCK_TOKEN_ADDR")).length != 0) tokenAddr = vm.envAddress("MOCK_TOKEN_ADDR");

        uint256 alicePk = vm.envUint("ALICE_PK");
        uint256 attackerPk = vm.envUint("ATTACKER_PK");
        uint256 aliceBid = vm.envUint("ALICE_BID");
        uint256 attackerBid = vm.envUint("ATTACKER_BID");
        bytes32 aliceNonce = bytes32(vm.envUint("ALICE_NONCE"));
        bytes32 attackerNonce = bytes32(vm.envUint("ATTACKER_NONCE"));

        // ALICE: approve + commit
        vm.startBroadcast(alicePk);
        if (tokenAddr != address(0)) {
            MockERC20(tokenAddr).approve(auctionAddr, type(uint256).max);
        }
        bytes32 aC = _makeCommitment(aliceBid, vm.addr(alicePk), aliceNonce);
        SealedBidAuction(auctionAddr).commit(aC);
        console.logBytes32(aC);
        vm.stopBroadcast();

        // ATTACKER: approve + commit (skip if ATTACKER_BID == 0)
        if (attackerBid > 0) {
            vm.startBroadcast(attackerPk);
            if (tokenAddr != address(0)) {
                MockERC20(tokenAddr).approve(auctionAddr, type(uint256).max);
            }
            bytes32 atC = _makeCommitment(attackerBid, vm.addr(attackerPk), attackerNonce);
            SealedBidAuction(auctionAddr).commit(atC);
            console.logBytes32(atC);
            vm.stopBroadcast();
        } else {
            console.log("Skipping attacker commit (attackerBid == 0)");
        }
        }

        // -------------------------
        // cheatReveal: attacker attempts inflated reveal with low-level call
        // -------------------------
        function cheatReveal() external {
        require(bytes(vm.envString("AUCTION_ADDR")).length != 0, "AUCTION_ADDR missing");
        address payable auctionAddr = payable (vm.envAddress("AUCTION_ADDR"));
        uint256 attackerPk = vm.envUint("ATTACKER_PK");
        uint256 attackerBid = vm.envUint("ATTACKER_BID");
        uint256 inflate = 0;
        if (bytes(vm.envString("CHEAT_INFLATE")).length != 0) inflate = vm.envUint("CHEAT_INFLATE");
        else inflate = 1; // minimal inflation

        bytes32 attackerNonce = bytes32(vm.envUint("ATTACKER_NONCE"));
        uint256 inflated = attackerBid + inflate;

        vm.startBroadcast(attackerPk);
        (bool ok, bytes memory ret) = address(auctionAddr).call(
            abi.encodeWithSelector(SealedBidAuction.reveal.selector, inflated, attackerNonce)
        );
        if (ok) {
            console.log("CHEAT_REVEAL_SUCCEEDED (unexpected)");
        } else {
            string memory reason = _decodeRevert(ret);
            console.log("CHEAT_REVEAL_REVERT", reason);
        }
        vm.stopBroadcast();
        }

        // -------------------------
        // revealBoth: honest + attacker reveal correctly
        // -------------------------
        function revealBoth() external {
        require(bytes(vm.envString("AUCTION_ADDR")).length != 0, "AUCTION_ADDR missing");
        address payable auctionAddr = payable (vm.envAddress("AUCTION_ADDR"));
        uint256 alicePk = vm.envUint("ALICE_PK");
        uint256 attackerPk = vm.envUint("ATTACKER_PK");
        uint256 aliceBid = vm.envUint("ALICE_BID");
        uint256 attackerBid = vm.envUint("ATTACKER_BID");
        bytes32 aliceNonce = bytes32(vm.envUint("ALICE_NONCE"));
        bytes32 attackerNonce = bytes32(vm.envUint("ATTACKER_NONCE"));

        vm.startBroadcast(alicePk);
        SealedBidAuction(auctionAddr).reveal(aliceBid, aliceNonce);
        console.log("Alice revealed");
        vm.stopBroadcast();

        if (attackerBid > 0) {
            vm.startBroadcast(attackerPk);
            SealedBidAuction(auctionAddr).reveal(attackerBid, attackerNonce);
            console.log("Attacker revealed");
            vm.stopBroadcast();
        } else {
            console.log("Skipping attacker reveal (attackerBid == 0)");
        }
        }

        // attacker-only reveal
        
	function revealAttackerOnly() external {
        require(bytes(vm.envString("AUCTION_ADDR")).length != 0, "AUCTION_ADDR missing");
        address payable auctionAddr = payable (vm.envAddress("AUCTION_ADDR"));
        uint256 attackerPk = vm.envUint("ATTACKER_PK");
        uint256 attackerBid = vm.envUint("ATTACKER_BID");
        bytes32 attackerNonce = bytes32(vm.envUint("ATTACKER_NONCE"));
        vm.startBroadcast(attackerPk);
        SealedBidAuction(auctionAddr).reveal(attackerBid, attackerNonce);
        console.log("Attacker revealed (only)");
        vm.stopBroadcast();
        }

        // alice-only reveal
        function revealAliceOnly() external {
        require(bytes(vm.envString("AUCTION_ADDR")).length != 0, "AUCTION_ADDR missing");
        address payable auctionAddr = payable (vm.envAddress("AUCTION_ADDR"));
        uint256 alicePk = vm.envUint("ALICE_PK");
        uint256 aliceBid = vm.envUint("ALICE_BID");
        bytes32 aliceNonce = bytes32(vm.envUint("ALICE_NONCE"));
        vm.startBroadcast(alicePk);
        SealedBidAuction(auctionAddr).reveal(aliceBid, aliceNonce);
        console.log("Alice revealed (only)");
        vm.stopBroadcast();
        }

        // attacker does not reveal (no-op) - helper for clarity
        function attackerDontReveal() external view {
        console.log("attacker will not reveal (no-op)");
        }

        // attacker does a double reveal: first valid, then attempt second (should revert)
        function attackerDoubleReveal() external {
        require(bytes(vm.envString("AUCTION_ADDR")).length != 0, "AUCTION_ADDR missing");
        address payable auctionAddr = payable (vm.envAddress("AUCTION_ADDR"));
        uint256 attackerPk = vm.envUint("ATTACKER_PK");
        uint256 attackerBid = vm.envUint("ATTACKER_BID");
        bytes32 attackerNonce = bytes32(vm.envUint("ATTACKER_NONCE"));

        vm.startBroadcast(attackerPk);
        SealedBidAuction(auctionAddr).reveal(attackerBid, attackerNonce);
        console.log("Attacker first reveal done");

        // second (invalid) reveal attempt - different amount
        uint256 cheated = attackerBid + 1;
        (bool ok, bytes memory ret) = address(auctionAddr).call(
            abi.encodeWithSelector(SealedBidAuction.reveal.selector, cheated, attackerNonce)
        );
        if (ok) {
            console.log("Attacker double-reveal unexpectedly SUCCEEDED");
        } else {
            console.log("double_reveal_revert", _decodeRevert(ret));
        }
        vm.stopBroadcast();
        }

        // replayer: low-level caller tries to replay honest preimage
        function cheatReplayCall() external {
        require(bytes(vm.envString("AUCTION_ADDR")).length != 0, "AUCTION_ADDR missing");
        address payable auctionAddr = payable (vm.envAddress("AUCTION_ADDR"));
        uint256 replayerPk = vm.envUint("REPLAYER_PK");
        uint256 aliceBid = vm.envUint("ALICE_BID");
        bytes32 aliceNonce = bytes32(vm.envUint("ALICE_NONCE"));

        vm.startBroadcast(replayerPk);
        (bool ok, bytes memory ret) = address(auctionAddr).call(
            abi.encodeWithSelector(SealedBidAuction.reveal.selector, aliceBid, aliceNonce)
        );
        if (ok) {
            console.log("REPLAYER reveal unexpectedly SUCCEEDED (unexpected)");
        } else {
            console.log("REPLAYER_reveal_revert", _decodeRevert(ret));
        }
        vm.stopBroadcast();
    }

    // -------------------------
    // finalize: call finalize (by deployer)
    // -------------------------
    function finalize() external {
        require(bytes(vm.envString("AUCTION_ADDR")).length != 0, "AUCTION_ADDR missing");
        address payable auctionAddr = payable (vm.envAddress("AUCTION_ADDR"));
        uint256 deployerPk = vm.envUint("DEPLOYER_PK");

        vm.startBroadcast(deployerPk);
        SealedBidAuction(auctionAddr).finalize();
        console.log("finalize called");
        vm.stopBroadcast();
    }

    // -------------------------
    // status: print helpful state
    // -------------------------
    function status() external view {
        require(bytes(vm.envString("AUCTION_ADDR")).length != 0, "AUCTION_ADDR missing");
        address payable auctionAddr = payable (vm.envAddress("AUCTION_ADDR"));
        SealedBidAuction auction = SealedBidAuction(auctionAddr);

        console.log("block.number", block.number);
        console.log("auction", auctionAddr);
        console.log("commitEndBlock", auction.commitEndBlock());
        console.log("revealEndBlock", auction.revealEndBlock());
        console.log("winner", auction.winner());
        console.log("winningBid", auction.winningBid());

        address[] memory bidders = auction.getBidders();
        console.log("bidders_count", bidders.length);
        for (uint256 i = 0; i < bidders.length; i++) {
            address b = bidders[i];
            console.log("bidder", b);
            console.logBytes32(auction.commitments(b));
            console.log("revealedBid", auction.revealedBid(b));
            console.log("deposit", auction.deposits(b));
            console.log("revealed", auction.revealed(b));
        }
    }

    /// decode revert message
    function _decodeRevert(bytes memory data) internal pure returns (string memory) {
        if (data.length < 68) return "no revert message";
        assembly { data := add(data, 0x04) }
        return abi.decode(data, (string));
    }
}
