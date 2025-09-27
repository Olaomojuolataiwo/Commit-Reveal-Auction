// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;


import "forge-std/Script.sol";
import "forge-std/console.sol";
import "../src/MockERC20.sol";
import "../src/AuctionManager.sol";
import "../src/SealedBidAuction.sol";

contract ImpersonationOnchain2 is Script {
    function run() external {
        // ----------------------
        // Load env
        // ----------------------
       
        string memory rpc = vm.envString("RPC_URL_SEPOLIA"); // optional for logging
        uint256 deployerPk = vm.envUint("DEPLOYER_PK");
        uint256 alicePk = vm.envUint("ALICE_PK");
        uint256 attackerPk = vm.envUint("ATTACKER_PK");

        address mockTokenAddr = vm.envOr("MOCK_TOKEN_ADDR", address(0));
        address auctionAddr = vm.envOr("AUCTION_ADDR", address(0));
        address managerAddr = vm.envOr("MANAGER_ADDR", address(0));

	// Auction instance
	SealedBidAuction auction = SealedBidAuction(payable(auctionAddr));

	// Token instance
	MockERC20 token = MockERC20(mockTokenAddr);

	// Auction windows
	uint256 commitEndBlock = auction.commitEndBlock();
	uint256 revealEndBlock = auction.revealEndBlock();

	// Bids & nonces
	uint256 aliceBid = 100 ether;  // same as Stage 1
	bytes32 aliceNonce = keccak256(abi.encodePacked("alice-secret-onchain"));



        // Stage 2: reveal attempt (attacker tries to reveal alice's preimage), honest reveal, finalize

            // Sanity: ensure we're in reveal phase
            if (!(block.number > commitEndBlock && block.number <= revealEndBlock)) {
                require(block.number > commitEndBlock, "Reveal phase not started");
		console.log("ERROR: Not in reveal phase yet. block.number ");
                console.logUint(block.number);
            }

            address aliceAddr = vm.addr(alicePk);
            address attackerAddr = vm.addr(attackerPk);

            // Attacker tries to reveal using Alice's preimage (should fail)
            bytes memory payload = abi.encodeWithSignature("reveal(uint256,bytes32)", aliceBid, aliceNonce);
            vm.startBroadcast(attackerPk);
            (bool ok, bytes memory ret) = address(auction).call(payload);
            vm.stopBroadcast();

            console.log("Attacker attempted reveal with Alice's preimage. success:", ok);
            if (!ok) {
                // log revert reason if any
                if (ret.length > 0) {
                    // slice off selector for Error(string)
                    // decode if possible
                    // Error(string) => abi encoded as: 4-byte selector + abi.encode(string)
		string memory reason = decodeRevertMessage(ret);
                    console.log("Attacker reveal reverted reason:", reason);
                }
            } else {
                console.log("WARNING: Attacker reveal unexpectedly succeeded!");
            }

            

            // Honest reveal by Alice
            vm.startBroadcast(alicePk);
            auction.reveal(aliceBid, aliceNonce);
            vm.stopBroadcast();
            console.log("Alice successfully revealed.");

            // Wait until reveal end has passed in real chain; script cannot wait; check and require
            if (block.number <= revealEndBlock) {

                console.log("Note: reveal window still open (block.number <= revealEnd). To finalize, run the script again (STEP=2) after revealEndBlock.");
                // We stop here to avoid premature finalize. But allow the script to continue if revealEndBlock already passed.
                return;
            }

            // Finalize (anyone can call) — we'll use deployer key to call finalize
            vm.startBroadcast(deployerPk);
            auction.finalize();
            vm.stopBroadcast();
            console.log("Finalize called.");

            // Inspect balances
            console.log("Beneficiary token balance:", token.balanceOf(auction.beneficiary()));
            console.log("Alice token balance:", token.balanceOf(aliceAddr));
            console.log("Attacker token balance:", token.balanceOf(attackerAddr));
            return;
        }


    

    // ---------------------
    // Helpers
    // ---------------------
    function parseUint(string memory s) internal pure returns (uint256 res) {
        bytes memory b = bytes(s);
        for (uint i = 0; i < b.length; i++) {
            uint8 c = uint8(b[i]);
            if (c >= 48 && c <= 57) {
                res = res * 10 + (c - 48);
            }
        }
    }

    // Return address(0) if empty string
    function parseAddr(string memory s) internal pure returns (address) {
        bytes memory b = bytes(s);
        if (b.length == 0) return address(0);
        // caller will provide hex like 0x...
        // Very small parser: assume proper 0x-prefixed and 40 hex chars
        uint160 acc = 0;
        for (uint i = 2; i < 42; i++) {
            uint8 c = uint8(b[i]);
            uint160 v = 0;
            if (c >= 48 && c <= 57) v = uint160(c - 48);
            else if (c >= 97 && c <= 102) v = uint160(10 + c - 97);
            else if (c >= 65 && c <= 70) v = uint160(10 + c - 65);
            acc = acc * 16 + v;
        }
        return address(acc);
    }

/// @notice Decode revert ABI payload (Error(string)) into a string
function decodeRevertMessage(bytes memory data) public pure returns (string memory) {
    // Standard Error(string) selector = 0x08c379a0
    if (data.length < 4) return "no data";

    bytes4 selector;
    assembly {
        selector := mload(add(data, 32))
    }

    // If not the Error(string) selector, return a fallback message
    if (selector != 0x08c379a0) {
        return "non-standard revert or no string reason";
    }

    // Skip 4-byte selector and decode the remaining ABI-encoded string
    // data layout: 4 selector | abi.encode(string) ...
    // So we need to slice-off the first 4 bytes and decode the rest.
    // Create a new bytes array that contains data[4:]
    uint256 len = data.length - 4;
    bytes memory sliced = new bytes(len);
    for (uint256 i = 0; i < len; i++) {
        sliced[i] = data[i + 4];
    }

    // Now decode (sliced is standard abi-encoded string)
	return abi.decode(sliced, (string));
	}
}
