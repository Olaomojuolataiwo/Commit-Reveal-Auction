// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Script.sol";
import "../src/SealedBidAuction.sol";

contract DeploySealedBidAuction is Script {
    function run() external {
        // Load deployer key from environment variable
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

	// Log deployer info for clarity
        address deployer = vm.addr(deployerPrivateKey);
        console.log("Deploying from:", deployer);

        
	// Start broadcast with explicit RPC
	vm.startBroadcast(deployerPrivateKey);        

        // Set constructor parameters
        address creator = msg.sender;
        address beneficiary = msg.sender;        // replace with your desired beneficiary
        address paymentToken = address(0);       // native ETH
        uint256 commitEndBlock = block.number + 10;   // example: 10 blocks from now
        uint256 revealEndBlock = block.number + 20;   // example: 20 blocks from now
        uint256 depositAmount = 0.1 ether;            // example deposit

        // Deploy SealedBidAuction
        SealedBidAuction auction = new SealedBidAuction(
            creator,
            beneficiary,
            paymentToken,
            commitEndBlock,
            revealEndBlock,
            depositAmount
        );

        console.log("SealedBidAuction deployed at:", address(auction));

        // Stop broadcasting
        vm.stopBroadcast();
    }
}
