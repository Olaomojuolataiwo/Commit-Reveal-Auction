// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/MockERC20.sol";

contract DeployMockToken is Script {
    function run() external {
        // Load private key from .env
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerPrivateKey);

        // Adjust initial supply as needed (e.g. 1,000,000 tokens with 18 decimals)
        MockERC20 token = new MockERC20("Test Token", "TTK", 1_000_000 ether);

        console.log("MockERC20 deployed at:", address(token));

        vm.stopBroadcast();
    }
}
