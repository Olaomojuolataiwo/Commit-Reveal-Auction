// test/MockERC20.t.sol
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/MockERC20.sol";

contract MockERC20Test is Test {
    MockERC20 token;
    address alice = address(0xcc7a3706Df7FCcFbF99f577382BC62C0e565FcF0);
    address bob   = address(0x513B1d92C2CA2d364B9d99ABabA485D298bdCbea);

    function setUp() public {
        token = new MockERC20("Test Token", "TTK", 1_000_000 ether);

        // distribute some tokens to Alice
        token.transfer(alice, 100 ether);
    }

    // Baseline test: check balances
    function testInitialDistribution() public view {
        assertEq(token.balanceOf(address(this)), 1_000_000 ether - 100 ether);
        assertEq(token.balanceOf(alice), 100 ether);
    }

    // Allowance + transferFrom test
    function testAllowanceAndTransferFrom() public {
        vm.startPrank(alice);

        // Alice approves Bob to spend 50 tokens
        token.approve(bob, 50 ether);
        assertEq(token.allowance(alice, bob), 50 ether);

        vm.stopPrank();

        // Now Bob spends Alice's tokens using transferFrom
        vm.startPrank(bob);
        token.transferFrom(alice, bob, 20 ether);
        vm.stopPrank();

        // Check balances updated
        assertEq(token.balanceOf(alice), 80 ether); // 100 - 20
        assertEq(token.balanceOf(bob), 20 ether);

        // Allowance reduced
        assertEq(token.allowance(alice, bob), 30 ether); // 50 - 20
    }
}
