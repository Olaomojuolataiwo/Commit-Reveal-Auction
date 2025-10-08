// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Minimal {
    function approve(address spender, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IVulnerableAuction {
    function commit(uint256 auctionId, bytes32 commitHash, uint256 depositAmount) external;
    function reveal(uint256 auctionId, uint256 bidAmount, bytes32 salt) external;
    function withdraw(uint256 auctionId) external;
}

interface IHardenedAuction {
    function commit(uint256 auctionId, bytes32 commitHash) external;
    function reveal(uint256 auctionId, uint256 bidAmount, bytes32 salt) external;
    function withdraw(uint256 auctionId) external;
}

interface IERC20Approve {
    function approve(address spender, uint256 amount) external returns (bool);
}
