// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./SealedBidAuction.sol";

contract AuctionManager {
    address[] public auctions;

    event AuctionCreated(address indexed auction, address indexed creator);

    function createAuction(
        address beneficiary,
        address bidToken,
        uint256 commitBlocks,
        uint256 revealBlocks,
        uint256 deposit
    ) external returns (address) {
        // msg.sender becomes the owner
        SealedBidAuction auction = new SealedBidAuction(
            msg.sender,      // 👈 owner
            beneficiary,
            bidToken,
            commitBlocks,
            revealBlocks,
            deposit
        );

        auctions.push(address(auction));
        emit AuctionCreated(address(auction), msg.sender);
        return address(auction);
    }

    function getAllAuctions() external view returns (address[] memory) {
        return auctions;
    }
}
