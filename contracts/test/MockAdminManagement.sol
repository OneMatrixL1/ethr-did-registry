// SPDX-License-Identifier: MIT

pragma solidity ^0.8.28;

import {IAdminManagement} from "../EthereumDIDRegistry.sol";

/**
 * @title MockAdminManagement
 * @dev Simple mock contract for testing admin functionality
 */
contract MockAdminManagement is IAdminManagement {
    
    error NotOwner();
    error ZeroAddress();
    
    mapping(address => bool) private _admins;
    address public owner;
    
    event AdminStatusChanged(address indexed user, bool isAdmin);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    
    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }
    
    constructor() {
        owner = msg.sender;
        _admins[msg.sender] = true;
        emit AdminStatusChanged(msg.sender, true);
    }
    
    function isAdmin(address user) external view override returns (bool) {
        return _admins[user];
    }
    
    function setAdmin(address user, bool status) external onlyOwner {
        _admins[user] = status;
        emit AdminStatusChanged(user, status);
    }
    
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        address oldOwner = owner;
        owner = newOwner;
        _admins[newOwner] = true;
        emit OwnershipTransferred(oldOwner, newOwner);
        emit AdminStatusChanged(newOwner, true);
    }
}