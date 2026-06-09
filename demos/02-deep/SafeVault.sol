// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// A hardened version that should produce no high/medium findings: it follows
// checks-effects-interactions, guards every state-touching function with a
// reentrancy mutex, checks call return values, and uses msg.sender for auth.

contract SafeVault {
    address public owner;
    mapping(address => uint256) public balances;
    uint256 private _locked = 1;

    constructor() {
        owner = msg.sender;
    }

    modifier nonReentrant() {
        require(_locked == 1, "reentrant");
        _locked = 2;
        _;
        _locked = 1;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;          // effect before interaction
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
    }

    function balanceOf(address user) external view returns (uint256) {
        return balances[user];
    }
}
