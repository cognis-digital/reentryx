// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Vault - intentionally vulnerable demo for REENTRYX
contract Vault {
    mapping(address => uint256) public balances;
    uint256 public totalShares;
    bool private locked;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalShares += msg.value;
    }

    // VULNERABLE: external call before state update (RX001).
    // totalShares is also updated after the call, enabling read-only
    // reentrancy via getTotalShares() (RX002).
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] -= amount;
        totalShares -= amount;
    }

    // SAFE: effects happen before the interaction. Should NOT trigger RX001.
    function safeWithdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        totalShares -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    // Read-only getter that exposes the stale value during reentrancy.
    function getTotalShares() external view returns (uint256) {
        return totalShares;
    }
}
