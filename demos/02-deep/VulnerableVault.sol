// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Demo target for reentryx. Contains intentional, well-known vulnerability
// patterns so the analyzer's detectors have something real to flag.
//
//   * classic reentrancy (state write after external call)   -> REX-REEN
//   * cross-function reentrancy (shared balances mapping)      -> REX-XFRE
//   * read-only reentrancy (getter reads stale totalShares)    -> REX-RORE
//   * unchecked low-level call return value                    -> REX-UCALL
//   * tx.origin authentication (in a modifier)                 -> REX-TXORG
//   * delegatecall into caller-controlled target               -> REX-DELEG

interface IRewards {
    function notify(address user, uint256 amount) external;
}

contract VulnerableVault {
    address public owner;
    mapping(address => uint256) public balances;
    uint256 public totalShares;
    IRewards public rewards;

    constructor(address _rewards) {
        owner = msg.sender;
        rewards = IRewards(_rewards);
    }

    // tx.origin authentication is phishable -> REX-TXORG
    // Note: this lives in a MODIFIER, not a function -- reentryx models
    // modifier bodies as first-class units to catch exactly this.
    modifier onlyOwner() {
        require(tx.origin == owner, "not owner");
        _;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalShares += msg.value;
    }

    // Classic reentrancy: external call before state update -> REX-REEN
    // Also moves value with no nonReentrant guard -> REX-SEND-VALUE
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");

        // interaction BEFORE effect -- the bug
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");

        balances[msg.sender] -= amount;   // updated too late
        totalShares -= amount;
    }

    // Cross-function reentrancy: also mutates the shared balances mapping,
    // unguarded, so it can be re-entered during withdraw's callback -> REX-XFRE
    function transferShares(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        rewards.notify(to, amount);            // external call first
        balances[msg.sender] -= amount;        // shared state settled after
        balances[to] += amount;
    }

    // Read-only reentrancy: integrators reading this mid-callback see a stale
    // totalShares / balances -> REX-RORE
    function shareValue(address user) external view returns (uint256) {
        if (totalShares == 0) return 0;
        return (balances[user] * address(this).balance) / totalShares;
    }

    // Unchecked low-level call -> REX-UCALL
    function payout(address payable to, uint256 amount) external {
        to.call{value: amount}("");
    }

    // delegatecall into caller-controlled target -> REX-DELEG
    function execute(address target, bytes calldata data) external onlyOwner {
        (bool success, ) = target.delegatecall(data);
        require(success, "delegatecall failed");
    }
}
