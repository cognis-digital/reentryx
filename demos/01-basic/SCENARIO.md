# Demo 01 - Basic reentrancy detection

This demo runs REENTRYX against `Vault.sol`, a deliberately vulnerable
classic "withdraw" contract plus a read-only getter.

## What the contract does wrong

1. **Classic reentrancy (RX001)** - `withdraw()` sends ETH with a low-level
   `msg.sender.call{value: ...}("")` *before* zeroing the user's balance.
   An attacker contract can re-enter `withdraw()` from its `receive()` hook
   and drain the vault, because `balances[msg.sender]` is still non-zero when
   control returns to the attacker.

2. **Read-only reentrancy (RX002)** - the `totalShares` storage variable is
   updated *after* an external call inside `withdraw()`. The public `view`
   getter `getTotalShares()` reads that same variable, so an external protocol
   that calls the getter during the re-entrant window sees a stale value.

The contract also includes `safeWithdraw()`, which fixes the issue by writing
state *before* the external call (checks-effects-interactions). REENTRYX should
NOT flag `safeWithdraw()` for RX001.

## Run it

```
python -m reentryx scan demos/01-basic/Vault.sol
python -m reentryx scan demos/01-basic/Vault.sol --format json
python -m reentryx scan demos/01-basic/Vault.sol --format sarif -o vault.sarif
```

## Expected result

- At least one **RX001** finding in function `withdraw` for `balances`.
- At least one **RX002** finding in function `getTotalShares` for `totalShares`.
- No RX001 finding for `safeWithdraw`.
- Process exits with code **1** (findings present) - good for CI gates.
