# reentryx deep demo — a full reentrancy/auth kill-chain in one vault

This scenario is a realistic DeFi vault (`VulnerableVault.sol`) that bundles
the six highest-impact Solidity vulnerability classes reentryx detects, plus a
hardened counterpart (`SafeVault.sol`) that should come back clean. It mirrors
the kind of audit triage a security engineer does with crytic/slither.

## The bugs in `VulnerableVault.sol`

1. **Classic reentrancy (REX-REEN).** `withdraw()` sends Ether with
   `msg.sender.call{value: amount}("")` *before* decrementing `balances` and
   `totalShares`. A malicious receiver re-enters and drains the vault.
2. **Cross-function reentrancy (REX-XFRE).** `transferShares()` calls out to
   `rewards.notify(...)` before settling the shared `balances` mapping that
   `deposit()`/`withdraw()` also mutate, all unguarded.
3. **Read-only reentrancy (REX-RORE).** The `view` getter `shareValue()` reads
   `totalShares`/`balances` while another function leaves them stale mid-call,
   so integrators (e.g. a price oracle) read a corrupt share price.
4. **Unchecked low-level call (REX-UCALL).** `payout()` ignores the boolean
   returned by `to.call{value:}("")`; a failed transfer silently succeeds.
5. **tx.origin authentication (REX-TXORG).** The `onlyOwner` **modifier** uses
   `require(tx.origin == owner)`, which is phishable through an intermediary
   contract. reentryx models modifier bodies, not just functions, so it catches
   this — the most common place auth logic actually lives.
6. **Dangerous delegatecall (REX-DELEG).** `execute()` `delegatecall`s into a
   caller-supplied `target`, letting an attacker overwrite storage (incl.
   `owner`) or `selfdestruct` the vault.

`SafeVault.sol` follows checks-effects-interactions, guards state-touching
functions with a custom `nonReentrant` modifier (recognized by name), checks
call return values, and authenticates with `msg.sender` — so it yields no
high/medium findings.

## Run it

```bash
# Human-readable table — exits 1 because high/medium findings exist
python -m reentryx scan demos/02-deep/VulnerableVault.sol

# The hardened contract — exits 0, no high/medium findings
python -m reentryx scan demos/02-deep/SafeVault.sol

# Whole directory at once
python -m reentryx scan demos/02-deep/

# SARIF 2.1.0 for GitHub code-scanning / CI ingest
python -m reentryx scan demos/02-deep/VulnerableVault.sol --format sarif -o out.sarif

# JSON for tooling
python -m reentryx scan demos/02-deep/VulnerableVault.sol --format json

# Restrict to a single detector
python -m reentryx scan demos/02-deep/VulnerableVault.sol --only REX-RORE

# Inspect the bundled detector knowledge base
python -m reentryx rules
python -m reentryx rules --format json
```

Expected: the vulnerable vault reports REX-REEN, REX-XFRE, REX-RORE,
REX-UCALL, REX-TXORG, and REX-DELEG and exits non-zero; the safe vault is clean.
