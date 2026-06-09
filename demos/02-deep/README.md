# reentryx deep demo

Two Solidity contracts: a deliberately vulnerable vault and a hardened one.

```bash
# Scan everything, human-readable
python -m reentryx scan demos/02-deep/

# CI / code-scanning ingest
python -m reentryx scan demos/02-deep/VulnerableVault.sol --format sarif -o out.sarif

# JSON for tooling, non-zero exit on high/medium findings
python -m reentryx scan demos/02-deep/VulnerableVault.sol --format json

# Only look for read-only reentrancy
python -m reentryx scan demos/02-deep/VulnerableVault.sol --only REX-RORE

# List the detector knowledge base (table or json)
python -m reentryx rules
python -m reentryx rules --format json
```

`VulnerableVault.sol` triggers REX-REEN, REX-XFRE, REX-RORE, REX-UCALL,
REX-TXORG (auth check inside the `onlyOwner` *modifier*), and REX-DELEG.
`SafeVault.sol` should be clean of high/medium findings.
