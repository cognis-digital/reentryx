"""REENTRYX — Solidity reentrancy & high-impact vulnerability analyzer.

A standard-library static analyzer for Solidity source, in the spirit of
crytic/slither. Detects classic state-after-call reentrancy, cross-function
reentrancy, read-only reentrancy, unchecked low-level calls, tx.origin
authentication, and dangerous delegatecall — modeling modifier bodies as
first-class units (where auth/guard logic usually lives). Emits table, JSON,
and SARIF 2.1.0.

Defensive analysis only: pure static inspection of source you provide. No
network access, no bytecode execution, no attack capability.
"""
from .core import (
    Finding,
    Report,
    Severity,
    RULES,
    analyze,
    analyze_file,
    render_table,
    render_json,
    render_sarif,
    strip_comments,
    parse,
    TOOL_NAME,
    TOOL_VERSION,
)

__all__ = [
    "Finding",
    "Report",
    "Severity",
    "RULES",
    "analyze",
    "analyze_file",
    "render_table",
    "render_json",
    "render_sarif",
    "strip_comments",
    "parse",
    "TOOL_NAME",
    "TOOL_VERSION",
]
