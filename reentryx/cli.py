"""Command-line interface for REENTRYX.

Examples
--------
  # Scan one or more Solidity files, human-readable table:
  reentryx scan contracts/Vault.sol

  # JSON output for piping into jq / CI:
  reentryx scan contracts/*.sol --format json

  # SARIF for GitHub code scanning:
  reentryx scan src/ --format sarif -o reentryx.sarif

Exit codes:
  0  no findings
  1  one or more findings (use for CI gates)
  2  usage / IO error
"""
from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    Finding,
    analyze_file,
    findings_to_json,
    findings_to_sarif,
)

_LEVEL_TAG = {"error": "ERROR ", "warning": "WARN  ", "note": "NOTE  "}


def _gather_sol_files(paths: List[str]) -> List[str]:
    out: List[str] = []
    for p in paths:
        if os.path.isdir(p):
            for root, _dirs, files in os.walk(p):
                for name in sorted(files):
                    if name.endswith(".sol"):
                        out.append(os.path.join(root, name))
        else:
            out.append(p)
    return out


def _render_table(findings: List[Finding]) -> str:
    if not findings:
        return "No reentrancy issues found."
    lines = []
    for f in findings:
        tag = _LEVEL_TAG.get(f.level, f.level.upper())
        lines.append(f"{tag} {f.rule_id} {f.filename}:{f.line}  [{f.function}]")
        lines.append(f"        {f.message}")
        if f.snippet:
            lines.append(f"        > {f.snippet}")
    n = len(findings)
    lines.append("")
    lines.append(f"{n} finding{'s' if n != 1 else ''}.")
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Static detector for reentrancy and read-only reentrancy in Solidity.",
        epilog="Example: reentryx scan contracts/ --format sarif -o out.sarif",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}"
    )
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser(
        "scan",
        help="Scan Solidity files or directories for reentrancy issues.",
        description="Scan one or more .sol files (or directories) for reentrancy.",
    )
    scan.add_argument("paths", nargs="+", help=".sol files or directories to scan")
    scan.add_argument(
        "--format",
        choices=["table", "json", "sarif"],
        default="table",
        help="output format (default: table)",
    )
    scan.add_argument(
        "-o", "--output", help="write output to a file instead of stdout"
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.print_help()
        return 2

    files = _gather_sol_files(args.paths)
    if not files:
        sys.stderr.write("error: no .sol files found in given paths\n")
        return 2

    all_findings: List[Finding] = []
    for path in files:
        try:
            all_findings.extend(analyze_file(path))
        except OSError as exc:
            sys.stderr.write(f"error: cannot read {path}: {exc}\n")
            return 2

    if args.format == "json":
        out = findings_to_json(all_findings)
    elif args.format == "sarif":
        out = findings_to_sarif(all_findings, TOOL_NAME, TOOL_VERSION)
    else:
        out = _render_table(all_findings)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(out + "\n")
        except OSError as exc:
            sys.stderr.write(f"error: cannot write {args.output}: {exc}\n")
            return 2
    else:
        sys.stdout.write(out + "\n")

    return 1 if all_findings else 0


if __name__ == "__main__":
    sys.exit(main())
