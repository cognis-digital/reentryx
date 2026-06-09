"""Command-line interface for REENTRYX."""
from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    RULES,
    analyze,
    render_table,
    render_json,
    render_sarif,
)

SOL_EXTS = (".sol",)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Detect reentrancy and high-impact Solidity "
                    "vulnerabilities (read-only / cross-function / classic "
                    "reentrancy, unchecked-call, tx.origin, delegatecall).",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Scan Solidity file(s) or directories.")
    scan.add_argument("paths", nargs="+",
                      help="Solidity files and/or directories to scan.")
    scan.add_argument("--format", choices=["table", "json", "sarif"],
                      default="table", help="Output format (default: table).")
    scan.add_argument("--only", action="append", default=None,
                      metavar="RULE_ID",
                      help="Restrict to specific rule id(s); repeatable.")
    scan.add_argument("-o", "--output",
                      help="Write report to this file instead of stdout.")
    scan.add_argument("--exit-zero", action="store_true",
                      help="Always exit 0, even when findings are present.")

    rules = sub.add_parser("rules", help="List the detector knowledge base.")
    rules.add_argument("--format", choices=["table", "json"], default="table")

    return p


def _collect_files(paths: List[str]) -> List[str]:
    files: List[str] = []
    for path in paths:
        if os.path.isdir(path):
            for root, _dirs, names in os.walk(path):
                for n in names:
                    if n.endswith(SOL_EXTS):
                        files.append(os.path.join(root, n))
        else:
            files.append(path)
    return sorted(set(files))


def _run_scan(args) -> int:
    files = _collect_files(args.paths)
    if not files:
        print("error: no .sol files found", file=sys.stderr)
        return 2

    all_findings = []
    contracts = funcs = 0
    reports = []
    for fp in files:
        try:
            with open(fp, "r", encoding="utf-8") as fh:
                src = fh.read()
        except OSError as exc:
            print(f"error: cannot read {fp}: {exc}", file=sys.stderr)
            return 2
        rep = analyze(src, source_name=fp, only=args.only)
        reports.append(rep)
        all_findings.extend(rep.findings)
        contracts += rep.contracts
        funcs += rep.functions

    # Build a combined report for rendering.
    from .core import Report
    if len(reports) == 1:
        combined = reports[0]
    else:
        combined = Report(
            source=f"{len(files)} files",
            findings=sorted(
                all_findings,
                key=lambda f: (f.severity, f.contract, f.line, f.rule_id),
            ),
            contracts=contracts,
            functions=funcs,
        )

    if args.format == "json":
        out = render_json(combined)
    elif args.format == "sarif":
        out = render_sarif(combined)
    else:
        out = render_table(combined)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
        print(f"wrote {args.output} ({len(all_findings)} findings)")
    else:
        print(out)

    if args.exit_zero:
        return 0
    return 1 if combined.has_failures else 0


def _run_rules(args) -> int:
    if args.format == "json":
        import json
        print(json.dumps(RULES, indent=2))
        return 0
    print(f"{TOOL_NAME} {TOOL_VERSION} — detector knowledge base\n")
    for rid, meta in RULES.items():
        print(f"  {rid:14} [{meta['severity'].upper():6}] {meta['title']}")
    print(f"\n  {len(RULES)} rules.")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _run_scan(args)
    if args.command == "rules":
        return _run_rules(args)
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
