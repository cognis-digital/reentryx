"""Core static-analysis engine for REENTRYX.

The engine is deliberately stdlib-only. It does not build a full Solidity AST;
instead it performs a focused, line-aware lexical/structural analysis that is
robust enough to catch the dominant reentrancy patterns that show up in real
audits and PR reviews:

  RX001  classic reentrancy: an external call that transfers control to an
         untrusted contract (``.call{value:..}``, ``.call(...)``, low-level
         ``send``/``transfer`` to an address, or a call on a non-trusted
         contract handle) is followed by a state write to a storage variable.
         This is the checks-effects-interactions violation.

  RX002  read-only reentrancy: a ``view``/``public``/``external`` getter reads
         a storage variable that is written *after* an external call in some
         other (state-mutating) function in the same contract. During the
         re-entrant window the getter returns a stale value, which downstream
         protocols may trust.

The analysis is intentionally conservative about what counts as an *external
call* (to limit false positives) and reports a line number and a short,
actionable message for each finding.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple

RULES = {
    "RX001": {
        "name": "reentrancy-eth",
        "level": "error",
        "short": "State written after external call (checks-effects-interactions violation)",
    },
    "RX002": {
        "name": "reentrancy-readonly",
        "level": "warning",
        "short": "View function reads state that is updated after an external call",
    },
}

# Patterns that indicate an external call handing control to another contract.
_CALL_PATTERNS = [
    re.compile(r"\.call\s*\{"),            # addr.call{value: x}("")
    re.compile(r"\.call\s*\("),            # addr.call("")
    re.compile(r"\.delegatecall\s*\("),
    re.compile(r"\.send\s*\("),
    re.compile(r"\.transfer\s*\("),
    re.compile(r"\.functionCall\s*\("),   # OZ Address.functionCall
    re.compile(r"\.sendValue\s*\("),       # OZ Address.sendValue
]
# An interface-style call like IERC20(token).transfer(...) or token.onTokenReceived(...)
_IFACE_CALL = re.compile(r"\b[A-Z]\w*\s*\([^()]*\)\s*\.\s*\w+\s*\(")

_MODIFIER_GUARD = re.compile(r"\bnonReentrant\b")

_FUNC_RE = re.compile(
    r"function\s+(?P<name>\w+)\s*\((?P<params>[^)]*)\)\s*(?P<attrs>[^{;]*)",
)
_STATE_VAR_DECL = re.compile(
    r"^\s*(?:mapping\s*\([^;{}]*\)|address|uint\d*|int\d*|bool|bytes\d*|string)"
    r"(?:\s*\[[^\]]*\])?\s*(?:public|private|internal|external|constant|immutable|payable\s+)*"
    r"\s*(?P<name>\w+)\s*(?:=|;)"
)


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    level: str
    message: str
    filename: str
    line: int
    function: str
    snippet: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Function:
    name: str
    start_line: int
    end_line: int
    attrs: str
    body: str
    body_start_line: int
    is_view: bool = False
    is_external_visible: bool = False
    has_guard: bool = False
    # (line, varname) of storage writes that happen after the first external call
    writes_after_call: List[Tuple[int, str]] = field(default_factory=list)
    reads: List[Tuple[int, str]] = field(default_factory=list)
    first_call_line: Optional[int] = None


def _strip_comments(src: str) -> str:
    """Remove // and /* */ comments while preserving line count."""
    out = []
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                i += 1
        elif c == "/" and i + 1 < n and src[i + 1] == "*":
            i += 2
            while i + 1 < n and not (src[i] == "*" and src[i + 1] == "/"):
                if src[i] == "\n":
                    out.append("\n")
                i += 1
            i += 2
        elif c == '"' or c == "'":
            quote = c
            out.append(c)
            i += 1
            while i < n and src[i] != quote:
                if src[i] == "\\" and i + 1 < n:
                    out.append(src[i]); out.append(src[i + 1]); i += 2; continue
                out.append(src[i]); i += 1
            if i < n:
                out.append(src[i]); i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _collect_state_vars(src_nocomments: str) -> List[str]:
    """Best-effort list of contract-level storage variable names."""
    names: List[str] = []
    depth = 0
    in_func = False
    func_depth = 0
    for raw in src_nocomments.splitlines():
        line = raw
        # Track whether we are inside a function body (depth relative to func start)
        opens = line.count("{")
        closes = line.count("}")
        if "function" in line or re.search(r"\bconstructor\b", line):
            in_func = True
            func_depth = depth
        if not in_func and depth >= 1:
            m = _STATE_VAR_DECL.match(line)
            if m:
                names.append(m.group("name"))
        depth += opens - closes
        if in_func and depth <= func_depth:
            in_func = False
    # de-dup preserving order
    seen = set()
    uniq = []
    for nm in names:
        if nm not in seen:
            seen.add(nm)
            uniq.append(nm)
    return uniq


def _line_of(src: str, index: int) -> int:
    return src.count("\n", 0, index) + 1


def _extract_functions(src: str) -> List[Function]:
    funcs: List[Function] = []
    for m in _FUNC_RE.finditer(src):
        # find the opening brace after the match (skip abstract/interface decls ending in ;)
        brace_idx = src.find("{", m.end())
        semi_idx = src.find(";", m.end())
        if brace_idx == -1:
            continue
        if semi_idx != -1 and semi_idx < brace_idx:
            continue  # declaration only, no body
        # match the body via brace counting
        depth = 0
        i = brace_idx
        n = len(src)
        while i < n:
            if src[i] == "{":
                depth += 1
            elif src[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        body = src[brace_idx + 1 : i]
        attrs = m.group("attrs") or ""
        fn = Function(
            name=m.group("name"),
            start_line=_line_of(src, m.start()),
            end_line=_line_of(src, i),
            attrs=attrs.strip(),
            body=body,
            body_start_line=_line_of(src, brace_idx),
            is_view=bool(re.search(r"\b(view|pure)\b", attrs)),
            is_external_visible=bool(re.search(r"\b(public|external)\b", attrs)),
            has_guard=bool(_MODIFIER_GUARD.search(attrs)),
        )
        funcs.append(fn)
    return funcs


def _is_external_call(line: str) -> bool:
    for pat in _CALL_PATTERNS:
        if pat.search(line):
            return True
    if _IFACE_CALL.search(line):
        return True
    return False


def _write_target(line: str, state_vars: List[str]) -> Optional[str]:
    """If the line assigns to a known storage variable, return its name."""
    for var in state_vars:
        # var = ...   |  var += ...  |  var[...] = ...  | var -= / ++ / --
        pat = re.compile(
            r"\b" + re.escape(var) + r"\b\s*(?:\[[^\]]*\])*\s*(?:[-+*/%|&^]?=(?!=)|\+\+|--)"
        )
        if pat.search(line):
            return var
    return None


def _read_targets(line: str, state_vars: List[str]) -> List[str]:
    found = []
    for var in state_vars:
        if re.search(r"\b" + re.escape(var) + r"\b", line):
            found.append(var)
    return found


def _analyze_function(fn: Function, state_vars: List[str]) -> None:
    body_lines = fn.body.split("\n")
    seen_call = False
    call_line = None
    for offset, raw in enumerate(body_lines):
        abs_line = fn.body_start_line + offset
        line = raw.strip()
        if not line:
            continue
        if not seen_call and _is_external_call(line):
            seen_call = True
            call_line = abs_line
            fn.first_call_line = abs_line
            continue
        if seen_call:
            wt = _write_target(line, state_vars)
            if wt:
                fn.writes_after_call.append((abs_line, wt))
        # record reads (for read-only reentrancy view detection)
        if fn.is_view:
            for var in _read_targets(line, state_vars):
                fn.reads.append((abs_line, var))


def analyze_source(source: str, filename: str = "<source>") -> List[Finding]:
    """Analyze Solidity ``source`` text and return a list of Findings."""
    clean = _strip_comments(source)
    state_vars = _collect_state_vars(clean)
    funcs = _extract_functions(clean)
    src_lines = source.split("\n")

    for fn in funcs:
        _analyze_function(fn, state_vars)

    findings: List[Finding] = []

    # RX001: classic reentrancy - state write after external call (no guard)
    vars_written_after_call: Dict[str, int] = {}
    for fn in funcs:
        if fn.has_guard:
            # nonReentrant guard mitigates classic reentrancy; still track for read-only
            for ln, var in fn.writes_after_call:
                vars_written_after_call.setdefault(var, ln)
            continue
        for ln, var in fn.writes_after_call:
            vars_written_after_call.setdefault(var, ln)
            snippet = src_lines[ln - 1].strip() if 0 < ln <= len(src_lines) else ""
            findings.append(
                Finding(
                    rule_id="RX001",
                    rule_name=RULES["RX001"]["name"],
                    level=RULES["RX001"]["level"],
                    message=(
                        f"State variable '{var}' is written on line {ln} after the "
                        f"external call on line {fn.first_call_line} in function "
                        f"'{fn.name}'. Move effects before interactions or add a "
                        f"nonReentrant guard."
                    ),
                    filename=filename,
                    line=ln,
                    function=fn.name,
                    snippet=snippet,
                )
            )

    # RX002: read-only reentrancy - a view getter reads a var that is mutated
    # after an external call elsewhere (even guarded functions count, because
    # the guard does not protect external view readers during the call window).
    risky_vars: Dict[str, int] = {}
    for fn in funcs:
        for ln, var in fn.writes_after_call:
            risky_vars.setdefault(var, ln)
    for fn in funcs:
        if not (fn.is_view and fn.is_external_visible):
            continue
        reported_vars = set()
        for ln, var in fn.reads:
            if var in risky_vars and var not in reported_vars:
                reported_vars.add(var)
                snippet = src_lines[ln - 1].strip() if 0 < ln <= len(src_lines) else ""
                findings.append(
                    Finding(
                        rule_id="RX002",
                        rule_name=RULES["RX002"]["name"],
                        level=RULES["RX002"]["level"],
                        message=(
                            f"View function '{fn.name}' reads state variable '{var}' "
                            f"(line {ln}) that is updated after an external call "
                            f"(line {risky_vars[var]}). A read-only reentrancy attacker "
                            f"can observe a stale value."
                        ),
                        filename=filename,
                        line=ln,
                        function=fn.name,
                        snippet=snippet,
                    )
                )

    findings.sort(key=lambda f: (f.line, f.rule_id))
    return findings


def analyze_file(path: str) -> List[Finding]:
    with open(path, "r", encoding="utf-8") as fh:
        return analyze_source(fh.read(), filename=path)


def findings_to_json(findings: List[Finding]) -> str:
    return json.dumps([f.to_dict() for f in findings], indent=2)


def findings_to_sarif(findings: List[Finding], tool_name: str, tool_version: str) -> str:
    """Render findings as a SARIF 2.1.0 document (string)."""
    rule_index: Dict[str, int] = {}
    rules_list = []
    for rid, meta in RULES.items():
        rule_index[rid] = len(rules_list)
        rules_list.append(
            {
                "id": rid,
                "name": meta["name"],
                "shortDescription": {"text": meta["short"]},
                "defaultConfiguration": {"level": meta["level"]},
            }
        )
    results = []
    for f in findings:
        results.append(
            {
                "ruleId": f.rule_id,
                "ruleIndex": rule_index.get(f.rule_id, 0),
                "level": f.level,
                "message": {"text": f.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.filename},
                            "region": {"startLine": f.line, "snippet": {"text": f.snippet}},
                        }
                    }
                ],
            }
        )
    doc = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": "https://github.com/cognis/reentryx",
                        "rules": rules_list,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2)
