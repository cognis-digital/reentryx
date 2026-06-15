"""Core engine for REENTRYX.

A static analyzer for Solidity source that detects high-impact smart-contract
vulnerability classes, in the spirit of crytic/slither:

  * read-only reentrancy        (REX-RORE)
  * cross-function reentrancy   (REX-XFRE)
  * classic state-after-call    (REX-REEN)
  * unchecked low-level call     (REX-UCALL)
  * tx.origin authentication    (REX-TXORG)
  * delegatecall to untrusted    (REX-DELEG)

It works by lexing the source, slicing it into contracts and functions, building
a lightweight per-function model (which storage variables are read / written,
which external calls are made and in what order, modifiers, visibility, and
function-state-mutability), then running detector rules over that model.

Modifiers are modeled as first-class units too (like Slither), because auth and
guard logic -- tx.origin checks, low-level calls -- most often lives in a
modifier rather than a function body.

Output formats: table, JSON, and SARIF 2.1.0 (the format Slither emits for
CI / code-scanning integration).

Standard library only. No network. Single-pass, robust to comments & strings.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Iterable, List, Optional, Tuple

TOOL_NAME = "reentryx"
TOOL_VERSION = "2.1.0"

# ---------------------------------------------------------------------------
# Severity model
# ---------------------------------------------------------------------------


class Severity:
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3}

    # SARIF maps severities onto error / warning / note levels.
    SARIF_LEVEL = {HIGH: "error", MEDIUM: "warning", LOW: "warning", INFO: "note"}

    @classmethod
    def rank(cls, sev: str) -> int:
        return cls.ORDER.get(sev, 99)


# Findings at these severities cause a non-zero process exit.
FAIL_AT = {Severity.HIGH, Severity.MEDIUM}


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    contract: str
    function: str
    line: int
    detail: str
    remediation: str
    confidence: str = "medium"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Report:
    source: str
    findings: List[Finding] = field(default_factory=list)
    contracts: int = 0
    functions: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "source": self.source,
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.findings],
        }

    def summary(self) -> Dict[str, int]:
        out = {s: 0 for s in (Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        out["total"] = len(self.findings)
        out["contracts"] = self.contracts
        out["functions"] = self.functions
        return out

    @property
    def has_failures(self) -> bool:
        return any(f.severity in FAIL_AT for f in self.findings)


# ---------------------------------------------------------------------------
# Bundled rule metadata (the "knowledge base")
# ---------------------------------------------------------------------------

RULES: Dict[str, Dict[str, str]] = {
    "REX-REEN": {
        "title": "State write after external call (reentrancy)",
        "severity": Severity.HIGH,
        "help": (
            "An external call is followed by a storage write in the same "
            "function. An attacker contract can re-enter before state is "
            "updated. Apply checks-effects-interactions: update state BEFORE "
            "the external call, or guard with a nonReentrant mutex."
        ),
    },
    "REX-XFRE": {
        "title": "Cross-function reentrancy",
        "severity": Severity.HIGH,
        "help": (
            "A function makes an external call before finalizing a storage "
            "variable that a second, non-guarded function also exposes/mutates. "
            "An attacker can re-enter through the sibling function while the "
            "shared variable is stale. Guard ALL functions touching the shared "
            "state with the same reentrancy mutex."
        ),
    },
    "REX-RORE": {
        "title": "Read-only reentrancy",
        "severity": Severity.MEDIUM,
        "help": (
            "A public/external view function reads a storage variable that is "
            "left in an inconsistent state during another function's external "
            "call. Integrators reading this getter mid-callback observe stale "
            "values. Make the view consistent or expose a reentrancy-aware "
            "read. nonReentrant does NOT protect view functions."
        ),
    },
    "REX-UCALL": {
        "title": "Unchecked low-level call return value",
        "severity": Severity.MEDIUM,
        "help": (
            "The boolean returned by .call/.send/.delegatecall is ignored. A "
            "failed transfer silently continues. Check the return value and "
            "revert on failure, or use a safe wrapper."
        ),
    },
    "REX-TXORG": {
        "title": "tx.origin used for authorization",
        "severity": Severity.HIGH,
        "help": (
            "tx.origin authentication is phishable: a malicious intermediate "
            "contract called by the victim passes the tx.origin check. Use "
            "msg.sender for authorization."
        ),
    },
    "REX-DELEG": {
        "title": "delegatecall into caller-controlled target",
        "severity": Severity.HIGH,
        "help": (
            "delegatecall executes external code in this contract's storage "
            "context. If the target address derives from msg.sender / calldata, "
            "an attacker can overwrite arbitrary storage (incl. owner) or "
            "selfdestruct the contract. Restrict the target to a vetted, "
            "immutable implementation."
        ),
    },
    "REX-SEND-VALUE": {
        "title": "Funds-moving external call without reentrancy guard",
        "severity": Severity.LOW,
        "help": (
            "A value-bearing external call is made from a function with no "
            "nonReentrant modifier. Even with checks-effects-interactions, a "
            "mutex is defense-in-depth for any function that moves Ether."
        ),
    },
}


# ---------------------------------------------------------------------------
# Lexing / source normalization
# ---------------------------------------------------------------------------


def strip_comments(src: str) -> str:
    """Replace comments and string/hex literals with spaces, preserving offsets.

    Keeping the character count identical lets us map any offset back to the
    original line number with a simple newline count.
    """
    out = list(src)
    i, n = 0, len(src)
    state = None  # None | "line" | "block" | "str" | "char"
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if state is None:
            if c == "/" and nxt == "/":
                state = "line"
                out[i] = out[i + 1] = " "
                i += 2
                continue
            if c == "/" and nxt == "*":
                state = "block"
                out[i] = out[i + 1] = " "
                i += 2
                continue
            if c == '"':
                state = "str"
                # keep quote so we can still see assignment shapes
                i += 1
                continue
            if c == "'":
                state = "char"
                i += 1
                continue
            i += 1
        elif state == "line":
            if c == "\n":
                state = None
            else:
                out[i] = " "
            i += 1
        elif state == "block":
            if c == "*" and nxt == "/":
                out[i] = out[i + 1] = " "
                i += 2
                state = None
            else:
                if c != "\n":
                    out[i] = " "
                i += 1
        elif state == "str":
            if c == "\\":
                out[i] = " "
                if i + 1 < n and src[i + 1] != "\n":
                    out[i + 1] = " "
                i += 2
                continue
            if c == '"':
                state = None
                i += 1
                continue
            out[i] = " "
            i += 1
        elif state == "char":
            if c == "\\":
                out[i] = " "
                if i + 1 < n and src[i + 1] != "\n":
                    out[i + 1] = " "
                i += 2
                continue
            if c == "'":
                state = None
                i += 1
                continue
            out[i] = " "
            i += 1
    return "".join(out)


def _line_at(src: str, offset: int) -> int:
    return src.count("\n", 0, offset) + 1


def _matching_brace(src: str, open_idx: int) -> int:
    """Return index of the '}' matching the '{' at open_idx, or len(src)."""
    depth = 0
    for i in range(open_idx, len(src)):
        c = src[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
    return len(src) - 1


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


@dataclass
class FunctionModel:
    name: str
    visibility: str
    mutability: str          # "", "view", "pure", "payable", "nonpayable"
    modifiers: List[str]
    has_guard: bool
    start_line: int
    body: str
    body_offset: int         # offset of body within the (clean) full source
    kind: str = "function"   # "function" | "modifier"
    # external-call sites: (offset, snippet, is_value_bearing, is_low_level)
    calls: List[Tuple[int, str, bool, bool]] = field(default_factory=list)
    writes: List[str] = field(default_factory=list)
    reads: List[str] = field(default_factory=list)


@dataclass
class ContractModel:
    name: str
    kind: str                # contract | library | interface
    start_line: int
    state_vars: List[str]
    functions: List[FunctionModel]


GUARD_NAMES = {"nonreentrant", "noreentrancy", "nonreentrantview", "lock", "mutex"}

_STATE_VAR_RE = re.compile(
    r"^\s*(?:mapping\s*\([^;{}]*\)|"
    r"(?:u?int\d*|address|bool|bytes\d*|string|"
    r"[A-Z][A-Za-z0-9_]*))\s*"
    r"(?:public|private|internal|external|constant|immutable|payable|memory|storage|calldata|\s)*"
    r"\b([A-Za-z_]\w*)\s*(?:=|;)",
    re.MULTILINE,
)

_FUNC_RE = re.compile(
    r"\bfunction\s+([A-Za-z_]\w*)\s*"  # function name
    r"((?:\([^;{}]*\)|[^;{}()])*?)"     # params + attrs blob (balanced-ish)
    r"\{",
    re.DOTALL,
)

# Modifiers define auth/guard logic and frequently contain the very checks
# (tx.origin, low-level calls) that detectors care about. Slither models them
# as first-class units; so do we. A modifier with parameters or none:
#   modifier onlyOwner() { ... }
#   modifier costs(uint price) { ... }
_MODIFIER_RE = re.compile(
    r"\bmodifier\s+([A-Za-z_]\w*)\s*"
    r"(\([^;{}]*\))?\s*"
    r"\{",
    re.DOTALL,
)

_CONTRACT_RE = re.compile(
    r"\b(contract|library|interface)\s+([A-Za-z_]\w*)"
    r"(?:\s+is\s+[^{]+)?\s*\{",
)

# External call patterns: x.call{...}(...), x.send(...), x.transfer(...),
# x.delegatecall(...), x.staticcall(...), and generic interface calls
# Token(addr).foo(...) / IERC20(t).transferFrom(...).
_LOWLEVEL_RE = re.compile(
    r"\.\s*(call|delegatecall|staticcall|send|transfer)\s*"
    r"(?:\{[^}]*\})?\s*\("
)
_IFACE_CALL_RE = re.compile(
    r"\b([A-Z][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*\.\s*([A-Za-z_]\w*)\s*"
    r"(?:\{[^}]*\})?\s*\("
)
_VAR_CALL_RE = re.compile(
    r"\b([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)\s*(?:\{[^}]*\})?\s*\("
)

_VALUE_CALL_RE = re.compile(r"\.\s*(?:call|delegatecall)\s*\{[^}]*value\s*:")
_SEND_TRANSFER_RE = re.compile(r"\.\s*(?:send|transfer)\s*\(")

# Builtins / non-external member accesses we never treat as external calls.
_NON_EXTERNAL = {
    "push", "pop", "length", "selector", "address", "balance", "code",
    "codehash", "encode", "encodePacked", "encodeWithSelector",
    "encodeWithSignature", "decode", "wrap", "unwrap", "min", "max",
    "sub", "add", "mul", "div", "toUint256", "log", "log0",
}


def _attr_tokens(attr_blob: str) -> List[str]:
    return re.findall(r"[A-Za-z_]\w*", attr_blob)


def parse(clean: str) -> List[ContractModel]:
    contracts: List[ContractModel] = []
    for cm in _CONTRACT_RE.finditer(clean):
        kind, name = cm.group(1), cm.group(2)
        open_brace = clean.index("{", cm.start())
        end = _matching_brace(clean, open_brace)
        body = clean[open_brace + 1 : end]
        body_off = open_brace + 1
        start_line = _line_at(clean, cm.start())

        # state variables: top-level declarations inside the contract body, not
        # inside any function. Approximate by scanning declarations whose brace
        # depth (relative to contract body) is zero.
        state_vars = _top_level_state_vars(body)

        functions = _parse_functions(body, body_off, clean, state_vars)
        contracts.append(
            ContractModel(name=name, kind=kind, start_line=start_line,
                          state_vars=state_vars, functions=functions)
        )
    return contracts


def _top_level_state_vars(body: str) -> List[str]:
    """State vars declared at contract-top-level (brace depth 0)."""
    names: List[str] = []
    depth = 0
    seg_start = 0
    segments: List[str] = []
    for i, c in enumerate(body):
        if c == "{":
            if depth == 0:
                segments.append(body[seg_start:i])
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                seg_start = i + 1
        elif c == ";" and depth == 0:
            segments.append(body[seg_start:i + 1])
            seg_start = i + 1
    segments.append(body[seg_start:])
    top = "\n".join(s for s in segments)
    for m in _STATE_VAR_RE.finditer(top):
        nm = m.group(1)
        if nm not in names:
            names.append(nm)
    return names


def _parse_functions(body: str, body_off: int, clean: str,
                     state_vars: Optional[List[str]] = None) -> List[FunctionModel]:
    funcs: List[FunctionModel] = []
    for fm in _FUNC_RE.finditer(body):
        name = fm.group(1)
        attrs = _attr_tokens(fm.group(2))
        attrs_lower = [a.lower() for a in attrs]
        vis = "internal"
        for v in ("public", "external", "internal", "private"):
            if v in attrs_lower:
                vis = v
                break
        mut = ""
        for m in ("view", "pure", "payable"):
            if m in attrs_lower:
                mut = m
                break
        known = {"public", "external", "internal", "private", "view", "pure",
                 "payable", "virtual", "override", "returns", "memory",
                 "storage", "calldata"}
        modifiers = [a for a in attrs if a.lower() not in known]
        has_guard = any(a.lower() in GUARD_NAMES for a in modifiers)

        open_brace = body.index("{", fm.start())
        end = _matching_brace(body, open_brace)
        fbody = body[open_brace + 1 : end]
        fbody_off = body_off + open_brace + 1
        start_line = _line_at(clean, body_off + fm.start())

        f = FunctionModel(
            name=name, visibility=vis, mutability=mut, modifiers=modifiers,
            has_guard=has_guard, start_line=start_line, body=fbody,
            body_offset=fbody_off,
        )
        _analyze_function_body(f, clean, state_vars)
        funcs.append(f)

    # Modifiers: analyze their bodies too. They carry the auth/guard logic
    # (tx.origin checks, low-level calls) the detectors must see. A modifier
    # is treated as an internal, non-view "function" for detector purposes.
    for mm in _MODIFIER_RE.finditer(body):
        mname = mm.group(1)
        open_brace = body.index("{", mm.start())
        end = _matching_brace(body, open_brace)
        mbody = body[open_brace + 1 : end]
        mbody_off = body_off + open_brace + 1
        start_line = _line_at(clean, body_off + mm.start())
        fm_mod = FunctionModel(
            name=mname, visibility="internal", mutability="",
            modifiers=[], has_guard=False, start_line=start_line,
            body=mbody, body_offset=mbody_off, kind="modifier",
        )
        _analyze_function_body(fm_mod, clean, state_vars)
        funcs.append(fm_mod)
    return funcs


def _analyze_function_body(f: FunctionModel, clean: str,
                           state_vars: Optional[List[str]] = None) -> None:
    state_set = set(state_vars or [])
    fbody = f.body

    # external calls -----------------------------------------------------
    seen_offsets: set = set()
    for m in _LOWLEVEL_RE.finditer(fbody):
        off = m.start()
        seen_offsets.add(off)
        snippet = _snippet(fbody, off)
        is_value = bool(_VALUE_CALL_RE.search(fbody[off - 1:off + 60])) or \
            bool(_SEND_TRANSFER_RE.match(fbody[off:off + 30]))
        f.calls.append((f.body_offset + off, snippet, is_value, True))

    for m in _IFACE_CALL_RE.finditer(fbody):
        member = m.group(2)
        if member in _NON_EXTERNAL:
            continue
        if m.start() in seen_offsets:
            continue
        snippet = _snippet(fbody, m.start())
        is_value = bool(re.search(r"\{[^}]*value\s*:", fbody[m.start():m.end() + 5]))
        f.calls.append((f.body_offset + m.start(), snippet, is_value, False))
        seen_offsets.add(m.start())

    for m in _VAR_CALL_RE.finditer(fbody):
        recv, member = m.group(1), m.group(2)
        if member in _NON_EXTERNAL:
            continue
        # skip msg./block./abi./tx. builtins and obvious internal helpers
        if recv in {"msg", "block", "abi", "tx", "type", "super", "this",
                    "string", "bytes", "address"}:
            continue
        if m.start() in seen_offsets:
            continue
        # only treat capitalized/external-looking receivers, or receivers that
        # look like address-typed params (heuristic: contains addr/token/target)
        looks_external = (
            recv[:1].isupper()
            or recv in state_set
            or re.search(r"(addr|token|target|pool|vault|recipient|to|dest|"
                         r"reward|oracle|router|gateway)",
                         recv, re.IGNORECASE)
        )
        if not looks_external:
            continue
        snippet = _snippet(fbody, m.start())
        is_value = bool(re.search(r"\{[^}]*value\s*:", fbody[m.start():m.end() + 5]))
        f.calls.append((f.body_offset + m.start(), snippet, is_value, False))
        seen_offsets.add(m.start())

    f.calls.sort(key=lambda t: t[0])

    # storage reads / writes --------------------------------------------
    # writes: identifier (optionally indexed) on the LHS of an assignment.
    for m in re.finditer(
        r"\b([A-Za-z_]\w*)\s*(?:\[[^\]]*\]|\.\w+)*\s*"
        r"(?:=(?![=>])|\+=|-=|\*=|/=|\|=|&=|\^=|%=)", fbody
    ):
        f.writes.append(m.group(1))
    for m in re.finditer(r"\bdelete\s+([A-Za-z_]\w*)", fbody):
        f.writes.append(m.group(1))
    # reads: any identifier (we filter against state vars later)
    for m in re.finditer(r"\b([A-Za-z_]\w*)\b", fbody):
        f.reads.append(m.group(1))


def _snippet(text: str, off: int, width: int = 70) -> str:
    line_start = text.rfind("\n", 0, off) + 1
    line_end = text.find("\n", off)
    if line_end == -1:
        line_end = len(text)
    s = text[line_start:line_end].strip()
    return s[:width]


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------


def _mk(rule_id: str, contract: str, function: str, line: int,
        detail: str, confidence: str = "medium") -> Finding:
    r = RULES[rule_id]
    return Finding(
        rule_id=rule_id, title=r["title"], severity=r["severity"],
        contract=contract, function=function, line=line, detail=detail,
        remediation=r["help"], confidence=confidence,
    )


def detect_reentrancy(c: ContractModel, clean: str) -> List[Finding]:
    """Classic checks-effects-interactions violation: state write after call."""
    out: List[Finding] = []
    stvars = set(c.state_vars)
    for f in c.functions:
        if f.kind == "modifier":
            continue
        if f.mutability in ("view", "pure") or not f.calls:
            continue
        if f.has_guard:
            continue
        first_call_off = f.calls[0][0]
        # find storage writes after the first external call
        for m in re.finditer(
            r"\b([A-Za-z_]\w*)\s*(?:\[[^\]]*\]|\.\w+)*\s*"
            r"(?:=(?![=>])|\+=|-=|\*=|/=)", f.body
        ):
            wname = m.group(1)
            if wname not in stvars:
                continue
            abs_off = f.body_offset + m.start()
            if abs_off > first_call_off:
                line = _line_at(clean, abs_off)
                out.append(_mk(
                    "REX-REEN", c.name, f.name, line,
                    f"Storage var '{wname}' is written AFTER an external call "
                    f"(`{f.calls[0][1]}`). Reorder per checks-effects-"
                    f"interactions or add a nonReentrant guard.",
                    confidence="high",
                ))
                break  # one finding per function is enough signal
    return out


def detect_cross_function(c: ContractModel, clean: str) -> List[Finding]:
    """A guarded-missing function makes a call before settling a state var that
    another non-guarded function in the same contract also mutates."""
    out: List[Finding] = []
    stvars = set(c.state_vars)

    # map: state var -> functions that write it
    writers: Dict[str, List[FunctionModel]] = {}
    for f in c.functions:
        if f.kind == "modifier":
            continue
        for w in set(f.writes):
            if w in stvars:
                writers.setdefault(w, []).append(f)

    for f in c.functions:
        if f.kind == "modifier":
            continue
        if f.mutability in ("view", "pure") or not f.calls or f.has_guard:
            continue
        first_call_off = f.calls[0][0]
        # state vars this function writes AFTER the external call
        post_call_writes = set()
        for m in re.finditer(
            r"\b([A-Za-z_]\w*)\s*(?:\[[^\]]*\]|\.\w+)*\s*"
            r"(?:=(?![=>])|\+=|-=|\*=|/=)", f.body
        ):
            if m.group(1) in stvars and f.body_offset + m.start() > first_call_off:
                post_call_writes.add(m.group(1))
        for var in post_call_writes:
            for sib in writers.get(var, []):
                if sib is f or sib.has_guard:
                    continue
                if sib.visibility in ("public", "external"):
                    out.append(_mk(
                        "REX-XFRE", c.name, f.name, f.start_line,
                        f"Function '{f.name}' calls out before settling '{var}', "
                        f"and sibling '{sib.name}' ({sib.visibility}, unguarded) "
                        f"also mutates '{var}'. An attacker can re-enter via "
                        f"'{sib.name}' while '{var}' is stale.",
                        confidence="medium",
                    ))
                    break
    return out


def detect_readonly_reentrancy(c: ContractModel, clean: str) -> List[Finding]:
    """A public/external view reads a state var that a non-guarded mutating
    function leaves inconsistent during an external call."""
    out: List[Finding] = []
    stvars = set(c.state_vars)

    # state vars left stale during a call (written after the first call) in any
    # unguarded mutating function
    stale_vars: Dict[str, str] = {}
    for f in c.functions:
        if f.kind == "modifier":
            continue
        if f.mutability in ("view", "pure") or not f.calls or f.has_guard:
            continue
        first_call_off = f.calls[0][0]
        for m in re.finditer(
            r"\b([A-Za-z_]\w*)\s*(?:\[[^\]]*\]|\.\w+)*\s*"
            r"(?:=(?![=>])|\+=|-=|\*=|/=)", f.body
        ):
            if m.group(1) in stvars and f.body_offset + m.start() > first_call_off:
                stale_vars.setdefault(m.group(1), f.name)

    if not stale_vars:
        return out

    for f in c.functions:
        if f.mutability != "view":
            continue
        if f.visibility not in ("public", "external"):
            continue
        read_set = set(f.reads) & set(stale_vars)
        for var in sorted(read_set):
            out.append(_mk(
                "REX-RORE", c.name, f.name, f.start_line,
                f"View '{f.name}' reads '{var}', which '{stale_vars[var]}' "
                f"updates only AFTER an external call. Integrators querying "
                f"'{f.name}' during that callback observe a stale '{var}'. "
                f"nonReentrant does not protect views.",
                confidence="medium",
            ))
    return out


def detect_unchecked_call(c: ContractModel, clean: str) -> List[Finding]:
    """Low-level .call/.send/.delegatecall whose bool return is discarded."""
    out: List[Finding] = []
    for f in c.functions:
        for m in re.finditer(
            r"(?P<lhs>[^\n;{}]*?)\.\s*(?P<kind>call|send|delegatecall)\s*"
            r"(?:\{[^}]*\})?\s*\([^;]*?\)\s*(?P<tail>;|,|\))", f.body, re.DOTALL
        ):
            kind = m.group("kind")
            lhs = m.group("lhs")
            tail = m.group("tail")
            # "checked" if assigned, used in require/if, or the bool captured
            checked = (
                "=" in lhs
                or "require" in lhs
                or "if" in lhs
                or "(" in lhs.strip()[-1:] if lhs.strip() else False
            )
            # also treat `(bool ok, ) = x.call(...)` as checked (= in lhs)
            if checked:
                continue
            # tail ';' immediately after close paren with bare statement => unchecked
            if tail == ";":
                abs_off = f.body_offset + m.start()
                line = _line_at(clean, abs_off)
                out.append(_mk(
                    "REX-UCALL", c.name, f.name, line,
                    f"Return value of low-level `.{kind}(...)` is ignored. A "
                    f"failed call continues silently.",
                    confidence="high",
                ))
    return out


def detect_tx_origin(c: ContractModel, clean: str) -> List[Finding]:
    out: List[Finding] = []
    for f in c.functions:
        for m in re.finditer(
            r"\btx\s*\.\s*origin\b\s*(==|!=)|"
            r"(==|!=)\s*tx\s*\.\s*origin\b|"
            r"require\s*\([^;]*tx\s*\.\s*origin", f.body
        ):
            abs_off = f.body_offset + m.start()
            line = _line_at(clean, abs_off)
            out.append(_mk(
                "REX-TXORG", c.name, f.name, line,
                "tx.origin is compared for authorization. Use msg.sender; "
                "tx.origin checks are phishable via an intermediary contract.",
                confidence="high",
            ))
            break  # one per function
    return out


def detect_delegatecall(c: ContractModel, clean: str) -> List[Finding]:
    out: List[Finding] = []
    for f in c.functions:
        for m in re.finditer(
            r"([A-Za-z_]\w*)\s*\.\s*delegatecall\s*(?:\{[^}]*\})?\s*\(", f.body
        ):
            recv = m.group(1)
            abs_off = f.body_offset + m.start()
            line = _line_at(clean, abs_off)
            # Heuristic: target untrusted if receiver is a function param, a
            # name suggesting external input, or assigned from calldata/msg.
            untrusted = bool(re.search(
                r"(target|impl|addr|to|input|param|user|data)", recv, re.IGNORECASE
            ))
            # higher confidence if receiver looks like a parameter (lowercase &
            # not a known state var)
            conf = "high" if (untrusted and recv not in set(c.state_vars)) else "low"
            sev_note = "" if untrusted else " (verify target is immutable/vetted)"
            out.append(_mk(
                "REX-DELEG", c.name, f.name, line,
                f"delegatecall on `{recv}`{sev_note}. If the target is "
                f"caller-controlled, an attacker can hijack this contract's "
                f"storage or selfdestruct it.",
                confidence=conf,
            ))
    return out


def detect_value_send_no_guard(c: ContractModel, clean: str) -> List[Finding]:
    out: List[Finding] = []
    for f in c.functions:
        if f.kind == "modifier":
            continue
        if f.has_guard or f.mutability in ("view", "pure"):
            continue
        for off, snippet, is_value, _low in f.calls:
            if is_value:
                line = _line_at(clean, off)
                out.append(_mk(
                    "REX-SEND-VALUE", c.name, f.name, line,
                    f"Value-bearing external call `{snippet}` in unguarded "
                    f"function '{f.name}'. Add a nonReentrant mutex for "
                    f"defense-in-depth.",
                    confidence="low",
                ))
                break
    return out


DETECTORS = [
    detect_reentrancy,
    detect_cross_function,
    detect_readonly_reentrancy,
    detect_unchecked_call,
    detect_tx_origin,
    detect_delegatecall,
    detect_value_send_no_guard,
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def analyze(src: str, source_name: str = "<source>",
            only: Optional[Iterable[str]] = None) -> Report:
    clean = strip_comments(src)
    contracts = parse(clean)
    only_set = {r.upper() for r in only} if only else None

    findings: List[Finding] = []
    nfuncs = 0
    for c in contracts:
        nfuncs += sum(1 for fn in c.functions if fn.kind == "function")
        for det in DETECTORS:
            for fnd in det(c, clean):
                if only_set and fnd.rule_id not in only_set:
                    continue
                findings.append(fnd)

    findings.sort(key=lambda f: (Severity.rank(f.severity), f.contract,
                                 f.line, f.rule_id))
    rep = Report(source=source_name, findings=findings,
                 contracts=len(contracts), functions=nfuncs)
    return rep


def analyze_file(path: str, only: Optional[Iterable[str]] = None) -> Report:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            src = fh.read()
    except FileNotFoundError:
        raise FileNotFoundError(f"Solidity file not found: {path!r}") from None
    except PermissionError:
        raise PermissionError(f"Permission denied reading: {path!r}") from None
    except OSError as exc:
        raise OSError(f"Cannot read {path!r}: {exc}") from exc
    return analyze(src, source_name=path, only=only)


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------


def render_table(rep: Report) -> str:
    lines: List[str] = []
    s = rep.summary()
    lines.append(f"reentryx {TOOL_VERSION}  —  {rep.source}")
    lines.append(
        f"contracts={s['contracts']} functions={s['functions']}  "
        f"findings={s['total']} "
        f"(high={s['high']} medium={s['medium']} low={s['low']} info={s['info']})"
    )
    lines.append("-" * 78)
    if not rep.findings:
        lines.append("No findings. Clean.")
        return "\n".join(lines)
    for f in rep.findings:
        lines.append(
            f"[{f.severity.upper():6}] {f.rule_id:12} {f.contract}.{f.function}"
            f"  (line {f.line}, conf={f.confidence})"
        )
        lines.append(f"        {f.title}")
        lines.append(f"        {f.detail}")
        lines.append("")
    return "\n".join(lines)


def render_json(rep: Report) -> str:
    return json.dumps(rep.to_dict(), indent=2)


def render_sarif(rep: Report) -> str:
    """SARIF 2.1.0 output (matches what code-scanning ingests)."""
    rule_index: Dict[str, int] = {}
    sarif_rules: List[Dict[str, Any]] = []
    for rid, meta in RULES.items():
        rule_index[rid] = len(sarif_rules)
        sarif_rules.append({
            "id": rid,
            "name": meta["title"].replace(" ", ""),
            "shortDescription": {"text": meta["title"]},
            "fullDescription": {"text": meta["help"]},
            "defaultConfiguration": {
                "level": Severity.SARIF_LEVEL.get(meta["severity"], "warning")
            },
            "properties": {"security-severity": _sec_score(meta["severity"])},
            "help": {"text": meta["help"]},
        })

    results: List[Dict[str, Any]] = []
    for f in rep.findings:
        results.append({
            "ruleId": f.rule_id,
            "ruleIndex": rule_index.get(f.rule_id, 0),
            "level": Severity.SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f"{f.title}: {f.detail}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": rep.source},
                    "region": {"startLine": max(1, f.line)},
                },
                "logicalLocations": [{
                    "name": f.function,
                    "fullyQualifiedName": f"{f.contract}.{f.function}",
                    "kind": "function",
                }],
            }],
            "properties": {
                "contract": f.contract,
                "confidence": f.confidence,
            },
        })

    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "version": TOOL_VERSION,
                    "informationUri": "https://cognis.work/reentryx",
                    "rules": sarif_rules,
                }
            },
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2)


def _sec_score(sev: str) -> str:
    return {"high": "8.5", "medium": "5.5", "low": "3.0", "info": "0.0"}.get(sev, "5.0")
