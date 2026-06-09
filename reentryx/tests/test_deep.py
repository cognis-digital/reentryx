"""Deep tests for reentryx: assert every detector class actually fires."""
import json
import os
import sys

sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")))

from reentryx import (  # noqa: E402
    analyze,
    render_json,
    render_sarif,
    render_table,
    RULES,
    TOOL_NAME,
    TOOL_VERSION,
)
from reentryx.cli import main  # noqa: E402

DEMO = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "demos", "02-deep"))
VULN = os.path.join(DEMO, "VulnerableVault.sol")
SAFE = os.path.join(DEMO, "SafeVault.sol")


def _rule_ids(rep):
    return {f.rule_id for f in rep.findings}


def test_version_exported():
    assert TOOL_NAME == "reentryx"
    assert TOOL_VERSION.count(".") == 2


def test_vulnerable_contract_triggers_all_classes():
    with open(VULN, encoding="utf-8") as fh:
        rep = analyze(fh.read(), VULN)
    ids = _rule_ids(rep)
    for expected in (
        "REX-REEN",    # state write after call
        "REX-XFRE",    # cross-function reentrancy
        "REX-RORE",    # read-only reentrancy
        "REX-UCALL",   # unchecked low-level call
        "REX-TXORG",   # tx.origin auth
        "REX-DELEG",   # delegatecall
    ):
        assert expected in ids, f"{expected} not detected; got {sorted(ids)}"
    assert rep.has_failures
    assert rep.contracts >= 1
    assert rep.functions >= 5


def test_classic_reentrancy_points_at_withdraw():
    with open(VULN, encoding="utf-8") as fh:
        rep = analyze(fh.read(), VULN)
    reen = [f for f in rep.findings if f.rule_id == "REX-REEN"]
    assert any(f.function == "withdraw" for f in reen)
    f = reen[0]
    assert f.line > 0
    assert f.severity == "high"


def test_readonly_reentrancy_is_on_view_getter():
    with open(VULN, encoding="utf-8") as fh:
        rep = analyze(fh.read(), VULN)
    rore = [f for f in rep.findings if f.rule_id == "REX-RORE"]
    assert rore, "expected a read-only reentrancy finding"
    assert any(f.function == "shareValue" for f in rore)


def test_txorigin_and_delegatecall_high_severity():
    with open(VULN, encoding="utf-8") as fh:
        rep = analyze(fh.read(), VULN)
    for rid in ("REX-TXORG", "REX-DELEG"):
        hits = [f for f in rep.findings if f.rule_id == rid]
        assert hits
        assert all(h.severity == "high" for h in hits)
    deleg = [f for f in rep.findings if f.rule_id == "REX-DELEG"]
    assert any(f.function == "execute" for f in deleg)


def test_safe_contract_has_no_high_or_medium():
    with open(SAFE, encoding="utf-8") as fh:
        rep = analyze(fh.read(), SAFE)
    bad = [f for f in rep.findings if f.severity in ("high", "medium")]
    assert not bad, f"SafeVault should be clean; got {[(f.rule_id, f.function) for f in bad]}"
    assert not rep.has_failures


def test_only_filter_restricts_rules():
    with open(VULN, encoding="utf-8") as fh:
        src = fh.read()
    rep = analyze(src, VULN, only=["REX-RORE"])
    assert _rule_ids(rep) <= {"REX-RORE"}
    assert "REX-RORE" in _rule_ids(rep)


def test_json_output_is_valid_and_structured():
    with open(VULN, encoding="utf-8") as fh:
        rep = analyze(fh.read(), VULN)
    doc = json.loads(render_json(rep))
    assert doc["tool"] == "reentryx"
    assert doc["summary"]["total"] == len(rep.findings)
    assert doc["summary"]["high"] >= 1
    assert isinstance(doc["findings"], list)
    assert doc["findings"][0]["rule_id"]


def test_sarif_output_is_valid_210():
    with open(VULN, encoding="utf-8") as fh:
        rep = analyze(fh.read(), VULN)
    doc = json.loads(render_sarif(rep))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "reentryx"
    described = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert set(RULES) <= described
    for res in run["results"]:
        assert res["ruleId"] in RULES
        assert res["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1


def test_table_render_runs():
    with open(VULN, encoding="utf-8") as fh:
        rep = analyze(fh.read(), VULN)
    txt = render_table(rep)
    assert "reentryx" in txt
    assert "REX-" in txt


def test_comment_and_string_stripping_avoids_false_positives():
    src = '''
    pragma solidity ^0.8.0;
    contract C {
        uint256 x;
        function f(address to) external {
            // tx.origin == owner   <- in a comment, must NOT flag
            string memory s = "to.delegatecall(data)";  // string, must NOT flag
            x = 1;
        }
    }
    '''
    rep = analyze(src, "inline.sol")
    ids = _rule_ids(rep)
    assert "REX-TXORG" not in ids
    assert "REX-DELEG" not in ids


def test_cli_scan_exit_codes():
    rc = main(["scan", VULN, "--format", "json"])
    assert rc == 1
    rc = main(["scan", SAFE])
    assert rc == 0
    rc = main(["scan", VULN, "--exit-zero"])
    assert rc == 0


def test_cli_rules_command(capsys):
    rc = main(["rules"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "REX-REEN" in out
    assert "REX-DELEG" in out


def test_txorigin_detected_inside_modifier():
    # Regression: tx.origin auth lives in a `modifier`, not a `function`.
    # The engine must model modifier bodies (Slither does) or it misses the
    # single most common phishable-auth pattern.
    src = '''
    pragma solidity ^0.8.0;
    contract C {
        address owner;
        modifier onlyOwner() {
            require(tx.origin == owner, "no");
            _;
        }
        function f() external onlyOwner {}
    }
    '''
    rep = analyze(src, "mod.sol")
    txorg = [f for f in rep.findings if f.rule_id == "REX-TXORG"]
    assert txorg, "tx.origin in a modifier must be detected"
    assert txorg[0].function == "onlyOwner"
    # Modifiers must not inflate the public function count.
    assert rep.summary()["functions"] == 1


def test_unchecked_call_inside_modifier_is_flagged():
    src = '''
    pragma solidity ^0.8.0;
    contract C {
        modifier ping(address probe) {
            probe.call("");
            _;
        }
        function f(address a) external ping(a) {}
    }
    '''
    rep = analyze(src, "mod2.sol")
    assert "REX-UCALL" in {f.rule_id for f in rep.findings}


def test_modifier_guard_recognized_as_reentrancy_protection():
    # A custom nonReentrant modifier on a withdraw must suppress REX-REEN.
    with open(SAFE, encoding="utf-8") as fh:
        rep = analyze(fh.read(), SAFE)
    assert "REX-REEN" not in {f.rule_id for f in rep.findings}


def test_cli_rules_json(capsys):
    rc = main(["rules", "--format", "json"])
    assert rc == 0
    out = capsys.readouterr().out
    doc = json.loads(out)
    assert "REX-TXORG" in doc
    assert doc["REX-DELEG"]["severity"] == "high"


def test_cli_sarif_to_file(tmp_path):
    out = tmp_path / "out.sarif"
    rc = main(["scan", VULN, "--format", "sarif", "-o", str(out)])
    assert rc == 1
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))
