"""Smoke tests for REENTRYX. No network access."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from reentryx import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    analyze,
    analyze_file,
    render_json,
    render_sarif,
)
from reentryx.cli import main  # noqa: E402

DEMO = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "demos", "01-basic", "Vault.sol")
)


def test_metadata():
    assert TOOL_NAME == "reentryx"
    assert isinstance(TOOL_VERSION, str) and TOOL_VERSION


def test_demo_classic_reentrancy_flagged():
    report = analyze_file(DEMO)
    findings = report.findings
    rex_reen = [f for f in findings if f.rule_id == "REX-REEN"]
    assert rex_reen, "expected at least one classic reentrancy finding"
    # the vulnerable function is 'withdraw' and the var is 'balances'
    assert any(f.function == "withdraw" for f in rex_reen)
    assert any("balances" in f.detail for f in rex_reen)


def test_safe_withdraw_not_flagged_rex_reen():
    report = analyze_file(DEMO)
    findings = report.findings
    assert not any(
        f.rule_id == "REX-REEN" and f.function == "safeWithdraw" for f in findings
    ), "safeWithdraw follows checks-effects-interactions and must not be flagged"


def test_read_only_reentrancy_flagged():
    report = analyze_file(DEMO)
    findings = report.findings
    rex_rore = [f for f in findings if f.rule_id == "REX-RORE"]
    assert rex_rore, "expected a read-only reentrancy finding"
    assert any(f.function == "getTotalShares" for f in rex_rore)
    assert any("totalShares" in f.detail for f in rex_rore)


def test_clean_contract_no_findings():
    clean = """
    pragma solidity ^0.8.20;
    contract Clean {
        mapping(address => uint256) public balances;
        function withdraw(uint256 amount) external {
            balances[msg.sender] -= amount;
            (bool ok, ) = msg.sender.call{value: amount}("");
            require(ok);
        }
    }
    """
    report = analyze(clean, source_name="Clean.sol")
    assert not any(f.rule_id == "REX-REEN" for f in report.findings)


def test_nonreentrant_guard_suppresses_rex_reen():
    guarded = """
    pragma solidity ^0.8.20;
    contract Guarded {
        mapping(address => uint256) public balances;
        function withdraw(uint256 amount) external nonReentrant {
            (bool ok, ) = msg.sender.call{value: amount}("");
            require(ok);
            balances[msg.sender] -= amount;
        }
    }
    """
    report = analyze(guarded, source_name="Guarded.sol")
    assert not any(f.rule_id == "REX-REEN" for f in report.findings)


def test_json_output_is_valid():
    report = analyze_file(DEMO)
    parsed = json.loads(render_json(report))
    assert isinstance(parsed, dict)
    assert "findings" in parsed
    assert isinstance(parsed["findings"], list)
    assert all("rule_id" in item and "line" in item for item in parsed["findings"])


def test_sarif_output_is_valid():
    report = analyze_file(DEMO)
    doc = json.loads(render_sarif(report))
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == TOOL_NAME
    assert len(doc["runs"][0]["results"]) == len(report.findings)


def test_cli_exit_nonzero_on_findings(capsys):
    rc = main(["scan", DEMO, "--format", "json"])
    assert rc == 1
    out = capsys.readouterr().out
    data = json.loads(out)
    assert isinstance(data, dict)
    assert any(item["rule_id"] == "REX-REEN" for item in data["findings"])


def test_cli_exit_zero_on_clean(tmp_path, capsys):
    p = tmp_path / "Clean.sol"
    p.write_text(
        "pragma solidity ^0.8.20;\n"
        "contract C {\n"
        "  uint256 public x;\n"
        "  function f() external { x = 1; }\n"
        "}\n"
    )
    rc = main(["scan", str(p), "--format", "table"])
    assert rc == 0
    assert "No findings. Clean." in capsys.readouterr().out


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert TOOL_VERSION in capsys.readouterr().out
