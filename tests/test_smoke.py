"""Smoke tests for REENTRYX. No network access."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from reentryx import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    analyze_source,
    analyze_file,
    findings_to_json,
    findings_to_sarif,
)
from reentryx.cli import main  # noqa: E402

DEMO = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "demos", "01-basic", "Vault.sol")
)


def test_metadata():
    assert TOOL_NAME == "reentryx"
    assert isinstance(TOOL_VERSION, str) and TOOL_VERSION


def test_demo_classic_reentrancy_flagged():
    findings = analyze_file(DEMO)
    rx001 = [f for f in findings if f.rule_id == "RX001"]
    assert rx001, "expected at least one classic reentrancy finding"
    # the vulnerable function is 'withdraw' and the var is 'balances'
    assert any(f.function == "withdraw" for f in rx001)
    assert any("balances" in f.message for f in rx001)


def test_safe_withdraw_not_flagged_rx001():
    findings = analyze_file(DEMO)
    assert not any(
        f.rule_id == "RX001" and f.function == "safeWithdraw" for f in findings
    ), "safeWithdraw follows checks-effects-interactions and must not be flagged"


def test_read_only_reentrancy_flagged():
    findings = analyze_file(DEMO)
    rx002 = [f for f in findings if f.rule_id == "RX002"]
    assert rx002, "expected a read-only reentrancy finding"
    assert any(f.function == "getTotalShares" for f in rx002)
    assert any("totalShares" in f.message for f in rx002)


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
    findings = analyze_source(clean, filename="Clean.sol")
    assert not any(f.rule_id == "RX001" for f in findings)


def test_nonreentrant_guard_suppresses_rx001():
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
    findings = analyze_source(guarded, filename="Guarded.sol")
    assert not any(f.rule_id == "RX001" for f in findings)


def test_json_output_is_valid():
    findings = analyze_file(DEMO)
    parsed = json.loads(findings_to_json(findings))
    assert isinstance(parsed, list)
    assert all("rule_id" in item and "line" in item for item in parsed)


def test_sarif_output_is_valid():
    findings = analyze_file(DEMO)
    doc = json.loads(findings_to_sarif(findings, TOOL_NAME, TOOL_VERSION))
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == TOOL_NAME
    assert len(doc["runs"][0]["results"]) == len(findings)


def test_cli_exit_nonzero_on_findings(capsys):
    rc = main(["scan", DEMO, "--format", "json"])
    assert rc == 1
    out = capsys.readouterr().out
    data = json.loads(out)
    assert any(item["rule_id"] == "RX001" for item in data)


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
    assert "No reentrancy issues found." in capsys.readouterr().out


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert TOOL_VERSION in capsys.readouterr().out
