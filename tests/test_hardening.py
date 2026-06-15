"""Hardening tests: error/edge paths added during production hardening."""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from reentryx import analyze, analyze_file  # noqa: E402
from reentryx.cli import main  # noqa: E402


# ---------------------------------------------------------------------------
# analyze_file — missing / unreadable paths
# ---------------------------------------------------------------------------


def test_analyze_file_missing_raises_file_not_found():
    with pytest.raises(FileNotFoundError, match="not found"):
        analyze_file("/no/such/path/totally_missing.sol")


def test_cli_scan_missing_path_exits_2(tmp_path, capsys):
    """A non-existent path should exit 2 with a clear error on stderr."""
    missing = str(tmp_path / "ghost.sol")
    # _collect_files does sys.exit(2) for missing paths — catch SystemExit
    with pytest.raises(SystemExit) as exc:
        main(["scan", missing])
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "not found" in err or "error" in err.lower()


# ---------------------------------------------------------------------------
# --only with unknown rule IDs
# ---------------------------------------------------------------------------


def test_cli_scan_unknown_rule_id_exits_2(tmp_path, capsys):
    """--only with a bogus rule ID should exit 2 with a clear error."""
    p = tmp_path / "sample.sol"
    p.write_text(
        "pragma solidity ^0.8.0;\ncontract C { uint256 x; }\n",
        encoding="utf-8",
    )
    rc = main(["scan", str(p), "--only", "REX-BOGUS-XYZ"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "REX-BOGUS-XYZ" in err
    assert "unknown" in err.lower()


def test_cli_scan_valid_only_flag_works(tmp_path):
    """--only with a real rule ID should succeed (exit 0 on a clean file)."""
    p = tmp_path / "clean.sol"
    p.write_text(
        "pragma solidity ^0.8.0;\ncontract C { uint256 x; }\n",
        encoding="utf-8",
    )
    rc = main(["scan", str(p), "--only", "REX-REEN"])
    assert rc == 0


# ---------------------------------------------------------------------------
# Empty source / empty file
# ---------------------------------------------------------------------------


def test_analyze_empty_string_returns_empty_report():
    """analyze() on an empty string must return a valid Report with 0 findings."""
    rep = analyze("", source_name="empty.sol")
    assert rep.findings == []
    assert rep.contracts == 0
    assert rep.functions == 0


def test_cli_scan_empty_file_warns_and_exits_2(tmp_path, capsys):
    """An empty .sol file should emit a warning and exit 2 (no scannable files)."""
    p = tmp_path / "empty.sol"
    p.write_text("", encoding="utf-8")
    rc = main(["scan", str(p)])
    assert rc == 2
    err = capsys.readouterr().err
    assert "empty" in err.lower() or "warning" in err.lower()


# ---------------------------------------------------------------------------
# Output file write error
# ---------------------------------------------------------------------------


def test_cli_scan_bad_output_path_exits_2(tmp_path, capsys):
    """Writing to a non-existent directory must exit 2 with a clear error."""
    p = tmp_path / "sample.sol"
    p.write_text(
        "pragma solidity ^0.8.0;\ncontract C { uint256 x; }\n",
        encoding="utf-8",
    )
    bad_out = str(tmp_path / "no_such_dir" / "out.sarif")
    rc = main(["scan", str(p), "--format", "sarif", "-o", bad_out])
    assert rc == 2
    err = capsys.readouterr().err
    assert "error" in err.lower()


# ---------------------------------------------------------------------------
# No-command / help path is clean (exit 0)
# ---------------------------------------------------------------------------


def test_cli_no_command_exits_0(capsys):
    rc = main([])
    assert rc == 0
