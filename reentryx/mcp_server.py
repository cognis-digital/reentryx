"""REENTRYX MCP server — exposes analyze_file() as an MCP tool."""
from __future__ import annotations
import sys


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-reentryx[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        print(
            "Install the MCP extra: pip install 'cognis-reentryx[mcp]'",
            file=sys.stderr,
        )
        return 1

    from reentryx.core import analyze_file, render_json

    app = FastMCP("reentryx")

    @app.tool()
    def reentryx_scan(target: str) -> str:
        """Scan a Solidity file for reentrancy and high-impact vulnerabilities.

        Returns JSON findings (reentrancy, cross-function, read-only reentrancy,
        unchecked calls, tx.origin, delegatecall).
        """
        if not target or not target.strip():
            return '{"error": "target path must not be empty"}'
        try:
            rep = analyze_file(target)
        except (FileNotFoundError, PermissionError, OSError) as exc:
            return f'{{"error": "{exc}"}}'
        return render_json(rep)

    app.run()
    return 0
