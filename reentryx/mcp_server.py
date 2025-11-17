"""REENTRYX MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from reentryx.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-reentryx[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-reentryx[mcp]'")
        return 1
    app = FastMCP("reentryx")

    @app.tool()
    def reentryx_scan(target: str) -> str:
        """Static + symbolic detector that flags reentrancy, cross-function, and read-only reentrancy paths in Solidity/Vyper with CI-gating SARIF output.. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
