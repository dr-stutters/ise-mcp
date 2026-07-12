"""System tools: version + reachable-surface probe."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from ..client import ISEClient
from ..spec import SpecCache
from . import dumps


def register(mcp: FastMCP, client: ISEClient, spec: SpecCache) -> None:
    @mcp.tool()
    async def ise_version() -> str:
        """Get the ISE software version + node type (via MnT)."""
        return dumps(await client.mnt("/Version"))

    @mcp.tool()
    async def ise_check_surfaces() -> str:
        """Probe which ISE API surfaces are reachable from here (OpenAPI / MnT / ERS).

        Handy first call: ERS (port 9060) is firewalled off in some deployments
        (e.g. dCloud); this reports what actually works so you know which tools
        will function.
        """
        out = {}
        try:
            await client.openapi("GET", "/api/v1/deployment/node")
            out["openapi"] = "reachable"
        except Exception as e:
            out["openapi"] = f"unreachable: {str(e)[:80]}"
        try:
            await client.mnt("/Version")
            out["mnt"] = "reachable"
        except Exception as e:
            out["mnt"] = f"unreachable: {str(e)[:80]}"
        try:
            await client.ers("GET", "/ers/config/networkdevice", params={"size": 1})
            out["ers"] = "reachable"
        except Exception as e:
            out["ers"] = f"unreachable (port 9060 blocked or ERS off): {str(e)[:60]}"
        return dumps(out)
