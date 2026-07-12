"""Session / monitoring tools (MnT, read-only, XML)."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from ..client import ISEClient
from ..spec import SpecCache
from . import dumps


def register(mcp: FastMCP, client: ISEClient, spec: SpecCache) -> None:
    @mcp.tool()
    async def ise_active_session_count() -> str:
        """Count of currently active RADIUS/authentication sessions (MnT)."""
        return dumps(await client.mnt("/Session/ActiveCount"))

    @mcp.tool()
    async def ise_active_sessions() -> str:
        """List active sessions (MnT /Session/ActiveList)."""
        return dumps(await client.mnt("/Session/ActiveList"))

    @mcp.tool()
    async def ise_session_by_mac(mac: str) -> str:
        """Get the current session for an endpoint MAC (MnT), e.g. 'AA:BB:CC:DD:EE:FF'."""
        return dumps(await client.mnt(f"/Session/MACAddress/{mac}"))

    @mcp.tool()
    async def ise_session_by_ip(ip: str) -> str:
        """Get the current session for an endpoint IP (MnT)."""
        return dumps(await client.mnt(f"/Session/EndPointIPAddress/{ip}"))

    @mcp.tool()
    async def ise_failure_reasons() -> str:
        """Get the MnT failure-reasons dictionary (auth failure codes)."""
        return dumps(await client.mnt("/FailureReasons"))
