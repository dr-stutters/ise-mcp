"""Session / monitoring tools (MnT, read-only, XML)."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from ..client import ISEClient, ISEAPIError
from ..spec import SpecCache
from . import dumps


def register(mcp: FastMCP, client: ISEClient, spec: SpecCache) -> None:
    async def _session_lookup(path: str, ident: str) -> str:
        # MnT returns HTTP 500 (cpm-code 34110) when no active session matches
        # the identifier - report that cleanly instead of surfacing a raw error.
        try:
            return dumps(await client.mnt(path))
        except ISEAPIError as e:
            if e.status_code == 500:
                return dumps({"activeSession": None, "identifier": ident,
                              "note": "No active session found for this identifier "
                              "(MnT returned no match). Check ise_active_session_count."})
            raise

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
        """Get the current session for an endpoint MAC (MnT), e.g. 'AA:BB:CC:DD:EE:FF'.

        Returns a clear "no active session" note if the MAC has no live session.
        """
        return await _session_lookup(f"/Session/MACAddress/{mac}", mac)

    @mcp.tool()
    async def ise_session_by_ip(ip: str) -> str:
        """Get the current session for an endpoint IP (MnT).

        Returns a clear "no active session" note if the IP has no live session.
        """
        return await _session_lookup(f"/Session/EndPointIPAddress/{ip}", ip)

    @mcp.tool()
    async def ise_failure_reasons() -> str:
        """Get the MnT failure-reasons dictionary (auth failure codes)."""
        return dumps(await client.mnt("/FailureReasons"))
