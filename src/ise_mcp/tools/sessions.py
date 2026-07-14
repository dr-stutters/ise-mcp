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
    async def ise_session_by_username(username: str) -> str:
        """Get the current session for a username (MnT).

        Returns a clear "no active session" note if the user has no live session.
        """
        return await _session_lookup(f"/Session/UserName/{username}", username)

    @mcp.tool()
    async def ise_session_counts() -> str:
        """Session count summary: active, posture, and profiler counts (MnT)."""
        out = {}
        for key, path in (("active", "/Session/ActiveCount"),
                          ("posture", "/Session/PostureCount"),
                          ("profiler", "/Session/ProfilerCount")):
            data = await client.mnt(path)
            out[key] = (data or {}).get("count") if isinstance(data, dict) else data
        return dumps(out)

    @mcp.tool()
    async def ise_auth_status_by_mac(mac: str, seconds: int = 86400,
                                     records: int = 100, filter: str = "All") -> str:
        """Recent authentication attempts for an endpoint MAC (MnT AuthStatus).

        The day-2 troubleshooting view: shows each auth attempt and its result
        (pass/fail + failure reason) over a time window - works even when the
        endpoint has no *active* session.

        Args:
            mac: endpoint MAC, e.g. 'AA:BB:CC:DD:EE:FF'.
            seconds: how far back to look (default 86400 = 24h).
            records: max records to return (default 100).
            filter: 'All', 'Success', or 'Failure'.
        """
        return dumps(await client.mnt(
            f"/AuthStatus/MACAddress/{mac}/{seconds}/{records}/{filter}"))

    @mcp.tool()
    async def ise_failure_reasons() -> str:
        """Get the MnT failure-reasons dictionary (auth failure codes)."""
        return dumps(await client.mnt("/FailureReasons"))

    @mcp.tool()
    async def ise_recent_authentications() -> str:
        """MnT recent-authentications report (/Session/AuthList) - the latest RADIUS
        authentication events across the deployment (user/MAC, NAS, result), not just
        currently-active sessions. Use ise_auth_status_by_mac for one endpoint's
        pass/fail history."""
        return dumps(await client.mnt("/Session/AuthList/null/null"))
