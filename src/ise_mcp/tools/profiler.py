"""Endpoint profiling policy tools (ERS /ers/config/profilerprofile).

Works on ISE 3.4 and 3.5. Most profiler profiles are system-defined; custom ones
carry rules, so create/update go through the raw body tool."""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from ..client import ISEClient
from ..spec import SpecCache
from . import dumps

_PP = "/ers/config/profilerprofile"


def register(mcp: FastMCP, client: ISEClient, spec: SpecCache) -> None:
    @mcp.tool()
    async def ise_list_profiler_profiles(name_contains: str | None = None) -> str:
        """List endpoint profiling policies (ERS) as compact {id, name} entries.

        ISE ships ~600 built-in profiling policies, so this returns a summary;
        use ise_get_profiler_profile for a policy's full detail.

        Args:
            name_contains: optional case-insensitive substring to filter names.
        """
        items = await client.ers_list_all(_PP)
        if name_contains:
            n = name_contains.lower()
            items = [i for i in items if n in (i.get("name") or "").lower()]
        compact = [{"id": i.get("id"), "name": i.get("name")} for i in items]
        return dumps({"count": len(compact), "profiles": compact})

    @mcp.tool()
    async def ise_get_profiler_profile(profile_id: str) -> str:
        """Get one endpoint profiling policy by id (ERS)."""
        return dumps(await client.ers("GET", f"{_PP}/{profile_id}"))

    @mcp.tool()
    async def ise_create_profiler_profile_raw(body: str) -> str:
        """Create an endpoint profiling policy from a full ERS JSON body
        ({'ProfilerProfile': {...}} with parent/rules)."""
        return dumps(await client.ers("POST", _PP, json_body=json.loads(body)))

    @mcp.tool()
    async def ise_delete_profiler_profile(profile_id: str) -> str:
        """Delete an endpoint profiling policy by id (ERS)."""
        return dumps(await client.ers("DELETE", f"{_PP}/{profile_id}"))
