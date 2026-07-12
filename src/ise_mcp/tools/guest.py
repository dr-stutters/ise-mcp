"""Guest & sponsor tools (ERS). Guest types, sponsor portals and sponsor groups
are readable with an ISE admin account; guest *users* are managed by sponsors, so
those calls need a sponsor account (they return 401 for a plain admin) - they are
provided as best-effort."""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from ..client import ISEClient
from ..spec import SpecCache
from . import dumps

_GUEST = "/ers/config/guestuser"


def register(mcp: FastMCP, client: ISEClient, spec: SpecCache) -> None:
    @mcp.tool()
    async def ise_list_guest_types() -> str:
        """List guest types (ERS)."""
        return dumps(await client.ers_list_all("/ers/config/guesttype"))

    @mcp.tool()
    async def ise_get_guest_type(guest_type_id: str) -> str:
        """Get one guest type by id (ERS)."""
        return dumps(await client.ers("GET", f"/ers/config/guesttype/{guest_type_id}"))

    @mcp.tool()
    async def ise_list_sponsor_portals() -> str:
        """List sponsor portals (ERS)."""
        return dumps(await client.ers_list_all("/ers/config/sponsorportal"))

    @mcp.tool()
    async def ise_list_sponsor_groups() -> str:
        """List sponsor groups (ERS)."""
        return dumps(await client.ers_list_all("/ers/config/sponsorgroup"))

    @mcp.tool()
    async def ise_list_guest_users() -> str:
        """List guest users (ERS). Needs a SPONSOR account - a plain admin gets 401."""
        return dumps(await client.ers_list_all(_GUEST))

    @mcp.tool()
    async def ise_create_guest_user_raw(body: str) -> str:
        """Create a guest user from a full ERS JSON body ({'GuestUser': {...}}).

        Needs a sponsor account with a guest portal context (401 for a plain admin).
        """
        return dumps(await client.ers("POST", _GUEST, json_body=json.loads(body)))

    @mcp.tool()
    async def ise_delete_guest_user(guest_user_id: str) -> str:
        """Delete a guest user by id (ERS; needs a sponsor account)."""
        return dumps(await client.ers("DELETE", f"{_GUEST}/{guest_user_id}"))
