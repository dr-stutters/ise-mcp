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
    async def ise_enable_sponsor_rest_access(group_name: str,
                                             enable: bool = True) -> str:
        """Toggle a sponsor group's REST-API access (otherPermissions.canAccessViaRest).

        This is the exact permission that gates sponsor-authenticated guest-user
        API calls: with it off (the default), a sponsor gets 401 'Sponsor does not
        have permission to access REST Apis'. Run this (as admin) once per sponsor
        group whose members will provision guests over ERS. Returns the updated flag.

        Args:
            group_name: sponsor group name, e.g. 'ALL_ACCOUNTS (default)'.
            enable: True to grant REST access (default), False to revoke.
        """
        groups = await client.ers_list_all("/ers/config/sponsorgroup")
        match = next((g for g in groups if g.get("name") == group_name), None)
        if not match:
            raise ValueError(f"sponsor group '{group_name}' not found - see ise_list_sponsor_groups")
        current = (await client.ers(
            "GET", f"/ers/config/sponsorgroup/{match['id']}")).get("SponsorGroup", {})
        other = dict(current.get("otherPermissions") or {})
        other["canAccessViaRest"] = enable
        await client.ers_update("/ers/config/sponsorgroup", match["id"], "SponsorGroup",
                                {"otherPermissions": other})
        return dumps({"sponsorGroup": group_name, "canAccessViaRest": enable})

    @mcp.tool()
    async def ise_list_guest_users() -> str:
        """List guest users (ERS). Needs a SPONSOR account - a plain admin gets 401."""
        return dumps(await client.ers_list_all(_GUEST))

    @mcp.tool()
    async def ise_create_guest_user_raw(body: str) -> str:
        """Create a guest user from a full ERS JSON body ({'GuestUser': {...}}).

        Needs a **sponsor** account (a plain admin gets 401), and the sponsor's
        group must have REST access (`ise_enable_sponsor_rest_access`). The admin-
        authed MCP server can't send sponsor creds, so this is driven with a
        sponsor-cred client. Body needs `guestType`, `portalId`, `guestInfo`
        (userName; omit `password` to auto-generate per the portal policy) and
        `guestAccessInfo` (`fromDate`/`toDate` are mandatory).
        """
        return dumps(await client.ers("POST", _GUEST, json_body=json.loads(body)))

    @mcp.tool()
    async def ise_delete_guest_user(guest_user_id: str) -> str:
        """Delete a guest user by id (ERS; needs a sponsor account)."""
        return dumps(await client.ers("DELETE", f"{_GUEST}/{guest_user_id}"))
