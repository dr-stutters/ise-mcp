"""Identity tools: internal users + identity/endpoint groups.

ERS surface (over port 443 by default; legacy 9060 - see network_devices.py).
Internal users and identity groups have no OpenAPI equivalent in ISE 3.4/3.5.
"""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from ..client import ISEClient
from ..spec import SpecCache
from . import dumps

_USER = "/ers/config/internaluser"


def register(mcp: FastMCP, client: ISEClient, spec: SpecCache) -> None:
    @mcp.tool()
    async def ise_list_internal_users() -> str:
        """List internal users (ERS, follows paging)."""
        return dumps(await client.ers_list_all(_USER))

    @mcp.tool()
    async def ise_get_internal_user(user_id: str) -> str:
        """Get one internal user by id (ERS)."""
        return dumps(await client.ers("GET", f"{_USER}/{user_id}"))

    @mcp.tool()
    async def ise_create_internal_user(
        name: str,
        password: str,
        identity_groups: str | None = None,
        email: str = "",
    ) -> str:
        """Create an internal user (ERS).

        Args:
            name: username.
            password: the user's password.
            identity_groups: optional identity group name/id to place the user in.
            email: optional.
        """
        user: dict = {"name": name, "password": password, "email": email,
                      "enabled": True, "changePassword": False}
        if identity_groups:
            user["identityGroups"] = identity_groups
        return dumps(await client.ers("POST", _USER,
                                      json_body={"InternalUser": user}))

    @mcp.tool()
    async def ise_create_internal_user_raw(body: str) -> str:
        """Create an internal user from a full ERS JSON body ({'InternalUser': {...}})."""
        return dumps(await client.ers("POST", _USER, json_body=json.loads(body)))

    @mcp.tool()
    async def ise_delete_internal_user(user_id: str) -> str:
        """Delete an internal user by id (ERS)."""
        return dumps(await client.ers("DELETE", f"{_USER}/{user_id}"))

    @mcp.tool()
    async def ise_list_identity_groups() -> str:
        """List user identity groups (ERS)."""
        return dumps(await client.ers_list_all("/ers/config/identitygroup"))

    @mcp.tool()
    async def ise_list_endpoint_groups() -> str:
        """List endpoint identity groups (ERS)."""
        return dumps(await client.ers_list_all("/ers/config/endpointgroup"))
