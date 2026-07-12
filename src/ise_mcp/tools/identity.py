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
    async def ise_list_internal_users(filter: str | None = None) -> str:
        """List internal users (ERS, follows paging).

        Args:
            filter: optional ERS filter, e.g. 'name.CONTAINS.svc' or
                'enabled.EQ.true'.
        """
        params = {"filter": filter} if filter else None
        return dumps(await client.ers_list_all(_USER, params=params))

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
            identity_groups: optional identity group name or id to place the user
                in. A name is resolved to its id automatically (ERS stores the id).
            email: optional.
        """
        user: dict = {"name": name, "password": password, "email": email,
                      "enabled": True, "changePassword": False}
        if identity_groups:
            # ERS wants the group id (CSV). If a name was given, resolve it.
            gid = identity_groups
            if "-" not in identity_groups:  # ids are GUIDs; a name has no dashes
                groups = await client.ers_list_all("/ers/config/identitygroup")
                match = next((g for g in groups if g.get("name") == identity_groups), None)
                if match:
                    gid = match["id"]
            user["identityGroups"] = gid
        return dumps(await client.ers("POST", _USER,
                                      json_body={"InternalUser": user}))

    @mcp.tool()
    async def ise_create_internal_user_raw(body: str) -> str:
        """Create an internal user from a full ERS JSON body ({'InternalUser': {...}})."""
        return dumps(await client.ers("POST", _USER, json_body=json.loads(body)))

    @mcp.tool()
    async def ise_update_internal_user(user_id: str, password: str | None = None,
                                       enabled: bool | None = None,
                                       email: str | None = None,
                                       description: str | None = None) -> str:
        """Update an internal user (ERS; only given fields change).

        The GET returns a masked password ('*******'); echoing it back on the PUT
        is rejected, so it is stripped and only re-set when a new `password` is
        supplied.
        """
        current = await client.ers("GET", f"{_USER}/{user_id}")
        obj = dict((current or {}).get("InternalUser", {}))
        obj.pop("password", None)  # never echo the masked password back
        for key, val in (("password", password), ("enabled", enabled),
                         ("email", email), ("description", description)):
            if val is not None:
                obj[key] = val
        return dumps(await client.ers("PUT", f"{_USER}/{user_id}",
                                      json_body={"InternalUser": obj}))

    @mcp.tool()
    async def ise_delete_internal_user(user_id: str) -> str:
        """Delete an internal user by id (ERS)."""
        return dumps(await client.ers("DELETE", f"{_USER}/{user_id}"))

    @mcp.tool()
    async def ise_list_identity_groups() -> str:
        """List user identity groups (ERS)."""
        return dumps(await client.ers_list_all("/ers/config/identitygroup"))

    @mcp.tool()
    async def ise_create_identity_group(
        name: str, description: str = "",
        parent: str = "NAC Group:NAC:IdentityGroups:User Identity Groups",
    ) -> str:
        """Create a user identity group (ERS). Returns the new group's id."""
        body = {"IdentityGroup": {"name": name, "description": description,
                                  "parent": parent}}
        return dumps(await client.ers("POST", "/ers/config/identitygroup",
                                      json_body=body))

    @mcp.tool()
    async def ise_delete_identity_group(group_id: str) -> str:
        """Delete a user identity group by id (ERS)."""
        return dumps(await client.ers("DELETE", f"/ers/config/identitygroup/{group_id}"))

    @mcp.tool()
    async def ise_list_endpoint_groups() -> str:
        """List endpoint identity groups (ERS)."""
        return dumps(await client.ers_list_all("/ers/config/endpointgroup"))

    @mcp.tool()
    async def ise_create_endpoint_group(name: str, description: str = "") -> str:
        """Create an endpoint identity group (ERS). Returns the new group's id."""
        body = {"EndPointGroup": {"name": name, "description": description,
                                  "systemDefined": False}}
        return dumps(await client.ers("POST", "/ers/config/endpointgroup",
                                      json_body=body))

    @mcp.tool()
    async def ise_delete_endpoint_group(group_id: str) -> str:
        """Delete an endpoint identity group by id (ERS)."""
        return dumps(await client.ers("DELETE", f"/ers/config/endpointgroup/{group_id}"))

    @mcp.tool()
    async def ise_list_active_directory() -> str:
        """List Active Directory join points (ERS external identity source)."""
        return dumps(await client.ers_list_all("/ers/config/activedirectory"))

    @mcp.tool()
    async def ise_get_active_directory(ad_id: str) -> str:
        """Get one Active Directory join point by id, incl. domain/group detail (ERS)."""
        return dumps(await client.ers("GET", f"/ers/config/activedirectory/{ad_id}"))

    @mcp.tool()
    async def ise_list_external_radius_servers() -> str:
        """List external RADIUS servers (ERS; used for RADIUS proxy/token)."""
        return dumps(await client.ers_list_all("/ers/config/externalradiusserver"))
