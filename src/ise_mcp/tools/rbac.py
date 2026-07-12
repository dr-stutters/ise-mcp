"""RBAC / admin-account tools.

Admin users are readable via ERS (/ers/config/adminuser) on 3.4 and 3.5.
Creating/deleting admin users and listing admin groups use the OpenAPI Rbac
Catalog group, which exists on ISE 3.5+ (absent on 3.4 - those tools 404 there).
Useful for creating an ERS-Admin / Super-Admin account programmatically."""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from ..client import ISEClient
from ..spec import SpecCache
from . import dumps

_RBAC_USER = "/api/v1/rbac/admin-user"
_RBAC_GROUP = "/api/v1/rbac/admin-group"


def register(mcp: FastMCP, client: ISEClient, spec: SpecCache) -> None:
    @mcp.tool()
    async def ise_list_admin_users() -> str:
        """List admin users (ERS - works on 3.4 and 3.5)."""
        return dumps(await client.ers_list_all("/ers/config/adminuser"))

    @mcp.tool()
    async def ise_list_admin_groups() -> str:
        """List RBAC admin groups (OpenAPI; ISE 3.5+)."""
        return dumps(await client.openapi("GET", _RBAC_GROUP))

    @mcp.tool()
    async def ise_create_admin_user(name: str, password: str,
                                    rbac_groups: list[str],
                                    description: str = "") -> str:
        """Create an admin user and assign RBAC group(s) (OpenAPI; ISE 3.5+).

        Use this to create an ERS-Admin account. `rbac_groups` may be group names
        (e.g. 'ERS Admin', 'Super Admin') or ids - names are resolved.

        Note: on some 3.5 builds this endpoint returns a generic HTTP 500
        ("Unexpected Error in admin user creation") - best-effort. The read tools
        (ise_list_admin_users / ise_list_admin_groups) are the reliable surface;
        use ise_create_admin_user_raw for full body control.

        Args:
            name: admin username.
            password: the admin password.
            rbac_groups: list of admin group names or ids to assign.
            description: optional.
        """
        # resolve group names -> ids (admin-group returns {adminGroupList: [...]})
        groups = await client.openapi("GET", _RBAC_GROUP)
        if isinstance(groups, dict):
            glist = groups.get("adminGroupList") or groups.get("response") or []
        else:
            glist = groups
        by_name = {g.get("name"): (g.get("id") or g.get("name")) for g in glist}
        resolved = [by_name.get(g, g) for g in rbac_groups]
        body = {"name": name, "password": password, "description": description,
                "rbacGroups": resolved, "changePasswordOnNextLogin": False,
                "inactiveAccountNeverDisabled": True, "status": True}
        return dumps(await client.openapi("POST", _RBAC_USER, json_body=body))

    @mcp.tool()
    async def ise_create_admin_user_raw(body: str) -> str:
        """Create an admin user from a full JSON body (OpenAPI; ISE 3.5+).

        See ise_get_definition 'OpenApiAdminUser' for fields.
        """
        return dumps(await client.openapi("POST", _RBAC_USER, json_body=json.loads(body)))

    @mcp.tool()
    async def ise_delete_admin_user(name: str) -> str:
        """Delete an admin user by name (OpenAPI; ISE 3.5+)."""
        return dumps(await client.openapi("DELETE", f"{_RBAC_USER}/{name}"))
