"""TACACS+ device-administration tools (ERS + OpenAPI).

Command sets and shell (TACACS) profiles are ERS resources
(`/ers/config/tacacscommandsets`, `/ers/config/tacacsprofile`); the device-admin
policy sets + authZ rules that reference them live on the OpenAPI Policy surface
(see policy.py, `kind='device-admin'`). Onboard a NAD with a TACACS shared secret
via `ise_create_network_device(..., tacacs_shared_secret=...)`.

Note: configuring these objects works regardless of node services, but ISE only
*answers* TACACS+ (TCP 49) once the **Device Admin service** is enabled on the node
(see `ise_enable_device_admin`).
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from ..client import ISEClient
from ..spec import SpecCache
from . import dumps

_CS = "/ers/config/tacacscommandsets"
_TP = "/ers/config/tacacsprofile"
_TES = "/ers/config/tacacsexternalservers"
_DA = "/api/v1/policy/device-admin"


def register(mcp: FastMCP, client: ISEClient, spec: SpecCache) -> None:
    # ---- TACACS command sets (ERS) ----
    @mcp.tool()
    async def ise_list_tacacs_command_sets() -> str:
        """List TACACS+ command sets (ERS)."""
        return dumps(await client.ers_list_all(_CS))

    @mcp.tool()
    async def ise_get_tacacs_command_set(cs_id: str) -> str:
        """Get one TACACS+ command set by id (ERS)."""
        return dumps(await client.ers("GET", f"{_CS}/{cs_id}"))

    @mcp.tool()
    async def ise_create_tacacs_command_set(
        name: str,
        commands: list[dict] | None = None,
        permit_unmatched: bool = False,
        description: str = "",
    ) -> str:
        """Create a TACACS+ command set (ERS). Returns the new id.

        Args:
            name: command-set name.
            commands: list of command grants, each
                {"grant": "PERMIT"|"DENY"|"DENY_ALWAYS", "command": "show",
                 "arguments": "*"}. Omit for an empty set.
            permit_unmatched: if True, commands not listed are permitted (a
                permit-all set); if False, unmatched commands are denied.
            description: optional.
        """
        body = {"TacacsCommandSets": {
            "name": name, "description": description,
            "permitUnmatched": permit_unmatched,
            "commands": {"commandList": commands or []}}}
        return dumps(await client.ers("POST", _CS, json_body=body))

    @mcp.tool()
    async def ise_delete_tacacs_command_set(cs_id: str) -> str:
        """Delete a TACACS+ command set by id (ERS)."""
        return dumps(await client.ers("DELETE", f"{_CS}/{cs_id}"))

    # ---- TACACS (shell) profiles (ERS) ----
    @mcp.tool()
    async def ise_list_tacacs_profiles() -> str:
        """List TACACS+ (shell) profiles (ERS)."""
        return dumps(await client.ers_list_all(_TP))

    @mcp.tool()
    async def ise_get_tacacs_profile(profile_id: str) -> str:
        """Get one TACACS+ profile by id (ERS)."""
        return dumps(await client.ers("GET", f"{_TP}/{profile_id}"))

    @mcp.tool()
    async def ise_create_tacacs_profile(
        name: str,
        privilege: int | None = 15,
        description: str = "",
        attributes: list[dict] | None = None,
    ) -> str:
        """Create a TACACS+ shell profile (ERS). Returns the new id.

        By default sets the shell `priv-lvl` mandatory attribute (the privilege
        level the NAD grants on exec authorization). Pass `attributes` for extra
        custom session attributes.

        Note: ISE TACACS profile names allow only alphanumeric, underscore, and
        space - no hyphens (unlike command sets).

        Args:
            name: profile name (alphanumeric / underscore / space only).
            privilege: shell privilege level 0-15 (default 15); set None to omit.
            description: optional.
            attributes: list of extra session attributes, each
                {"type": "MANDATORY"|"OPTIONAL", "name": "...", "value": "..."};
                appended after the priv-lvl attribute.
        """
        attr_list: list = []
        if privilege is not None:
            attr_list.append({"type": "MANDATORY", "name": "priv-lvl",
                              "value": str(privilege)})
        if attributes:
            attr_list.extend(attributes)
        body = {"TacacsProfile": {
            "name": name, "description": description,
            "sessionAttributes": {"sessionAttributeList": attr_list}}}
        return dumps(await client.ers("POST", _TP, json_body=body))

    @mcp.tool()
    async def ise_delete_tacacs_profile(profile_id: str) -> str:
        """Delete a TACACS+ profile by id (ERS)."""
        return dumps(await client.ers("DELETE", f"{_TP}/{profile_id}"))

    # ---- reads ----
    @mcp.tool()
    async def ise_list_tacacs_external_servers() -> str:
        """List TACACS+ external servers (proxy targets) (ERS, read-only here)."""
        return dumps(await client.ers_list_all(_TES))

    @mcp.tool()
    async def ise_deviceadmin_command_sets() -> str:
        """List device-admin command sets via the OpenAPI Policy surface (read).

        A cross-check of `ise_list_tacacs_command_sets` (ERS) from the policy side.
        """
        return dumps(await client.openapi("GET", f"{_DA}/command-sets"))
