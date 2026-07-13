"""Posture tools (OpenAPI Posture surface, /api/v1/posture/...).

Config-side management of the posture policy chain: conditions (file / application
/ registry / service / generic / ...) -> requirements (bundle conditions +
remediations per OS) -> posture policies (bind requirements to identity groups +
OS + agent type), plus read access to posture settings (general, reassessment,
AUP, update).

Posture *config* is fully API-driven here. Actually running a posture assessment
needs a posture-capable client (Cisco Secure Client / AnyConnect on Windows/macOS);
Linux-only lab endpoints can't complete a live posture flow, so this surface is for
building and inspecting policy, not live-assessment validation.

Create bodies are large and type-specific, so creates are raw-first: pull an
existing object with the list/get tools (or `ise_get_definition`) to see the shape,
then POST the same structure.
"""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from ..client import ISEClient
from ..spec import SpecCache
from . import dumps

_P = "/api/v1/posture"
_SETTINGS = {"general", "reassessment", "update", "acceptableusepolicy",
             "continuousmonitoring"}


def register(mcp: FastMCP, client: ISEClient, spec: SpecCache) -> None:
    # ---- conditions ----
    @mcp.tool()
    async def ise_list_posture_conditions(condition_type: str = "file") -> str:
        """List posture conditions of a type.

        Args:
            condition_type: file | application | service | registry | generic |
                dictionary_simple | dictionary_compound | antimalware | firewall |
                disk_encryption | patch_management | usb (per the ISE posture model).
        """
        return dumps(await client.openapi("GET", f"{_P}/condition/{condition_type}"))

    @mcp.tool()
    async def ise_get_posture_condition(condition_type: str, cond_id: str) -> str:
        """Get one posture condition by id (within its type)."""
        return dumps(await client.openapi("GET", f"{_P}/condition/{condition_type}/{cond_id}"))

    @mcp.tool()
    async def ise_create_posture_condition_raw(condition_type: str, body: str) -> str:
        """Create a posture condition from a full JSON body (see ise_get_posture_condition
        for the shape). Returns the created object.

        Example (Linux file-existence): condition_type='file', body=
        {"name":"...","FileCheckType":"FILE_EXISTENCE","FilePath":"ABSOLUTE_PATH",
         "FilePathSuffix":"/etc/hosts","FileOperator":"EXISTS","osGroupList":["Linux All"]}
        """
        return dumps(await client.openapi("POST", f"{_P}/condition/{condition_type}",
                                          json_body=json.loads(body)))

    @mcp.tool()
    async def ise_delete_posture_condition(condition_type: str, cond_id: str) -> str:
        """Delete a posture condition by id (within its type)."""
        return dumps(await client.openapi(
            "DELETE", f"{_P}/condition/{condition_type}/{cond_id}"))

    # ---- requirements ----
    @mcp.tool()
    async def ise_list_posture_requirements() -> str:
        """List posture requirements (condition + remediation bundles per OS)."""
        return dumps(await client.openapi("GET", f"{_P}/requirement"))

    @mcp.tool()
    async def ise_get_posture_requirement(req_id: str) -> str:
        """Get one posture requirement by id."""
        return dumps(await client.openapi("GET", f"{_P}/requirement/{req_id}"))

    @mcp.tool()
    async def ise_create_posture_requirement_raw(body: str) -> str:
        """Create a posture requirement from a full JSON body (see ise_get_posture_requirement)."""
        return dumps(await client.openapi("POST", f"{_P}/requirement",
                                          json_body=json.loads(body)))

    @mcp.tool()
    async def ise_delete_posture_requirement(req_id: str) -> str:
        """Delete a posture requirement by id."""
        return dumps(await client.openapi("DELETE", f"{_P}/requirement/{req_id}"))

    # ---- policies ----
    @mcp.tool()
    async def ise_list_posture_policies() -> str:
        """List posture policies (requirement -> identity group / OS / agent bindings)."""
        return dumps(await client.openapi("GET", f"{_P}/policy"))

    @mcp.tool()
    async def ise_get_posture_policy(policy_id: str) -> str:
        """Get one posture policy by id."""
        return dumps(await client.openapi("GET", f"{_P}/policy/{policy_id}"))

    @mcp.tool()
    async def ise_create_posture_policy_raw(body: str) -> str:
        """Create a posture policy from a full JSON body (see ise_get_posture_policy)."""
        return dumps(await client.openapi("POST", f"{_P}/policy", json_body=json.loads(body)))

    @mcp.tool()
    async def ise_delete_posture_policy(policy_id: str) -> str:
        """Delete a posture policy by id."""
        return dumps(await client.openapi("DELETE", f"{_P}/policy/{policy_id}"))

    # ---- settings (read) ----
    @mcp.tool()
    async def ise_get_posture_settings(setting: str = "general") -> str:
        """Read posture settings (read-only).

        Args:
            setting: general | reassessment | update | acceptableusepolicy |
                continuousmonitoring.
        """
        if setting not in _SETTINGS:
            raise ValueError(f"setting must be one of {sorted(_SETTINGS)}")
        return dumps(await client.openapi("GET", f"{_P}/setting/{setting}"))
