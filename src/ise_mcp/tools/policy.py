"""Policy tools (OpenAPI): network-access + device-admin policy sets."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from ..client import ISEClient
from ..spec import SpecCache
from . import dumps

_NA = "/api/v1/policy/network-access"
_DA = "/api/v1/policy/device-admin"


def register(mcp: FastMCP, client: ISEClient, spec: SpecCache) -> None:
    @mcp.tool()
    async def ise_list_policy_sets(kind: str = "network-access") -> str:
        """List policy sets.

        Args:
            kind: 'network-access' (RADIUS, default) or 'device-admin' (TACACS+).
        """
        base = _DA if kind == "device-admin" else _NA
        return dumps(await client.openapi("GET", f"{base}/policy-set"))

    @mcp.tool()
    async def ise_get_policy_set(policy_id: str, kind: str = "network-access") -> str:
        """Get one policy set by id (kind: 'network-access' | 'device-admin')."""
        base = _DA if kind == "device-admin" else _NA
        return dumps(await client.openapi("GET", f"{base}/policy-set/{policy_id}"))

    @mcp.tool()
    async def ise_get_authentication_rules(policy_id: str,
                                           kind: str = "network-access") -> str:
        """List the authentication rules under a policy set."""
        base = _DA if kind == "device-admin" else _NA
        return dumps(await client.openapi(
            "GET", f"{base}/policy-set/{policy_id}/authentication"))

    @mcp.tool()
    async def ise_get_authorization_rules(policy_id: str,
                                          kind: str = "network-access") -> str:
        """List the authorization rules under a policy set."""
        base = _DA if kind == "device-admin" else _NA
        return dumps(await client.openapi(
            "GET", f"{base}/policy-set/{policy_id}/authorization"))

    @mcp.tool()
    async def ise_list_authorization_profiles() -> str:
        """List authorization profiles (network-access)."""
        return dumps(await client.openapi(
            "GET", f"{_NA}/authorization-profiles"))

    @mcp.tool()
    async def ise_list_conditions() -> str:
        """List reusable policy conditions (network-access)."""
        return dumps(await client.openapi("GET", f"{_NA}/condition"))
