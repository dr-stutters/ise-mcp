"""TrustSec tools (OpenAPI): SGTs, SGACLs, egress matrix.

SGTs (security groups) live under the Policy group's network-access path;
SGACLs and the egress matrix under the TrustSec group. Both are OpenAPI.
"""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from ..client import ISEClient
from ..spec import SpecCache
from . import dumps

_SGT = "/api/v1/policy/network-access/security-groups"


def register(mcp: FastMCP, client: ISEClient, spec: SpecCache) -> None:
    @mcp.tool()
    async def ise_list_sgts() -> str:
        """List Security Group Tags (SGTs)."""
        return dumps(await client.openapi("GET", _SGT))

    @mcp.tool()
    async def ise_get_sgt(sgt_id: str) -> str:
        """Get one SGT by id."""
        return dumps(await client.openapi("GET", f"{_SGT}/{sgt_id}"))

    @mcp.tool()
    async def ise_create_sgt(name: str, value: int, description: str = "") -> str:
        """Create an SGT.

        Args:
            name: SGT name (e.g. 'Employees').
            value: the SGT numeric value/tag (e.g. 10); -1 lets ISE auto-assign.
            description: optional.
        """
        body = {"name": name, "value": value, "description": description}
        return dumps(await client.openapi("POST", _SGT, json_body=body))

    @mcp.tool()
    async def ise_delete_sgt(sgt_id: str) -> str:
        """Delete an SGT by id."""
        return dumps(await client.openapi("DELETE", f"{_SGT}/{sgt_id}"))

    @mcp.tool()
    async def ise_list_sgacls() -> str:
        """List SGACLs (TrustSec Security Group ACLs)."""
        return dumps(await client.openapi("GET", "/api/v1/trustsec/sgacl"))

    @mcp.tool()
    async def ise_create_sgacl(body: str) -> str:
        """Create an SGACL from a JSON body (see ise_get_definition for the schema)."""
        return dumps(await client.openapi(
            "POST", "/api/v1/trustsec/sgacl", json_body=json.loads(body)))

    @mcp.tool()
    async def ise_list_egress_matrix() -> str:
        """List the TrustSec egress matrix cells (source SGT x dest SGT -> SGACLs)."""
        return dumps(await client.openapi(
            "GET", "/api/v1/trustsec/egressmatrixcell"))
