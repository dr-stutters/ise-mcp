"""TrustSec tools: SGTs, SGACLs, egress matrix.

SGTs, SGACLs and egress-matrix cells are **ERS** resources (writes require ERS
enabled in API Settings). SGT *reads* are also mirrored on the OpenAPI Policy
surface (no ERS needed) and share the same ids, so `ise_list_sgts` uses that;
everything else uses ERS. The OpenAPI `/api/v1/trustsec/...` paths for SGACL and
egress matrix return 404 - those live only under ERS.
"""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from ..client import ISEClient
from ..spec import SpecCache
from . import dumps

_SGT_READ = "/api/v1/policy/network-access/security-groups"  # OpenAPI, read-only
_SGT = "/ers/config/sgt"                       # ERS, full CRUD
_SGACL = "/ers/config/sgacl"                   # ERS
_EMC = "/ers/config/egressmatrixcell"          # ERS


def register(mcp: FastMCP, client: ISEClient, spec: SpecCache) -> None:
    @mcp.tool()
    async def ise_list_sgts() -> str:
        """List Security Group Tags (SGTs). OpenAPI read view - no ERS needed."""
        return dumps(await client.openapi("GET", _SGT_READ))

    @mcp.tool()
    async def ise_get_sgt(sgt_id: str) -> str:
        """Get one SGT by id (ERS)."""
        return dumps(await client.ers("GET", f"{_SGT}/{sgt_id}"))

    @mcp.tool()
    async def ise_create_sgt(name: str, value: int, description: str = "") -> str:
        """Create an SGT (ERS). Returns the new SGT's id.

        Args:
            name: SGT name - alphanumeric and underscore only (no spaces/hyphens).
            value: the numeric SGT value/tag; must be a free value (see
                ise_list_sgts for those in use).
            description: optional.
        """
        body = {"Sgt": {"name": name, "value": value, "description": description}}
        return dumps(await client.ers("POST", _SGT, json_body=body))

    @mcp.tool()
    async def ise_update_sgt(sgt_id: str, name: str | None = None,
                             value: int | None = None,
                             description: str | None = None) -> str:
        """Update an SGT's name/value/description (ERS; only given fields change)."""
        return dumps(await client.ers_update(
            _SGT, sgt_id, "Sgt",
            {"name": name, "value": value, "description": description}))

    @mcp.tool()
    async def ise_delete_sgt(sgt_id: str) -> str:
        """Delete an SGT by id (ERS)."""
        return dumps(await client.ers("DELETE", f"{_SGT}/{sgt_id}"))

    @mcp.tool()
    async def ise_list_sgacls() -> str:
        """List SGACLs (TrustSec Security Group ACLs). ERS."""
        return dumps(await client.ers_list_all(_SGACL))

    @mcp.tool()
    async def ise_get_sgacl(sgacl_id: str) -> str:
        """Get one SGACL by id (ERS)."""
        return dumps(await client.ers("GET", f"{_SGACL}/{sgacl_id}"))

    @mcp.tool()
    async def ise_create_sgacl(body: str) -> str:
        """Create an SGACL from a JSON body ({'Sgacl': {...}}); returns its id. ERS."""
        return dumps(await client.ers("POST", _SGACL, json_body=json.loads(body)))

    @mcp.tool()
    async def ise_update_sgacl_raw(sgacl_id: str, body: str) -> str:
        """Update an SGACL from a full JSON body ({'Sgacl': {...}}). ERS PUT."""
        return dumps(await client.ers("PUT", f"{_SGACL}/{sgacl_id}",
                                      json_body=json.loads(body)))

    @mcp.tool()
    async def ise_delete_sgacl(sgacl_id: str) -> str:
        """Delete an SGACL by id (ERS)."""
        return dumps(await client.ers("DELETE", f"{_SGACL}/{sgacl_id}"))

    @mcp.tool()
    async def ise_list_egress_matrix() -> str:
        """List the TrustSec egress matrix cells (src SGT x dst SGT -> SGACLs). ERS."""
        return dumps(await client.ers_list_all(_EMC))
