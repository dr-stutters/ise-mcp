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
_IPSGT = "/api/v1/trustsec/ip-sgt-mapping"     # OpenAPI TrustSec (feeds SXP/pxGrid)


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

    @mcp.tool()
    async def ise_list_ip_sgt_mappings() -> str:
        """List ISE IP-SGT static mappings (OpenAPI TrustSec). These populate ISE's SXP
        binding DB and are advertised over SXP / published to pxGrid subscribers such as
        FMC/FTD - the supported way to feed FMC ACP (Snort) SGT enforcement."""
        return dumps(await client.openapi("GET", _IPSGT))

    @mcp.tool()
    async def ise_create_ip_sgt_mapping(ip_host: str, sgt_name: str, sgt_value: int,
                                        sgt_domains: list[str] | None = None) -> str:
        """Create an IP-SGT static mapping (OpenAPI TrustSec); returns the new id.

        Maps an IP to an SGT inside one or more SXP domains, so ISE advertises it over SXP
        and publishes it to pxGrid subscribers (e.g. FMC learns it -> pushes to FTD Snort).

        Args:
            ip_host: literal IP address, e.g. "10.40.0.10" (uses the `ipHost` field; the
                `ipOrHost` field is treated as an FQDN and would need resolvingNodes).
            sgt_name: SGT name, e.g. "Employees".
            sgt_value: SGT numeric tag, e.g. 4.
            sgt_domains: SXP domains to place the mapping in; defaults to ["default"]
                (one of sgt_domains / deployToDevices is mandatory - ISE 500s otherwise).
        """
        body = {
            "ipHost": ip_host,
            "sgt": f"{sgt_name} ({sgt_value}/{sgt_value:04d})",
            "sgtDomains": sgt_domains or ["default"],
        }
        return dumps(await client.openapi("POST", _IPSGT, json_body=body))

    @mcp.tool()
    async def ise_delete_ip_sgt_mapping(mapping_id: str) -> str:
        """Delete an IP-SGT static mapping by id (OpenAPI TrustSec)."""
        return dumps(await client.openapi("DELETE", f"{_IPSGT}/{mapping_id}"))
