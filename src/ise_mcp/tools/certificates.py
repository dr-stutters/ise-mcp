"""Certificate inventory tools (OpenAPI, read). System certs, trusted store,
and pending CSRs. Certificate authoring (generate CSR / import) is separate."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from ..client import ISEClient
from ..spec import SpecCache
from . import dumps


def register(mcp: FastMCP, client: ISEClient, spec: SpecCache) -> None:
    async def _default_host() -> str:
        nodes = await client.openapi("GET", "/api/v1/deployment/node")
        lst = nodes.get("response", nodes) if isinstance(nodes, dict) else nodes
        return lst[0]["hostname"] if isinstance(lst, list) and lst else "ise"

    @mcp.tool()
    async def ise_list_system_certs(hostname: str | None = None) -> str:
        """List a node's system (identity) certificates.

        Args:
            hostname: the node hostname; defaults to the first deployment node.
        """
        host = hostname or await _default_host()
        return dumps(await client.openapi(
            "GET", f"/api/v1/certs/system-certificate/{host}"))

    @mcp.tool()
    async def ise_get_system_cert(cert_id: str, hostname: str | None = None) -> str:
        """Get one system certificate by id (with node hostname)."""
        host = hostname or await _default_host()
        return dumps(await client.openapi(
            "GET", f"/api/v1/certs/system-certificate/{host}/{cert_id}"))

    @mcp.tool()
    async def ise_list_trusted_certs() -> str:
        """List certificates in the trusted-certificate store."""
        return dumps(await client.openapi("GET", "/api/v1/certs/trusted-certificate"))

    @mcp.tool()
    async def ise_get_trusted_cert(cert_id: str) -> str:
        """Get one trusted certificate by id."""
        return dumps(await client.openapi(
            "GET", f"/api/v1/certs/trusted-certificate/{cert_id}"))

    @mcp.tool()
    async def ise_list_csrs() -> str:
        """List pending certificate signing requests (CSRs)."""
        return dumps(await client.openapi(
            "GET", "/api/v1/certs/certificate-signing-request"))
