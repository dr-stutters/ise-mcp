"""Deployment tools (OpenAPI): nodes."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from ..client import ISEClient
from ..spec import SpecCache
from . import dumps


def register(mcp: FastMCP, client: ISEClient, spec: SpecCache) -> None:
    @mcp.tool()
    async def ise_deployment_nodes() -> str:
        """List ISE deployment nodes (hostname, roles, services, ip)."""
        return dumps(await client.openapi("GET", "/api/v1/deployment/node"))

    @mcp.tool()
    async def ise_get_node(hostname: str) -> str:
        """Get one deployment node's detail by hostname."""
        return dumps(await client.openapi("GET", f"/api/v1/deployment/node/{hostname}"))
