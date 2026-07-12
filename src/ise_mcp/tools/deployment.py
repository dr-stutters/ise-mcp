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

    @mcp.tool()
    async def ise_get_node_group(name: str) -> str:
        """Get one deployment node group by name (PSN group for session failover)."""
        return dumps(await client.openapi("GET", f"/api/v1/deployment/node-group/{name}"))

    @mcp.tool()
    async def ise_create_node_group(name: str, description: str = "") -> str:
        """Create a deployment node group (PSN group for session failover)."""
        return dumps(await client.openapi(
            "POST", "/api/v1/deployment/node-group",
            json_body={"name": name, "description": description}))

    @mcp.tool()
    async def ise_delete_node_group(name: str) -> str:
        """Delete a deployment node group by name."""
        return dumps(await client.openapi("DELETE", f"/api/v1/deployment/node-group/{name}"))
