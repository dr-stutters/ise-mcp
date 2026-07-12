"""Endpoint custom-attribute tools (OpenAPI). Define extra attributes that can
then be set on endpoints (e.g. for context-based authZ)."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from ..client import ISEClient
from ..spec import SpecCache
from . import dumps

_CA = "/api/v1/endpoint-custom-attribute"


def register(mcp: FastMCP, client: ISEClient, spec: SpecCache) -> None:
    @mcp.tool()
    async def ise_list_custom_attributes() -> str:
        """List endpoint custom-attribute definitions."""
        return dumps(await client.openapi("GET", _CA))

    @mcp.tool()
    async def ise_get_custom_attribute(name: str) -> str:
        """Get one endpoint custom-attribute definition by name."""
        return dumps(await client.openapi("GET", f"{_CA}/{name}"))

    @mcp.tool()
    async def ise_create_custom_attribute(name: str, attr_type: str = "String") -> str:
        """Create an endpoint custom-attribute definition.

        Args:
            name: attribute name.
            attr_type: 'String' (default), 'Int', 'Long', 'Boolean', 'Float',
                'Date', or 'IP'.
        """
        return dumps(await client.openapi(
            "POST", _CA, json_body={"attributeName": name, "attributeType": attr_type}))

    @mcp.tool()
    async def ise_delete_custom_attribute(name: str) -> str:
        """Delete an endpoint custom-attribute definition by name."""
        return dumps(await client.openapi("DELETE", f"{_CA}/{name}"))
