"""Endpoint tools (OpenAPI /api/v1/endpoint)."""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from ..client import ISEClient
from ..spec import SpecCache
from . import dumps


def register(mcp: FastMCP, client: ISEClient, spec: SpecCache) -> None:
    @mcp.tool()
    async def ise_list_endpoints(
        filter: str | None = None,
        page: int = 1,
        size: int = 100,
    ) -> str:
        """List endpoints (OpenAPI).

        Args:
            filter: optional filter e.g. 'mac.CONTAINS.AA' or 'name.EQ.<mac>'.
            page: 1-based page number.
            size: page size (max 500).
        """
        params: dict = {"page": page, "size": size}
        if filter:
            params["filter"] = filter
        return dumps(await client.openapi("GET", "/api/v1/endpoint", params=params))

    @mcp.tool()
    async def ise_get_endpoint(value: str) -> str:
        """Get one endpoint by id (UUID) or MAC address."""
        return dumps(await client.openapi("GET", f"/api/v1/endpoint/{value}"))

    @mcp.tool()
    async def ise_create_endpoint(mac: str, name: str | None = None,
                                  group_id: str | None = None,
                                  description: str | None = None) -> str:
        """Register an endpoint by MAC. Optionally assign an endpoint identity group.

        Returns the created endpoint (incl. its id). The POST itself returns an
        empty 201, so the new record is fetched back by MAC.
        """
        body: dict = {"mac": mac, "name": name or mac}
        if group_id:
            body["groupId"] = group_id
        if description:
            body["description"] = description
        result = await client.openapi("POST", "/api/v1/endpoint", json_body=body)
        if not result:  # empty 201 - fetch the created record so the id comes back
            result = await client.openapi("GET", f"/api/v1/endpoint/{mac}")
        return dumps(result)

    @mcp.tool()
    async def ise_create_endpoint_raw(body: str) -> str:
        """Create an endpoint from a full JSON body (see ise_get_definition 'Endpoint')."""
        return dumps(await client.openapi(
            "POST", "/api/v1/endpoint", json_body=json.loads(body)))

    @mcp.tool()
    async def ise_update_endpoint(value: str, group_id: str | None = None,
                                  description: str | None = None) -> str:
        """Update an endpoint by id/MAC (OpenAPI). Only given fields change.

        Commonly used to move an endpoint into an endpoint identity group
        (group_id) for MAB.
        """
        current = await client.openapi("GET", f"/api/v1/endpoint/{value}")
        obj = dict(current.get("response", current) if isinstance(current, dict) else {})
        if group_id is not None:
            obj["groupId"] = group_id
        if description is not None:
            obj["description"] = description
        return dumps(await client.openapi(
            "PUT", f"/api/v1/endpoint/{obj.get('id', value)}", json_body=obj))

    @mcp.tool()
    async def ise_delete_endpoint(value: str) -> str:
        """Delete an endpoint by id (UUID) or MAC address."""
        return dumps(await client.openapi("DELETE", f"/api/v1/endpoint/{value}"))

    # ------------------------------------------------------------------
    # Bulk endpoint operations (OpenAPI /api/v1/endpoint/bulk). Async: each
    # returns a task id - poll it with ise_get_task_status.
    # ------------------------------------------------------------------
    @mcp.tool()
    async def ise_bulk_create_endpoints(macs: list[str], group_id: str | None = None,
                                        description: str = "") -> str:
        """Bulk-create endpoints from a list of MACs (OpenAPI); returns an async task
        id (poll ise_get_task_status). Optionally static-assign them all to an endpoint
        identity group (group_id, e.g. for MAB - see ise_list_endpoint_groups)."""
        extra = {"groupId": group_id, "staticGroupAssignment": True} if group_id else {}
        body = [{"mac": m, "description": description, **extra} for m in macs]
        return dumps(await client.openapi("POST", "/api/v1/endpoint/bulk", json_body=body))

    @mcp.tool()
    async def ise_bulk_update_endpoints(macs: list[str], group_id: str | None = None,
                                        description: str | None = None) -> str:
        """Bulk-update endpoints by MAC (OpenAPI); returns an async task id. Give
        group_id to static-assign them all to an endpoint identity group, and/or
        description to set it. At least one of group_id/description should be set."""
        patch: dict = {}
        if group_id is not None:
            patch["groupId"] = group_id
            patch["staticGroupAssignment"] = True
        if description is not None:
            patch["description"] = description
        body = [{"mac": m, **patch} for m in macs]
        return dumps(await client.openapi("PUT", "/api/v1/endpoint/bulk", json_body=body))

    @mcp.tool()
    async def ise_bulk_delete_endpoints(macs: list[str]) -> str:
        """Bulk-delete endpoints by MAC (OpenAPI); returns an async task id (poll
        ise_get_task_status)."""
        return dumps(await client.openapi("DELETE", "/api/v1/endpoint/bulk",
                                          json_body={"endpoints": macs}))
