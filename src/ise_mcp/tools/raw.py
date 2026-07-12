"""Generic escape hatches (one per API surface) + OpenAPI spec search."""

from __future__ import annotations

import json
from typing import Any, Literal

from mcp.server.fastmcp import FastMCP

from ..client import ISEClient
from ..spec import SpecCache
from . import dumps


def register(mcp: FastMCP, client: ISEClient, spec: SpecCache) -> None:
    @mcp.tool()
    async def ise_openapi_call(
        method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"],
        path: str,
        query_params: dict[str, Any] | None = None,
        body: str | None = None,
    ) -> str:
        """Call any ISE OpenAPI endpoint (port 443, /api/...). The main surface.

        Use ise_search_spec / ise_get_definition first to find the path + schema.
        Example path: '/api/v1/endpoint', '/api/v1/trustsec/sgt',
        '/api/v1/policy/network-access/policy-set'.
        """
        return dumps(await client.openapi(
            method, path, params=query_params,
            json_body=json.loads(body) if body else None))

    @mcp.tool()
    async def ise_ers_call(
        method: Literal["GET", "POST", "PUT", "DELETE"],
        path: str,
        query_params: dict[str, Any] | None = None,
        body: str | None = None,
    ) -> str:
        """Call any ISE ERS endpoint (/ers/config/...), over port 443 by default.

        ERS must be enabled (Admin > System > Settings > API Settings > API
        Service Settings > ERS Read/Write); until then ISE redirects to /admin/
        and this reports "ERS not enabled". ERS is served on 443 (modern) and the
        legacy 9060 (deprecated in ISE 3.x, often off/firewalled - set
        ISE_ERS_PORT=9060 to force it). Example path: '/ers/config/networkdevice',
        '/ers/config/internaluser'.
        """
        return dumps(await client.ers(
            method, path, params=query_params,
            json_body=json.loads(body) if body else None))

    @mcp.tool()
    async def ise_mnt_call(path: str) -> str:
        """Call any ISE MnT (Monitoring) endpoint (port 443, /admin/API/mnt/...).

        Read-only operational data, returned as XML (parsed to a dict). Example
        path: '/Version', '/Session/ActiveCount', '/Session/ActiveList',
        '/Session/MACAddress/<mac>'.
        """
        return dumps(await client.mnt(path))

    @mcp.tool()
    async def ise_openapi_groups() -> str:
        """List the ISE OpenAPI groups (each is a documented sub-API)."""
        return dumps(await spec.groups())

    @mcp.tool()
    async def ise_search_spec(
        query: str,
        kind: Literal["both", "paths", "definitions"] = "both",
    ) -> str:
        """Search the ISE OpenAPI specs (all groups) for endpoints and schema names.

        Substring-matches operations (method + path + group + summary) and schema
        names across every OpenAPI group. Follow up with ise_get_definition.

        Args:
            query: substring, e.g. 'endpoint', 'sgt', 'policy-set', 'certificate'.
            kind: 'paths', 'definitions', or 'both' (default).
        """
        return dumps(await spec.search(query, kind=kind))

    @mcp.tool()
    async def ise_get_definition(name: str) -> str:
        """Dump an OpenAPI schema's fields (name -> type/enum/description) + which group."""
        return dumps(await spec.get_definition(name))
