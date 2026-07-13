"""Deployment tools (OpenAPI): nodes + persona/service enablement."""

from __future__ import annotations

import asyncio
import time

from mcp.server.fastmcp import FastMCP

from ..client import ISEAPIError, ISEClient
from ..spec import SpecCache
from . import dumps

# Fields on a deployment-node GET that are read-only status (must NOT be sent on PUT).
_NODE_READONLY = {"nodeStatus", "link"}


def register(mcp: FastMCP, client: ISEClient, spec: SpecCache) -> None:
    @mcp.tool()
    async def ise_deployment_nodes() -> str:
        """List ISE deployment nodes (hostname, roles, services, ip)."""
        return dumps(await client.openapi("GET", "/api/v1/deployment/node"))

    @mcp.tool()
    async def ise_node_services(hostname: str) -> str:
        """Show a deployment node's enabled roles + services (e.g. Session, Profiler,
        DeviceAdmin, pxGrid). Read-only summary."""
        node = await client.openapi("GET", f"/api/v1/deployment/node/{hostname}")
        n = node.get("response", node) if isinstance(node, dict) else node
        if isinstance(n, list):
            n = n[0] if n else {}
        return dumps({"hostname": n.get("hostname"), "roles": n.get("roles"),
                      "services": n.get("services"), "nodeStatus": n.get("nodeStatus")})

    @mcp.tool()
    async def ise_enable_device_admin(hostname: str, wait_minutes: int = 30) -> str:
        """Enable the TACACS+ Device Admin service on an ISE node (idempotent).

        Required before any device-admin (TACACS+) policy or accounting works.
        GETs the node, and if 'DeviceAdmin' is not already in its services, PUTs the
        full node doc back with DeviceAdmin appended. **This restarts the ISE
        application server** (~10-20 min): the tool then polls the node GET until the
        API answers again AND DeviceAdmin is listed, up to wait_minutes. No-op (fast
        return) if the service is already enabled.
        """
        node = await client.openapi("GET", f"/api/v1/deployment/node/{hostname}")
        n = node.get("response", node) if isinstance(node, dict) else node
        if isinstance(n, list):
            n = n[0] if n else {}
        before = list(n.get("services") or [])
        roles = list(n.get("roles") or ["Standalone"])
        if "DeviceAdmin" in before:
            return dumps({"hostname": hostname, "changed": False,
                          "services": before, "note": "DeviceAdmin already enabled"})
        # PUT body is a NodeUpdateRequest: roles + services only (echoing the full
        # read-model node doc is rejected with a 400).
        body = {"roles": roles, "services": before + ["DeviceAdmin"]}
        try:
            await client.openapi("PUT", f"/api/v1/deployment/node/{hostname}", json_body=body)
        except ISEAPIError as e:
            # A persona change often drops the connection mid-restart; treat a transient
            # error here as "restart likely underway" and fall through to polling.
            if e.status_code not in (0, 500, 502, 503):
                raise
        deadline = time.time() + wait_minutes * 60
        last = "no response yet"
        while time.time() < deadline:
            await asyncio.sleep(30)
            try:
                cur = await client.openapi("GET", f"/api/v1/deployment/node/{hostname}")
                c = cur.get("response", cur) if isinstance(cur, dict) else cur
                if isinstance(c, list):
                    c = c[0] if c else {}
                svcs = list(c.get("services") or [])
                if "DeviceAdmin" in svcs:
                    return dumps({"hostname": hostname, "changed": True,
                                  "services_before": before, "services_after": svcs,
                                  "elapsed_minutes": round((time.time() - deadline)
                                                           / 60 + wait_minutes, 1)})
                last = f"API up, services={svcs}"
            except ISEAPIError as e:
                last = f"API not ready: {e.status_code}"
            except Exception as e:  # noqa: BLE001 - transport churn during restart
                last = f"waiting: {type(e).__name__}"
        return dumps({"hostname": hostname, "changed": True, "healthy": False,
                      "services_before": before, "last_state": last,
                      "note": f"DeviceAdmin PUT sent but service not confirmed within "
                              f"{wait_minutes} min - check the node manually"})

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
