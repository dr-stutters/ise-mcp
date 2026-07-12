"""Network device (NAD / RADIUS client) tools.

ERS surface (port 9060). ERS must be enabled and 9060 reachable; some
deployments (dCloud) firewall 9060 - these tools then time out. There is no
OpenAPI equivalent for NADs in ISE 3.4/3.5, so this is ERS-only.
"""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from ..client import ISEClient
from ..spec import SpecCache
from . import dumps

_ND = "/ers/config/networkdevice"


def register(mcp: FastMCP, client: ISEClient, spec: SpecCache) -> None:
    @mcp.tool()
    async def ise_list_network_devices() -> str:
        """List all network devices (NADs / RADIUS clients). ERS, follows paging."""
        return dumps(await client.ers_list_all(_ND))

    @mcp.tool()
    async def ise_get_network_device(device_id: str) -> str:
        """Get one network device by id (ERS)."""
        return dumps(await client.ers("GET", f"{_ND}/{device_id}"))

    @mcp.tool()
    async def ise_get_network_device_by_name(name: str) -> str:
        """Get one network device by name (ERS)."""
        return dumps(await client.ers("GET", f"{_ND}/name/{name}"))

    @mcp.tool()
    async def ise_create_network_device(
        name: str,
        ip: str,
        radius_shared_secret: str,
        mask: int = 32,
        description: str = "",
    ) -> str:
        """Onboard a network device (NAD) with a RADIUS shared secret (ERS).

        Args:
            name: device name.
            ip: management/RADIUS source IP of the NAD.
            radius_shared_secret: the RADIUS shared secret.
            mask: prefix length for the device IP entry (default 32).
            description: optional.
        """
        body = {
            "NetworkDevice": {
                "name": name,
                "description": description,
                "NetworkDeviceIPList": [{"ipaddress": ip, "mask": mask}],
                "authenticationSettings": {
                    "radiusSharedSecret": radius_shared_secret,
                    "enableKeyWrap": False,
                },
            }
        }
        return dumps(await client.ers("POST", _ND, json_body=body))

    @mcp.tool()
    async def ise_create_network_device_raw(body: str) -> str:
        """Create a NAD from a full ERS JSON body ({'NetworkDevice': {...}})."""
        return dumps(await client.ers("POST", _ND, json_body=json.loads(body)))

    @mcp.tool()
    async def ise_delete_network_device(device_id: str) -> str:
        """Delete a network device by id (ERS)."""
        return dumps(await client.ers("DELETE", f"{_ND}/{device_id}"))

    @mcp.tool()
    async def ise_list_network_device_groups() -> str:
        """List network device groups (ERS)."""
        return dumps(await client.ers_list_all("/ers/config/networkdevicegroup"))
