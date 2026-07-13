"""Network device (NAD / RADIUS client) tools.

ERS surface (over port 443 by default; legacy 9060). ERS must be enabled in API
Settings, else ISE redirects to /admin/ and these report "ERS not enabled".
There is no OpenAPI equivalent for NADs in ISE 3.4/3.5, so this is ERS-only.
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
    async def ise_list_network_devices(filter: str | None = None) -> str:
        """List network devices (NADs / RADIUS clients). ERS, follows paging.

        Args:
            filter: optional ERS filter, e.g. 'name.CONTAINS.core' or
                'ipaddress.EQ.10.0.0.1'.
        """
        params = {"filter": filter} if filter else None
        return dumps(await client.ers_list_all(_ND, params=params))

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
        tacacs_shared_secret: str | None = None,
    ) -> str:
        """Onboard a network device (NAD) with a RADIUS shared secret (ERS).

        Args:
            name: device name.
            ip: management/RADIUS source IP of the NAD.
            radius_shared_secret: the RADIUS shared secret.
            mask: prefix length for the device IP entry (default 32).
            description: optional.
            tacacs_shared_secret: optional TACACS+ shared secret. When set, the NAD
                also gets tacacsSettings so it can be a TACACS+ device-admin client
                (requires the Device Admin service enabled on the ISE node).
        """
        nd: dict = {
            "name": name,
            "description": description,
            "NetworkDeviceIPList": [{"ipaddress": ip, "mask": mask}],
            "authenticationSettings": {
                "radiusSharedSecret": radius_shared_secret,
                "enableKeyWrap": False,
            },
        }
        if tacacs_shared_secret is not None:
            nd["tacacsSettings"] = {"sharedSecret": tacacs_shared_secret,
                                    "connectModeOptions": "ON_LEGACY"}
        return dumps(await client.ers("POST", _ND, json_body={"NetworkDevice": nd}))

    @mcp.tool()
    async def ise_create_network_device_raw(body: str) -> str:
        """Create a NAD from a full ERS JSON body ({'NetworkDevice': {...}})."""
        return dumps(await client.ers("POST", _ND, json_body=json.loads(body)))

    @mcp.tool()
    async def ise_update_network_device(device_id: str, name: str | None = None,
                                        description: str | None = None) -> str:
        """Update a network device's name/description (ERS; only given fields change).

        For deeper edits (IP list, shared secret) use ise_ers_call with a PUT.
        """
        return dumps(await client.ers_update(
            _ND, device_id, "NetworkDevice", {"name": name, "description": description}))

    @mcp.tool()
    async def ise_delete_network_device(device_id: str) -> str:
        """Delete a network device by id (ERS)."""
        return dumps(await client.ers("DELETE", f"{_ND}/{device_id}"))

    @mcp.tool()
    async def ise_list_network_device_groups() -> str:
        """List network device groups (ERS)."""
        return dumps(await client.ers_list_all("/ers/config/networkdevicegroup"))

    @mcp.tool()
    async def ise_create_network_device_group(name: str, root_type: str = "Device Type",
                                              description: str = "") -> str:
        """Create a network device group (ERS). Returns the new group's id.

        Args:
            name: hierarchical group name, e.g. 'Device Type#All Device Types#Switches'.
            root_type: the root group ('Device Type', 'Location', 'IPSEC', ...).
            description: optional.
        """
        body = {"NetworkDeviceGroup": {"name": name, "description": description,
                                       "othername": root_type}}
        return dumps(await client.ers("POST", "/ers/config/networkdevicegroup",
                                      json_body=body))

    @mcp.tool()
    async def ise_delete_network_device_group(group_id: str) -> str:
        """Delete a network device group by id (ERS)."""
        return dumps(await client.ers("DELETE",
                                      f"/ers/config/networkdevicegroup/{group_id}"))
