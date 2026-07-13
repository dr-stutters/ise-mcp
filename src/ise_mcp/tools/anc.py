"""Adaptive Network Control (ANC) tools (ERS).

ANC is ISE's on-demand endpoint containment. Define an ANC policy with an action
(quarantine the endpoint, shut its switchport, or bounce the port), then apply
that policy to an endpoint by MAC. Applying or clearing an ANC policy issues a
CoA so the network re-authorizes the session immediately - this is the basis for
rapid threat containment: a SIEM or firewall detects something, and ISE quarantines
the endpoint in seconds.

ERS-only (no OpenAPI equivalent). Policies live at /ers/config/ancpolicy; the
apply/clear/list of quarantined endpoints is /ers/config/ancendpoint.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from ..client import ISEClient
from ..spec import SpecCache
from . import dumps

_POLICY = "/ers/config/ancpolicy"
_ENDPOINT = "/ers/config/ancendpoint"
_ACTIONS = ("QUARANTINE", "SHUT_DOWN", "PORT_BOUNCE", "RE_AUTHENTICATE")


def register(mcp: FastMCP, client: ISEClient, spec: SpecCache) -> None:
    @mcp.tool()
    async def ise_list_anc_policies() -> str:
        """List Adaptive Network Control (ANC) policies (ERS)."""
        return dumps(await client.ers_list_all(_POLICY))

    @mcp.tool()
    async def ise_get_anc_policy(policy_id: str) -> str:
        """Get one ANC policy by id (ERS)."""
        return dumps(await client.ers("GET", f"{_POLICY}/{policy_id}"))

    @mcp.tool()
    async def ise_create_anc_policy(name: str, action: str = "QUARANTINE") -> str:
        """Create an ANC policy (ERS). Returns the new id.

        Args:
            name: policy name.
            action: the containment action - QUARANTINE (default; a policy result
                the authZ policy can match to drop/limit access), SHUT_DOWN (shut
                the switchport), PORT_BOUNCE (bounce the port to force re-auth), or
                RE_AUTHENTICATE.
        """
        if action not in _ACTIONS:
            raise ValueError(f"action must be one of {_ACTIONS}")
        body = {"ErsAncPolicy": {"name": name, "actions": [action]}}
        return dumps(await client.ers("POST", _POLICY, json_body=body))

    @mcp.tool()
    async def ise_delete_anc_policy(policy_id: str) -> str:
        """Delete an ANC policy by id (ERS)."""
        return dumps(await client.ers("DELETE", f"{_POLICY}/{policy_id}"))

    @mcp.tool()
    async def ise_list_anc_endpoints() -> str:
        """List endpoints that currently have an ANC policy applied (ERS)."""
        return dumps(await client.ers_list_all(_ENDPOINT))

    @mcp.tool()
    async def ise_apply_anc(mac: str, policy_name: str) -> str:
        """Apply an ANC policy to an endpoint by MAC - contain it now (ERS).

        Issues a CoA so the endpoint is re-authorized against the ANC result
        immediately. Use `ise_clear_anc` to release it.

        Args:
            mac: endpoint MAC address (e.g. 'AA:BB:CC:DD:EE:FF').
            policy_name: name of an existing ANC policy (see ise_list_anc_policies).
        """
        body = {"OperationAdditionalData": {"additionalData": [
            {"name": "macAddress", "value": mac},
            {"name": "policyName", "value": policy_name}]}}
        return dumps(await client.ers("PUT", f"{_ENDPOINT}/apply", json_body=body))

    @mcp.tool()
    async def ise_clear_anc(mac: str, policy_name: str) -> str:
        """Clear an ANC policy from an endpoint by MAC - release containment (ERS).

        Issues a CoA so the endpoint re-authorizes normally.

        Args:
            mac: endpoint MAC address.
            policy_name: the ANC policy currently applied to it.
        """
        body = {"OperationAdditionalData": {"additionalData": [
            {"name": "macAddress", "value": mac},
            {"name": "policyName", "value": policy_name}]}}
        return dumps(await client.ers("PUT", f"{_ENDPOINT}/clear", json_body=body))
