"""Policy tools: policy sets + rules (OpenAPI) and authorization results
(authZ profiles, downloadable ACLs) which are ERS resources.

Reads (policy sets, rules, authZ profiles, conditions) use the OpenAPI Policy
surface. Authoring authZ profiles and dACLs uses ERS (/ers/config/...); creating
policy sets and authN/authZ rules uses the OpenAPI Policy surface.
"""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from ..client import ISEClient
from ..spec import SpecCache
from . import dumps

_NA = "/api/v1/policy/network-access"
_DA = "/api/v1/policy/device-admin"
_ERS_AP = "/ers/config/authorizationprofile"
_ERS_DACL = "/ers/config/downloadableacl"

# Default allowed-protocols service per policy kind.
_DEFAULT_SERVICE = {"network-access": "Default Network Access",
                    "device-admin": "Default Device Admin"}


def _base(kind: str) -> str:
    """OpenAPI policy base for 'network-access' (RADIUS) or 'device-admin' (TACACS+)."""
    if kind not in ("network-access", "device-admin"):
        raise ValueError("kind must be 'network-access' or 'device-admin'")
    return _DA if kind == "device-admin" else _NA


def register(mcp: FastMCP, client: ISEClient, spec: SpecCache) -> None:
    async def _resolve_condition(condition_name, condition, kind="network-access"):
        """Return a condition dict from raw JSON, a library-condition name, or None.

        Library conditions are looked up in the matching (network-access or
        device-admin) condition library.
        """
        if condition:
            return json.loads(condition)
        if condition_name:
            conds = await client.openapi("GET", f"{_base(kind)}/condition")
            cl = conds if isinstance(conds, list) else conds.get("response", [])
            m = next((c for c in cl if c.get("name") == condition_name), None)
            if not m:
                raise ValueError(
                    f"library condition '{condition_name}' not found in {kind} - "
                    "see ise_list_conditions")
            return {"conditionType": "ConditionReference", "isNegate": False,
                    "id": m["id"], "name": m["name"]}
        return None

    @mcp.tool()
    async def ise_list_policy_sets(kind: str = "network-access") -> str:
        """List policy sets.

        Args:
            kind: 'network-access' (RADIUS, default) or 'device-admin' (TACACS+).
        """
        base = _DA if kind == "device-admin" else _NA
        return dumps(await client.openapi("GET", f"{base}/policy-set"))

    @mcp.tool()
    async def ise_get_policy_set(policy_id: str, kind: str = "network-access") -> str:
        """Get one policy set by id (kind: 'network-access' | 'device-admin')."""
        base = _DA if kind == "device-admin" else _NA
        return dumps(await client.openapi("GET", f"{base}/policy-set/{policy_id}"))

    @mcp.tool()
    async def ise_get_authentication_rules(policy_id: str,
                                           kind: str = "network-access") -> str:
        """List the authentication rules under a policy set."""
        base = _DA if kind == "device-admin" else _NA
        return dumps(await client.openapi(
            "GET", f"{base}/policy-set/{policy_id}/authentication"))

    @mcp.tool()
    async def ise_get_authorization_rules(policy_id: str,
                                          kind: str = "network-access") -> str:
        """List the authorization rules under a policy set."""
        base = _DA if kind == "device-admin" else _NA
        return dumps(await client.openapi(
            "GET", f"{base}/policy-set/{policy_id}/authorization"))

    @mcp.tool()
    async def ise_list_authorization_profiles() -> str:
        """List authorization profiles (network-access)."""
        return dumps(await client.openapi(
            "GET", f"{_NA}/authorization-profiles"))

    @mcp.tool()
    async def ise_list_conditions(kind: str = "network-access") -> str:
        """List reusable policy conditions (kind: 'network-access' | 'device-admin')."""
        return dumps(await client.openapi("GET", f"{_base(kind)}/condition"))

    # ---- Authorization profiles (ERS) ----
    @mcp.tool()
    async def ise_get_authz_profile(profile_id: str) -> str:
        """Get one authorization profile by id (ERS)."""
        return dumps(await client.ers("GET", f"{_ERS_AP}/{profile_id}"))

    @mcp.tool()
    async def ise_create_authz_profile(
        name: str,
        access_type: str = "ACCESS_ACCEPT",
        vlan: str | None = None,
        dacl_name: str | None = None,
        description: str = "",
    ) -> str:
        """Create an authorization profile (ERS). Returns the new profile's id.

        Args:
            name: profile name.
            access_type: 'ACCESS_ACCEPT' (default) or 'ACCESS_REJECT'.
            vlan: optional VLAN name/id to assign (sets vlan.nameID).
            dacl_name: optional downloadable ACL name to apply.
            description: optional.
        """
        ap: dict = {"name": name, "accessType": access_type, "description": description}
        if vlan:
            ap["vlan"] = {"nameID": vlan, "tagID": 1}
        if dacl_name:
            ap["daclName"] = dacl_name
        return dumps(await client.ers("POST", _ERS_AP,
                                      json_body={"AuthorizationProfile": ap}))

    @mcp.tool()
    async def ise_create_authz_profile_raw(body: str) -> str:
        """Create an authZ profile from a full ERS JSON body ({'AuthorizationProfile': {...}})."""
        return dumps(await client.ers("POST", _ERS_AP, json_body=json.loads(body)))

    @mcp.tool()
    async def ise_update_authz_profile(profile_id: str, vlan: str | None = None,
                                       dacl_name: str | None = None,
                                       description: str | None = None) -> str:
        """Update an authorization profile's VLAN/dACL/description (ERS)."""
        changes: dict = {"daclName": dacl_name, "description": description}
        if vlan is not None:
            changes["vlan"] = {"nameID": vlan, "tagID": 1}
        return dumps(await client.ers_update(
            _ERS_AP, profile_id, "AuthorizationProfile", changes))

    @mcp.tool()
    async def ise_delete_authz_profile(profile_id: str) -> str:
        """Delete an authorization profile by id (ERS)."""
        return dumps(await client.ers("DELETE", f"{_ERS_AP}/{profile_id}"))

    # ---- Downloadable ACLs (ERS) ----
    @mcp.tool()
    async def ise_list_dacls() -> str:
        """List downloadable ACLs (ERS)."""
        return dumps(await client.ers_list_all(_ERS_DACL))

    @mcp.tool()
    async def ise_get_dacl(dacl_id: str) -> str:
        """Get one downloadable ACL by id (ERS)."""
        return dumps(await client.ers("GET", f"{_ERS_DACL}/{dacl_id}"))

    @mcp.tool()
    async def ise_create_dacl(name: str, dacl: str, dacl_type: str = "IPV4",
                              description: str = "") -> str:
        """Create a downloadable ACL (ERS). Returns the new dACL's id.

        Args:
            name: dACL name.
            dacl: the ACL content, e.g. 'permit ip any any' (newline-separate ACEs).
            dacl_type: 'IPV4' (default), 'IPV6', or 'IP_AGNOSTIC'.
            description: optional.
        """
        body = {"DownloadableAcl": {"name": name, "dacl": dacl,
                                    "daclType": dacl_type, "description": description}}
        return dumps(await client.ers("POST", _ERS_DACL, json_body=body))

    @mcp.tool()
    async def ise_update_dacl(dacl_id: str, dacl: str | None = None,
                              description: str | None = None) -> str:
        """Update a downloadable ACL's content/description (ERS)."""
        return dumps(await client.ers_update(
            _ERS_DACL, dacl_id, "DownloadableAcl",
            {"dacl": dacl, "description": description}))

    @mcp.tool()
    async def ise_delete_dacl(dacl_id: str) -> str:
        """Delete a downloadable ACL by id (ERS)."""
        return dumps(await client.ers("DELETE", f"{_ERS_DACL}/{dacl_id}"))

    # ---- Policy sets + rules authoring (OpenAPI) ----
    @mcp.tool()
    async def ise_create_policy_set(name: str, description: str = "",
                                    service_name: str | None = None,
                                    condition_name: str | None = None,
                                    condition: str | None = None,
                                    kind: str = "network-access") -> str:
        """Create a policy set (OpenAPI). Returns the created set.

        A policy set REQUIRES a condition (only the built-in Default may be
        condition-less). Provide one via `condition_name` (a library condition,
        e.g. 'Wired_802.1X', 'Wired_MAB', 'Wireless_802.1X') or a raw `condition`
        JSON string.

        Args:
            name: policy set name.
            description: optional.
            service_name: allowed protocols / service. Defaults to
                'Default Network Access' (RADIUS) or 'Default Device Admin' (TACACS+).
            condition_name: a library condition name to match (resolved for you).
            condition: raw condition JSON string (alternative to condition_name).
            kind: 'network-access' (RADIUS, default) or 'device-admin' (TACACS+).
        """
        cond = await _resolve_condition(condition_name, condition, kind)
        if cond is None:
            raise ValueError("a policy set requires a condition - pass condition_name "
                             "(e.g. 'Wired_802.1X') or a condition JSON string")
        body: dict = {"name": name, "description": description,
                      "serviceName": service_name or _DEFAULT_SERVICE[kind],
                      "isProxy": False, "condition": cond}
        return dumps(await client.openapi("POST", f"{_base(kind)}/policy-set", json_body=body))

    @mcp.tool()
    async def ise_create_policy_set_raw(body: str, kind: str = "network-access") -> str:
        """Create a policy set from a full JSON body (kind: 'network-access' | 'device-admin')."""
        return dumps(await client.openapi("POST", f"{_base(kind)}/policy-set",
                                          json_body=json.loads(body)))

    @mcp.tool()
    async def ise_update_policy_set_raw(policy_id: str, body: str,
                                        kind: str = "network-access") -> str:
        """Update a policy set from a full JSON body (OpenAPI PUT)."""
        return dumps(await client.openapi(
            "PUT", f"{_base(kind)}/policy-set/{policy_id}", json_body=json.loads(body)))

    @mcp.tool()
    async def ise_delete_policy_set(policy_id: str, kind: str = "network-access") -> str:
        """Delete a policy set by id (kind: 'network-access' | 'device-admin')."""
        return dumps(await client.openapi("DELETE", f"{_base(kind)}/policy-set/{policy_id}"))

    @mcp.tool()
    async def ise_create_authz_rule(policy_id: str, name: str, profiles: list[str],
                                    security_group: str | None = None,
                                    condition_name: str | None = None,
                                    condition: str | None = None,
                                    rank: int = 0) -> str:
        """Create an authorization rule in a policy set (OpenAPI).

        Args:
            policy_id: the policy set id.
            name: rule name.
            profiles: list of authorization profile NAMES to apply (e.g. ['PermitAccess']).
            security_group: optional SGT name to assign.
            condition_name: a library condition name to match (resolved for you),
                e.g. 'Wired_802.1X'; omit (with no `condition`) for a catch-all rule.
            condition: raw condition JSON string (alternative to condition_name).
            rank: rule position (0 = top).
        """
        cond = await _resolve_condition(condition_name, condition)
        body: dict = {
            "rule": {"name": name, "rank": rank, "state": "enabled", "condition": cond},
            "profile": profiles,
            "securityGroup": security_group,
        }
        return dumps(await client.openapi(
            "POST", f"{_NA}/policy-set/{policy_id}/authorization", json_body=body))

    @mcp.tool()
    async def ise_create_authz_rule_raw(policy_id: str, body: str,
                                        kind: str = "network-access") -> str:
        """Create an authorization rule from a full JSON body (OpenAPI).

        Use this for device-admin (TACACS+) rules: pass kind='device-admin' and a
        body with `commandSets` (list of command-set names) and/or `profile` (a
        shell-profile name) as the result, instead of network-access `profile`
        (list of authZ profiles) + `securityGroup`.
        """
        return dumps(await client.openapi(
            "POST", f"{_base(kind)}/policy-set/{policy_id}/authorization",
            json_body=json.loads(body)))

    @mcp.tool()
    async def ise_update_authz_rule_raw(policy_id: str, rule_id: str, body: str,
                                        kind: str = "network-access") -> str:
        """Update an authorization rule from a full JSON body (OpenAPI PUT)."""
        return dumps(await client.openapi(
            "PUT", f"{_base(kind)}/policy-set/{policy_id}/authorization/{rule_id}",
            json_body=json.loads(body)))

    @mcp.tool()
    async def ise_delete_authz_rule(policy_id: str, rule_id: str,
                                    kind: str = "network-access") -> str:
        """Delete an authorization rule from a policy set (kind: net-access | device-admin)."""
        return dumps(await client.openapi(
            "DELETE", f"{_base(kind)}/policy-set/{policy_id}/authorization/{rule_id}"))
