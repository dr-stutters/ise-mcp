"""Integration suite: drive the ISE MCP tool layer against a live ISE.

Read-only by default (safe to run anytime). Pass --write to also run
create -> verify -> delete round-trips on throwaway objects (lab boxes only).

Needs a .env / env (ISE_URL, ISE_USERNAME, ISE_PASSWORD) pointing at a reachable
ISE with ERS enabled. Verified against ISE 3.4.0.608 and 3.5.0.527.

    uv run python tests/integration_test.py            # read-only
    uv run python tests/integration_test.py --write    # + write round-trips

Exit code is non-zero only on FAIL (version/feature SKIPs don't fail the run).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from ise_mcp.server import build_server

rows: list[tuple[str, str, str]] = []


def rec(label: str, status: str, detail: str = "") -> None:
    rows.append((label, status, str(detail).replace("\n", " ")[:90]))


async def call(mcp, tool, **args) -> str:
    try:
        res = await mcp.call_tool(tool, args)
    except Exception as e:  # FastMCP raises ToolError on tool failure
        return f"Error executing tool {tool}: {e}"
    if isinstance(res, tuple):
        res = res[0]
    return "\n".join(getattr(b, "text", str(b)) for b in res)


def safe(s):
    try:
        return json.loads(s)
    except Exception:
        return s


def is_err(s) -> bool:
    return isinstance(s, str) and ("Error executing tool" in s or s.startswith("ISE API error"))


def as_list(o):
    if isinstance(o, list):
        return o
    if isinstance(o, dict):
        if isinstance(o.get("response"), list):
            return o["response"]
        sr = o.get("SearchResult")
        if isinstance(sr, dict):
            return sr.get("resources", [])
        if isinstance(o.get("profiles"), list):
            return o["profiles"]
    return o


async def read_check(mcp, tool, **args) -> None:
    out = await call(mcp, tool, **args)
    if is_err(out):
        rec(tool, "SKIP" if "401" in out or "404" in out else "FAIL", out[-70:])
        return
    lv = as_list(safe(out))
    rec(tool, "OK", f"{len(lv)} items" if isinstance(lv, list) else "ok")


async def roundtrip(mcp, label, *, create_tool, create_args, list_tool, name_val,
                    del_tool, del_key, list_args=None, name_key="name"):
    """create -> find -> delete -> confirm-gone via the tool layer (pre-cleans)."""
    list_args = list_args or {}

    async def find_id():
        for it in as_list(safe(await call(mcp, list_tool, **list_args))):
            if isinstance(it, dict) and it.get(name_key) == name_val:
                return it.get("id")
        return None

    try:
        old = await find_id()
        if old:
            await call(mcp, del_tool, **{del_key: old})
        created = safe(await call(mcp, create_tool, **create_args))
        if is_err(created):
            rec(label, "FAIL", f"create: {created}")
            return
        oid = created.get("id") if isinstance(created, dict) else None
        oid = oid or await find_id()
        if not oid:
            rec(label, "FAIL", f"not found after create: {created}")
            return
        await call(mcp, del_tool, **{del_key: oid})
        rec(label, "OK" if await find_id() is None else "FAIL", f"id={oid}")
    except Exception as e:  # noqa: BLE001
        rec(label, "FAIL", e)


async def main(write: bool) -> int:
    mcp = build_server()
    tools = {t.name for t in await mcp.list_tools()}
    assert len(tools) >= 138, f"expected >=138 tools, got {len(tools)}"
    assert {"ise_version", "ise_check_surfaces", "ise_search_spec",
            "ise_openapi_call", "ise_ers_call", "ise_mnt_call"} <= tools
    print(f"server built: {len(tools)} tools\n")

    # ---------------- reads ----------------
    reads = ["ise_version", "ise_check_surfaces", "ise_deployment_nodes",
             "ise_session_counts", "ise_active_sessions", "ise_failure_reasons",
             "ise_openapi_groups", "ise_list_policy_sets", "ise_list_authorization_profiles",
             "ise_list_conditions", "ise_list_sgts", "ise_list_sgacls",
             "ise_list_egress_matrix", "ise_list_dacls", "ise_list_identity_groups",
             "ise_list_endpoint_groups", "ise_list_network_device_groups",
             "ise_list_network_devices", "ise_list_internal_users", "ise_list_endpoints",
             "ise_list_repositories", "ise_last_backup_status", "ise_installed_patches",
             "ise_license_status", "ise_system_summary", "ise_list_system_certs",
             "ise_list_trusted_certs", "ise_list_csrs", "ise_list_guest_types",
             "ise_list_sponsor_portals", "ise_list_sponsor_groups",
             "ise_list_profiler_profiles", "ise_list_admin_users",
             "ise_list_active_directory", "ise_list_external_radius_servers",
             "ise_list_custom_attributes", "ise_list_node_groups",
             "ise_list_tacacs_command_sets", "ise_list_tacacs_profiles",
             "ise_list_tacacs_external_servers", "ise_deviceadmin_command_sets"]
    for t in reads:
        await read_check(mcp, t)
    await read_check(mcp, "ise_get_node", hostname="ise")
    await read_check(mcp, "ise_node_services", hostname="ise")
    await read_check(mcp, "ise_list_policy_sets", kind="device-admin")
    await read_check(mcp, "ise_auth_status_by_mac", mac="AA:BB:CC:DD:EE:FF")
    await read_check(mcp, "ise_search_spec", query="endpoint", kind="paths")
    await read_check(mcp, "ise_get_definition", name="ERSEndPoint")
    # admin groups + guest users are version/sponsor gated -> SKIP, don't fail
    for t in ("ise_list_admin_groups", "ise_list_guest_users"):
        out = await call(mcp, t)
        rec(t, "OK" if not is_err(out) else "SKIP",
            "ok" if not is_err(out) else out[-55:])

    if not write:
        return report()

    # ---------------- write round-trips ----------------
    await roundtrip(mcp, "NAD", create_tool="ise_create_network_device",
                    create_args=dict(name="zzz_it_nad", ip="10.255.255.240",
                                     radius_shared_secret="verifyOnly123"),
                    list_tool="ise_list_network_devices", name_val="zzz_it_nad",
                    del_tool="ise_delete_network_device", del_key="device_id")

    # TACACS+ device admin (config plane; works without the node service enabled)
    await roundtrip(mcp, "TACACS command set",
                    create_tool="ise_create_tacacs_command_set",
                    create_args=dict(name="zzz_it_cmdset", permit_unmatched=False,
                                     commands=[{"grant": "PERMIT", "command": "show",
                                                "arguments": "*"}]),
                    list_tool="ise_list_tacacs_command_sets", name_val="zzz_it_cmdset",
                    del_tool="ise_delete_tacacs_command_set", del_key="cs_id")

    await roundtrip(mcp, "TACACS profile",
                    create_tool="ise_create_tacacs_profile",
                    create_args=dict(name="zzz_it_shell", privilege=7),
                    list_tool="ise_list_tacacs_profiles", name_val="zzz_it_shell",
                    del_tool="ise_delete_tacacs_profile", del_key="profile_id")

    used = {s.get("value") for s in as_list(safe(await call(mcp, "ise_list_sgts")))}
    val = next(v for v in range(3000, 5000) if v not in used)
    await roundtrip(mcp, "SGT", create_tool="ise_create_sgt",
                    create_args=dict(name="zzz_it_sgt", value=val),
                    list_tool="ise_list_sgts", name_val="zzz_it_sgt",
                    del_tool="ise_delete_sgt", del_key="sgt_id")

    await roundtrip(mcp, "SGACL", create_tool="ise_create_sgacl",
                    create_args=dict(body=json.dumps({"Sgacl": {"name": "zzz_it_sgacl",
                                     "ipVersion": "IPV4", "aclcontent": "permit ip"}})),
                    list_tool="ise_list_sgacls", name_val="zzz_it_sgacl",
                    del_tool="ise_delete_sgacl", del_key="sgacl_id")

    await roundtrip(mcp, "dACL", create_tool="ise_create_dacl",
                    create_args=dict(name="zzz_it_dacl", dacl="permit ip any any"),
                    list_tool="ise_list_dacls", name_val="zzz_it_dacl",
                    del_tool="ise_delete_dacl", del_key="dacl_id")

    await roundtrip(mcp, "authZ profile", create_tool="ise_create_authz_profile",
                    create_args=dict(name="zzz_it_authz", vlan="10"),
                    list_tool="ise_list_authorization_profiles", name_val="zzz_it_authz",
                    del_tool="ise_delete_authz_profile", del_key="profile_id")

    await roundtrip(mcp, "internal user", create_tool="ise_create_internal_user",
                    create_args=dict(name="zzz_it_user", password="McpVerify123!"),
                    list_tool="ise_list_internal_users", name_val="zzz_it_user",
                    del_tool="ise_delete_internal_user", del_key="user_id")

    await roundtrip(mcp, "identity group", create_tool="ise_create_identity_group",
                    create_args=dict(name="zzz_it_idg"),
                    list_tool="ise_list_identity_groups", name_val="zzz_it_idg",
                    del_tool="ise_delete_identity_group", del_key="group_id")

    await roundtrip(mcp, "endpoint group", create_tool="ise_create_endpoint_group",
                    create_args=dict(name="zzz_it_epg"),
                    list_tool="ise_list_endpoint_groups", name_val="zzz_it_epg",
                    del_tool="ise_delete_endpoint_group", del_key="group_id")

    await roundtrip(mcp, "NDG", create_tool="ise_create_network_device_group",
                    create_args=dict(name="Device Type#All Device Types#zzz_it_ndg"),
                    list_tool="ise_list_network_device_groups",
                    name_val="Device Type#All Device Types#zzz_it_ndg",
                    del_tool="ise_delete_network_device_group", del_key="group_id")

    await roundtrip(mcp, "endpoint", create_tool="ise_create_endpoint",
                    create_args=dict(mac="AA:BB:CC:DD:EE:F1", name="AA:BB:CC:DD:EE:F1"),
                    list_tool="ise_list_endpoints", list_args=dict(size=100),
                    name_val="AA:BB:CC:DD:EE:F1", del_tool="ise_delete_endpoint",
                    del_key="value")

    # update (PUT): create -> update -> confirm -> delete (SGT via generic
    # ers_update; internal user which strips the masked password)
    try:
        used2 = {s.get("value") for s in as_list(safe(await call(mcp, "ise_list_sgts")))}
        v2 = next(v for v in range(5000, 7000) if v not in used2)
        c = safe(await call(mcp, "ise_create_sgt", name="zzz_it_upd", value=v2, description="before"))
        sid = (c.get("id") if isinstance(c, dict) else None) or next(
            (s["id"] for s in as_list(safe(await call(mcp, "ise_list_sgts")))
             if s.get("name") == "zzz_it_upd"), None)
        await call(mcp, "ise_update_sgt", sgt_id=sid, description="after")
        got = safe(await call(mcp, "ise_get_sgt", sgt_id=sid))
        await call(mcp, "ise_delete_sgt", sgt_id=sid)
        ok = got.get("Sgt", {}).get("description") == "after"
        rec("SGT update (PUT)", "OK" if ok else "FAIL", f"id={sid}")
    except Exception as e:  # noqa: BLE001
        rec("SGT update (PUT)", "FAIL", e)

    # custom attribute + node group create/delete (name-keyed, OpenAPI)
    for label, create, cargs, list_tool, name, del_tool in [
        ("custom attribute", "ise_create_custom_attribute", dict(name="zzz_it_ca"),
         "ise_list_custom_attributes", "zzz_it_ca", "ise_delete_custom_attribute"),
        ("node group", "ise_create_node_group", dict(name="zzz_it_ng"),
         "ise_list_node_groups", "zzz_it_ng", "ise_delete_node_group"),
    ]:
        try:
            await call(mcp, del_tool, name=name)
            c = await call(mcp, create, **cargs)
            if is_err(c):
                rec(label, "FAIL", c[-60:])
                continue
            listed = as_list(safe(await call(mcp, list_tool)))
            made = any((i.get("name") or i.get("attributeName")) == name for i in listed)
            await call(mcp, del_tool, name=name)
            rec(label, "OK" if made else "FAIL", f"made={made}")
        except Exception as e:  # noqa: BLE001
            rec(label, "FAIL", e)

    # policy set + authZ rule (condition resolved by name)
    try:
        for p in as_list(safe(await call(mcp, "ise_list_policy_sets"))):
            if isinstance(p, dict) and p.get("name") == "zzz_it_ps":
                await call(mcp, "ise_delete_policy_set", policy_id=p["id"])
        c = safe(await call(mcp, "ise_create_policy_set", name="zzz_it_ps",
                            condition_name="Wired_MAB"))
        ps_id = (c.get("id") or (c.get("response", {}) or {}).get("id")) if isinstance(c, dict) else None
        if not ps_id:
            ps_id = next((p["id"] for p in as_list(safe(await call(mcp, "ise_list_policy_sets")))
                          if p.get("name") == "zzz_it_ps"), None)
        r = safe(await call(mcp, "ise_create_authz_rule", policy_id=ps_id,
                            name="zzz_it_rule", profiles=["PermitAccess"],
                            condition_name="Wired_802.1X"))
        az = as_list(safe(await call(mcp, "ise_get_authorization_rules", policy_id=ps_id)))
        made = any(x.get("rule", {}).get("name") == "zzz_it_rule" for x in az)
        await call(mcp, "ise_delete_policy_set", policy_id=ps_id)
        rec("policy set + authZ rule", "OK" if (ps_id and made) else "FAIL", f"ps={ps_id}")
    except Exception as e:  # noqa: BLE001
        rec("policy set + authZ rule", "FAIL", e)

    # trusted cert import (throwaway self-signed PEM)
    try:
        import subprocess
        pem = subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", "/dev/null", "-out", "-", "-days", "2", "-subj", "/CN=mcp-it-ca"],
            capture_output=True, text=True).stdout
        r = await call(mcp, "ise_import_trusted_cert", name="zzz_it_ca", cert_pem=pem)
        if is_err(r):
            rec("trusted cert import", "FAIL", r[-70:])
        else:
            tid = next((c["id"] for c in as_list(safe(await call(mcp, "ise_list_trusted_certs")))
                        if c.get("friendlyName") == "zzz_it_ca" or c.get("name") == "zzz_it_ca"), None)
            if tid:
                await call(mcp, "ise_delete_trusted_cert", cert_id=tid)
            rec("trusted cert import", "OK" if tid else "FAIL", f"id={tid}")
    except Exception as e:  # noqa: BLE001
        rec("trusted cert import", "FAIL", e)

    return report()


def report() -> int:
    print()
    counts = {"OK": 0, "SKIP": 0, "FAIL": 0}
    for label, status, detail in rows:
        counts[status] = counts.get(status, 0) + 1
        print(f"  [{status:4}] {label:32} {detail}")
    print(f"\n  {counts['OK']} OK, {counts['SKIP']} skip, {counts['FAIL']} fail")
    print("INTEGRATION TEST PASSED" if counts["FAIL"] == 0 else "INTEGRATION TEST FAILED")
    return 1 if counts["FAIL"] else 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="ISE MCP integration suite")
    ap.add_argument("--write", action="store_true",
                    help="also run create/verify/delete round-trips (lab only)")
    args = ap.parse_args()
    sys.exit(asyncio.run(main(args.write)))
