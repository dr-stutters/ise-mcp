"""Smoke test: drive the ISE MCP tool layer against a live ISE.

Read-only by default. Requires a .env (ISE_URL/ISE_USERNAME/ISE_PASSWORD)
pointing at a reachable ISE. Run: `uv run python tests/smoke_test.py`

Verified against ISE 3.4.0.608 (198.18.129.30) and ISE 3.5.0.527
(198.18.134.35). The OpenAPI + MnT tools work on both; ERS (port 9060) is
firewalled off in those deployments, so ERS tools are reported as skipped
rather than failing the run.
"""

from __future__ import annotations

import asyncio
import json

from ise_mcp.server import build_server


async def call(mcp, tool, /, **args) -> str:
    result = await mcp.call_tool(tool, args)
    if isinstance(result, tuple):
        result = result[0]
    parts = []
    for block in result:
        parts.append(getattr(block, "text", str(block)))
    return "\n".join(parts)


async def main() -> None:
    mcp = build_server()
    tools = {t.name for t in await mcp.list_tools()}
    assert {"ise_version", "ise_deployment_nodes", "ise_list_sgts",
            "ise_search_spec", "ise_get_definition", "ise_openapi_call",
            "ise_ers_call", "ise_mnt_call", "ise_list_network_devices"} <= tools, \
        "core tools missing"
    print(f"[ok] server built, {len(tools)} tools registered")

    # --- MnT surface (443) ---
    ver = json.loads(await call(mcp, "ise_version"))
    version = ver.get("product", {}).get("version", ver)
    print(f"[ok] ise_version -> {version}")

    surf = json.loads(await call(mcp, "ise_check_surfaces"))
    print(f"[ok] ise_check_surfaces -> {surf}")

    sc = await call(mcp, "ise_active_session_count")
    print(f"[ok] ise_active_session_count -> {sc[:120].splitlines()[0]}")

    # --- OpenAPI surface (443) ---
    nodes = json.loads(await call(mcp, "ise_deployment_nodes"))
    resp = nodes.get("response", nodes)
    names = [n.get("hostname") for n in resp] if isinstance(resp, list) else resp
    print(f"[ok] ise_deployment_nodes -> {names}")

    def as_list(obj):
        if isinstance(obj, list):
            return obj
        return obj.get("response", obj) if isinstance(obj, dict) else obj

    sgt_resp = as_list(json.loads(await call(mcp, "ise_list_sgts")))
    print(f"[ok] ise_list_sgts -> {len(sgt_resp) if isinstance(sgt_resp, list) else '?'} SGTs")

    pr = as_list(json.loads(await call(mcp, "ise_list_policy_sets")))
    print(f"[ok] ise_list_policy_sets -> {len(pr) if isinstance(pr, list) else '?'} policy sets")

    eps = json.loads(await call(mcp, "ise_list_endpoints", size=5))
    print(f"[ok] ise_list_endpoints(size=5) -> keys {list(eps)[:4]}")

    # --- Spec search (OpenAPI docs) ---
    groups = json.loads(await call(mcp, "ise_openapi_groups"))
    print(f"[ok] ise_openapi_groups -> {len(groups)} groups")

    search = json.loads(await call(mcp, "ise_search_spec", query="security-groups", kind="paths"))
    assert search.get("paths"), "spec search returned no paths"
    print(f"[ok] ise_search_spec('security-groups') -> {len(search['paths'])} paths")

    # --- ERS surface (9060) - best-effort (firewalled in some deployments) ---
    try:
        raw = await call(mcp, "ise_list_network_devices")
        ers = json.loads(raw)
        n = ers if isinstance(ers, list) else ers.get("SearchResult", {}).get("resources", ers)
        print(f"[ok] ise_list_network_devices -> {len(n) if isinstance(n, list) else ers}")
    except Exception as e:
        print(f"[skip] ise_list_network_devices -> ERS unreachable (port 9060): {str(e)[:80]}")

    print("\nSMOKE TEST PASSED")


if __name__ == "__main__":
    asyncio.run(main())
