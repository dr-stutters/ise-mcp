"""Operational / day-2 tools (OpenAPI, read): repositories, backup status,
patches, licensing, node groups, and an aggregated system summary."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from ..client import ISEClient, ISEAPIError
from ..spec import SpecCache
from . import dumps


def register(mcp: FastMCP, client: ISEClient, spec: SpecCache) -> None:
    @mcp.tool()
    async def ise_list_repositories() -> str:
        """List configured repositories (for backups/patches)."""
        return dumps(await client.openapi("GET", "/api/v1/repository"))

    @mcp.tool()
    async def ise_get_repository(name: str) -> str:
        """Get one repository by name, including its config."""
        return dumps(await client.openapi("GET", f"/api/v1/repository/{name}"))

    @mcp.tool()
    async def ise_repository_files(name: str) -> str:
        """List files available in a repository."""
        return dumps(await client.openapi("GET", f"/api/v1/repository/{name}/files"))

    @mcp.tool()
    async def ise_last_backup_status() -> str:
        """Status of the most recent configuration backup."""
        return dumps(await client.openapi(
            "GET", "/api/v1/backup-restore/config/last-backup-status"))

    @mcp.tool()
    async def ise_installed_patches() -> str:
        """Installed patches and hot patches on the deployment."""
        out = {"patches": await client.openapi("GET", "/api/v1/patch")}
        try:
            out["hotPatches"] = await client.openapi("GET", "/api/v1/hotpatch")
        except ISEAPIError:
            pass
        return dumps(out)

    @mcp.tool()
    async def ise_license_status() -> str:
        """Smart licensing status: connection/registration state + tier states."""
        out = {}
        for key, path in (("smartState", "/api/v1/license/system/smart-state"),
                          ("tierState", "/api/v1/license/system/tier-state")):
            try:
                out[key] = await client.openapi("GET", path)
            except ISEAPIError as e:
                out[key] = f"error: {e}"
        return dumps(out)

    @mcp.tool()
    async def ise_list_node_groups() -> str:
        """List deployment node groups (PSN groups for session failover)."""
        return dumps(await client.openapi("GET", "/api/v1/deployment/node-group"))

    @mcp.tool()
    async def ise_system_summary() -> str:
        """One-call day-2 health dashboard: version, nodes, licensing, patches,
        last backup, and live session counts."""
        summary: dict = {}

        async def safe(key, coro, extract=None):
            try:
                r = await coro
                summary[key] = extract(r) if extract else r
            except Exception as e:  # noqa: BLE001 - summary is best-effort
                summary[key] = f"error: {str(e)[:80]}"

        await safe("version", client.mnt("/Version"),
                   lambda r: r.get("version") if isinstance(r, dict) else r)
        await safe("nodes", client.openapi("GET", "/api/v1/deployment/node"),
                   lambda r: [n.get("hostname") for n in (r.get("response", r) or [])]
                   if isinstance(r, dict) else r)
        await safe("smartLicensing", client.openapi("GET", "/api/v1/license/system/smart-state"),
                   lambda r: (r.get("response", r) if isinstance(r, dict) else r))
        await safe("installedPatch", client.openapi("GET", "/api/v1/patch"),
                   lambda r: r.get("patchVersion") if isinstance(r, dict) else r)
        await safe("lastBackup", client.openapi(
            "GET", "/api/v1/backup-restore/config/last-backup-status"),
                   lambda r: (r.get("response", r) if isinstance(r, dict) else r))
        await safe("activeSessions", client.mnt("/Session/ActiveCount"),
                   lambda r: r.get("count") if isinstance(r, dict) else r)
        return dumps(summary)
