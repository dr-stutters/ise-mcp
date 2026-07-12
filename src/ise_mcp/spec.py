"""Fetch, cache and search the ISE OpenAPI specs.

ISE splits its OpenAPI across ~23 groups. `/api/swagger-resources` enumerates
them; each group's OpenAPI 3.0 doc is at `/api/v3/api-docs?group=<name>`. We load
them all once and search their paths + component schemas - the fast way to
discover endpoints and models before hand-writing a request.
"""

from __future__ import annotations

import asyncio
from typing import Any

from .client import ISEClient


class SpecCache:
    def __init__(self, client: ISEClient):
        self._client = client
        self._groups: list[str] | None = None
        self._specs: dict[str, dict] = {}

    async def _ensure(self) -> None:
        if self._groups is not None:
            return
        res = await self._client.openapi("GET", "/api/swagger-resources")
        self._groups = [g["name"] for g in res]

        async def fetch(name: str):
            try:
                self._specs[name] = await self._client.openapi(
                    "GET", "/api/v3/api-docs", params={"group": name})
            except Exception:
                self._specs[name] = {}
        await asyncio.gather(*(fetch(n) for n in self._groups))

    @staticmethod
    def _schemas(spec: dict) -> dict:
        return (spec.get("components", {}) or {}).get("schemas", {}) or spec.get("definitions", {}) or {}

    async def groups(self) -> list[str]:
        await self._ensure()
        return list(self._groups or [])

    async def search(self, query: str, kind: str = "both", limit: int = 80) -> dict[str, Any]:
        await self._ensure()
        q = query.lower()
        out: dict[str, Any] = {}
        if kind in ("both", "paths"):
            paths = []
            for group, spec in self._specs.items():
                for path, methods in (spec.get("paths", {}) or {}).items():
                    for method, op in methods.items():
                        if method not in ("get", "post", "put", "patch", "delete"):
                            continue
                        summary = (op.get("summary") or op.get("description") or "").strip()
                        line = f"{method.upper():6s} {path}  [{group}]  {summary.splitlines()[0][:80] if summary else ''}"
                        if q in line.lower():
                            paths.append(line)
            out["paths"] = sorted(paths)[:limit]
        if kind in ("both", "definitions"):
            defs = []
            for group, spec in self._specs.items():
                for name in self._schemas(spec):
                    if q in name.lower():
                        defs.append(f"{name}  [{group}]")
            out["definitions"] = sorted(set(defs))[:limit]
        return out

    async def get_definition(self, name: str) -> dict[str, Any]:
        await self._ensure()
        for group, spec in self._specs.items():
            schemas = self._schemas(spec)
            hit = name if name in schemas else next(
                (n for n in schemas if n.lower() == name.lower()), None)
            if hit:
                d = schemas[hit]
                props = {}
                for pname, pv in (d.get("properties") or {}).items():
                    ref = pv.get("$ref", "").split("/")[-1]
                    if pv.get("type") == "array":
                        it = pv.get("items", {})
                        ref = "[" + (it.get("$ref", "").split("/")[-1] or it.get("type", "?")) + "]"
                    entry: dict[str, Any] = {"type": pv.get("type") or ref or "?"}
                    if "enum" in pv:
                        entry["enum"] = pv["enum"]
                    if pv.get("description"):
                        entry["description"] = pv["description"][:140]
                    props[pname] = entry
                return {"name": hit, "group": group, "required": d.get("required"), "properties": props}
        return {"error": f"schema '{name}' not found in any OpenAPI group"}
