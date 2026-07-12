"""Async HTTP client for the Cisco ISE REST APIs.

ISE spreads its APIs across three surfaces, all HTTP Basic auth:
  - OpenAPI : https://<ise>/api/...            (port 443, JSON; ISE 3.x)
  - ERS     : https://<ise>/ers/config/...     (port 443 by default; ERS must be
              enabled in API Settings. Legacy port 9060 also serves ERS but is
              deprecated in ISE 3.x and often firewalled - override ISE_ERS_PORT
              to use it.)
  - MnT     : https://<ise>/admin/API/mnt/...   (port 443, returns XML)

There is no token dance (unlike FMC) - Basic auth on every call. OpenAPI writes
may require an X-CSRF-Token when CSRF checking is on; the client fetches one
lazily and retries. MnT XML is parsed to a dict.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit
from xml.etree import ElementTree as ET

import httpx

from .config import Settings


class ISEAPIError(Exception):
    def __init__(self, status_code: int, method: str, url: str, detail: str):
        self.status_code = status_code
        super().__init__(f"ISE API error {status_code} on {method} {url}: {detail}")


def _xml_to_dict(elem: ET.Element) -> Any:
    """Minimal XML element -> dict/str for MnT responses."""
    children = list(elem)
    if not children:
        return elem.text if (elem.text and elem.text.strip()) else (elem.attrib or None)
    out: dict[str, Any] = {}
    if elem.attrib:
        out.update({f"@{k}": v for k, v in elem.attrib.items()})
    for child in children:
        tag = child.tag.split("}")[-1]
        val = _xml_to_dict(child)
        if tag in out:
            if not isinstance(out[tag], list):
                out[tag] = [out[tag]]
            out[tag].append(val)
        else:
            out[tag] = val
    return out


class ISEClient:
    def __init__(self, settings: Settings):
        self.settings = settings
        parts = urlsplit(settings.base_url)
        self._ers_base = f"{parts.scheme}://{parts.hostname}:{settings.ers_port}"
        self._csrf: str | None = None
        self._http = httpx.AsyncClient(
            verify=settings.verify_ssl,
            timeout=settings.timeout,
            auth=httpx.BasicAuth(settings.username, settings.password),
            follow_redirects=True,
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    # ------------------------------------------------------------------
    # Low-level request with ISE error extraction
    # ------------------------------------------------------------------
    async def _request(self, method: str, url: str, *, headers=None, json_body=None,
                       params=None, raw_text=False, follow_redirects=None) -> Any:
        if params:
            params = {k: v for k, v in params.items() if v is not None}
        kwargs: dict[str, Any] = {}
        if follow_redirects is not None:
            kwargs["follow_redirects"] = follow_redirects
        resp = await self._http.request(method, url, headers=headers, json=json_body,
                                        params=params or None, **kwargs)
        # ERS bounces to /admin/ when the ERS API service is disabled.
        if resp.is_redirect and "/admin" in (resp.headers.get("location") or ""):
            raise ISEAPIError(
                resp.status_code, method.upper(), url,
                "redirected to /admin/ - the ERS API service is not enabled. "
                "Enable it in the ISE GUI: Administration > System > Settings > "
                "API Settings > API Service Settings > ERS (Read/Write).")
        if resp.status_code >= 400:
            detail = resp.text[:1500]
            try:
                err = resp.json()
                if isinstance(err, dict):
                    msg = (err.get("response") or {}).get("message") if isinstance(err.get("response"), dict) else None
                    ers = err.get("ERSResponse") or {}
                    msgs = ers.get("messages") if isinstance(ers, dict) else None
                    detail = msg or (msgs and msgs[0].get("title")) or err.get("message") or detail
                    if not isinstance(detail, str):
                        detail = json.dumps(detail)[:1500]
            except Exception:
                pass
            raise ISEAPIError(resp.status_code, method.upper(), url, detail)
        if raw_text:
            return resp.text
        if resp.status_code == 204 or not resp.content:
            return None
        ctype = resp.headers.get("content-type", "")
        if "json" in ctype:
            return resp.json()
        if "xml" in ctype:
            return _xml_to_dict(ET.fromstring(resp.content))
        return resp.text

    # ------------------------------------------------------------------
    # OpenAPI surface (port 443, /api/...)
    # ------------------------------------------------------------------
    async def openapi(self, method: str, path: str, *, json_body=None, params=None) -> Any:
        if not path.startswith("/"):
            path = "/" + path
        url = f"{self.settings.base_url}{path}"
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        try:
            return await self._request(method, url, headers=headers, json_body=json_body, params=params)
        except ISEAPIError as e:
            # Lazy CSRF: fetch a token and retry writes once.
            if e.status_code in (403, 400) and method.upper() in ("POST", "PUT", "DELETE", "PATCH") \
                    and "csrf" in str(e).lower():
                await self._fetch_csrf()
                headers["X-CSRF-Token"] = self._csrf or ""
                return await self._request(method, url, headers=headers, json_body=json_body, params=params)
            raise

    async def _fetch_csrf(self) -> None:
        resp = await self._http.get(
            f"{self.settings.base_url}/api/v1/deployment/node",
            headers={"X-CSRF-Token": "fetch", "Accept": "application/json"})
        self._csrf = resp.headers.get("X-CSRF-Token")

    # ------------------------------------------------------------------
    # ERS surface (port 443 by default; /ers/config/...). Legacy: port 9060.
    # ------------------------------------------------------------------
    async def ers(self, method: str, path: str, *, json_body=None, params=None) -> Any:
        if not path.startswith("/"):
            path = "/" + path
        url = f"{self._ers_base}{path}"
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        return await self._request(method, url, headers=headers, json_body=json_body,
                                   params=params, follow_redirects=False)

    async def ers_list_all(self, path: str, params=None) -> list[dict]:
        """Follow ERS SearchResult paging and return all resources."""
        params = dict(params or {})
        params.setdefault("size", 100)
        page = 1
        out: list[dict] = []
        while True:
            params["page"] = page
            data = await self.ers("GET", path, params=params)
            sr = (data or {}).get("SearchResult", {}) if isinstance(data, dict) else {}
            out.extend(sr.get("resources", []) or [])
            if not sr.get("nextPage"):
                break
            page += 1
        return out

    # ------------------------------------------------------------------
    # MnT surface (port 443, /admin/API/mnt/..., XML)
    # ------------------------------------------------------------------
    async def mnt(self, path: str) -> Any:
        if not path.startswith("/"):
            path = "/" + path
        url = f"{self.settings.base_url}/admin/API/mnt{path}"
        return await self._request("GET", url, headers={"Accept": "application/xml"})
