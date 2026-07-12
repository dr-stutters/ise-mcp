"""ISE-free unit tests for the client, config and spec cache.

No live ISE needed - httpx.MockTransport supplies canned responses, so these run
anywhere (CI included). Run: `uv run pytest`.
"""

from __future__ import annotations

import asyncio
from xml.etree import ElementTree as ET

import httpx
import pytest

from ise_mcp.client import ISEClient, ISEAPIError, _xml_to_dict
from ise_mcp.config import Settings, load_settings
from ise_mcp.spec import SpecCache


def run(coro):
    return asyncio.run(coro)


def _settings(ers_port: int = 443) -> Settings:
    return Settings(base_url="https://ise.example.com", username="admin",
                    password="pw", ers_port=ers_port, verify_ssl=False, timeout=5)


def _client(handler, ers_port: int = 443) -> ISEClient:
    c = ISEClient(_settings(ers_port))
    c._http = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        auth=httpx.BasicAuth("admin", "pw"), follow_redirects=True)
    return c


# --------------------------------------------------------------------------
# _xml_to_dict (MnT XML parsing)
# --------------------------------------------------------------------------
def test_xml_to_dict_basic():
    d = _xml_to_dict(ET.fromstring('<product name="ISE"><version>3.5.0</version></product>'))
    assert d == {"@name": "ISE", "version": "3.5.0"}


def test_xml_to_dict_repeated_tags_become_list():
    d = _xml_to_dict(ET.fromstring("<list><item>a</item><item>b</item></list>"))
    assert d == {"item": ["a", "b"]}


# --------------------------------------------------------------------------
# _ers_base construction (443 default vs legacy 9060)
# --------------------------------------------------------------------------
def test_ers_base_default_443():
    assert ISEClient(_settings(443))._ers_base == "https://ise.example.com:443"


def test_ers_base_legacy_9060():
    assert ISEClient(_settings(9060))._ers_base == "https://ise.example.com:9060"


# --------------------------------------------------------------------------
# ERS create -> Location header id extraction
# --------------------------------------------------------------------------
def test_ers_create_returns_location_id():
    def handler(_req):
        return httpx.Response(201, headers={
            "Location": "https://ise.example.com/ers/config/sgt/abc-123/"})
    r = run(_client(handler).ers("POST", "/ers/config/sgt", json_body={}))
    assert r == {"created": True, "id": "abc-123",
                 "location": "https://ise.example.com/ers/config/sgt/abc-123/"}


# --------------------------------------------------------------------------
# ERS "not enabled" redirect detection
# --------------------------------------------------------------------------
def test_ers_redirect_to_admin_raises_not_enabled():
    def handler(_req):
        return httpx.Response(302, headers={"location": "/admin/"})
    with pytest.raises(ISEAPIError) as ei:
        run(_client(handler).ers("GET", "/ers/config/sgt"))
    assert "not enabled" in str(ei.value)


# --------------------------------------------------------------------------
# ISE error message extraction (ERS + OpenAPI shapes)
# --------------------------------------------------------------------------
def test_error_extraction_ers_messages():
    def handler(_req):
        return httpx.Response(400, json={"ERSResponse": {"messages": [{"title": "bad name"}]}})
    with pytest.raises(ISEAPIError) as ei:
        run(_client(handler).ers("POST", "/ers/config/sgt", json_body={}))
    assert ei.value.status_code == 400 and "bad name" in str(ei.value)


def test_error_extraction_openapi_response_message():
    def handler(_req):
        return httpx.Response(400, json={"response": {"message": "Condition property is required"}})
    with pytest.raises(ISEAPIError) as ei:
        run(_client(handler).openapi("POST", "/api/v1/policy/network-access/policy-set", json_body={}))
    assert "Condition property is required" in str(ei.value)


# --------------------------------------------------------------------------
# content-type dispatch: JSON / XML / 204
# --------------------------------------------------------------------------
def test_json_response_parsed():
    def handler(_req):
        return httpx.Response(200, json={"hello": "world"})
    assert run(_client(handler).openapi("GET", "/api/v1/x")) == {"hello": "world"}


def test_204_returns_none():
    def handler(_req):
        return httpx.Response(204)
    assert run(_client(handler).openapi("DELETE", "/api/v1/x")) is None


def test_mnt_xml_parsed_to_dict():
    def handler(req):
        assert req.url.path == "/admin/API/mnt/Version"
        return httpx.Response(200, content=b'<product><version>3.5.0</version></product>',
                              headers={"content-type": "application/xml"})
    assert run(_client(handler).mnt("/Version")) == {"version": "3.5.0"}


# --------------------------------------------------------------------------
# CSRF: 403 with "csrf" -> fetch token -> retry write with X-CSRF-Token
# --------------------------------------------------------------------------
def test_csrf_fetch_and_retry_on_403():
    state = {"posts": 0}

    def handler(req):
        if req.method == "GET" and req.url.path == "/api/v1/deployment/node":
            return httpx.Response(200, json={}, headers={"X-CSRF-Token": "tok123"})
        if req.method == "POST":
            state["posts"] += 1
            if state["posts"] == 1:
                return httpx.Response(403, json={"response": {"message": "CSRF token required"}})
            assert req.headers.get("X-CSRF-Token") == "tok123"
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(404)

    r = run(_client(handler).openapi("POST", "/api/v1/endpoint", json_body={}))
    assert r == {"ok": True} and state["posts"] == 2


# --------------------------------------------------------------------------
# ers_list_all follows SearchResult.nextPage
# --------------------------------------------------------------------------
def test_ers_list_all_paginates():
    def handler(req):
        page = req.url.params.get("page")
        if page == "1":
            return httpx.Response(200, json={"SearchResult": {
                "resources": [{"id": "1"}], "nextPage": {"href": "x?page=2"}}})
        return httpx.Response(200, json={"SearchResult": {"resources": [{"id": "2"}]}})
    out = run(_client(handler).ers_list_all("/ers/config/sgt"))
    assert [r["id"] for r in out] == ["1", "2"]


# --------------------------------------------------------------------------
# config loading
# --------------------------------------------------------------------------
def test_load_settings_adds_scheme_and_reads_port(monkeypatch):
    monkeypatch.setattr("ise_mcp.config.load_dotenv", lambda *a, **k: None)
    monkeypatch.setenv("ISE_URL", "ise.example.com")
    monkeypatch.setenv("ISE_USERNAME", "admin")
    monkeypatch.setenv("ISE_PASSWORD", "pw")
    monkeypatch.setenv("ISE_ERS_PORT", "443")
    s = load_settings()
    assert s.base_url == "https://ise.example.com" and s.ers_port == 443 and s.verify_ssl is False


def test_load_settings_missing_url_raises(monkeypatch):
    monkeypatch.setattr("ise_mcp.config.load_dotenv", lambda *a, **k: None)
    monkeypatch.delenv("ISE_URL", raising=False)
    monkeypatch.delenv("ISE_HOST", raising=False)
    with pytest.raises(RuntimeError):
        load_settings()


# --------------------------------------------------------------------------
# spec search / get_definition against a canned OpenAPI doc (no network)
# --------------------------------------------------------------------------
def _canned_spec_cache() -> SpecCache:
    sc = SpecCache(ISEClient(_settings()))
    sc._groups = ["Endpoints"]
    sc._specs = {"Endpoints": {
        "paths": {"/api/v1/endpoint": {
            "get": {"summary": "Get all endpoints"},
            "post": {"summary": "Create endpoint"}}},
        "components": {"schemas": {
            "ERSEndPoint": {"required": ["mac"], "properties": {"mac": {"type": "string"}}}}},
    }}
    return sc


def test_spec_search_paths_and_definitions():
    res = run(_canned_spec_cache().search("endpoint", "both"))
    assert any("/api/v1/endpoint" in p for p in res["paths"])
    assert "ERSEndPoint  [Endpoints]" in res["definitions"]


def test_spec_get_definition_case_insensitive():
    d = run(_canned_spec_cache().get_definition("ersendpoint"))
    assert d["name"] == "ERSEndPoint" and d["required"] == ["mac"]
    assert d["properties"]["mac"]["type"] == "string"


def test_spec_get_definition_missing():
    d = run(_canned_spec_cache().get_definition("NoSuchSchema"))
    assert "error" in d
