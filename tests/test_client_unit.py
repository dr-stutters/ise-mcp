"""ISE-free unit tests for the client, config and spec cache.

No live ISE needed - httpx.MockTransport supplies canned responses, so these run
anywhere (CI included). Run: `uv run pytest`.
"""

from __future__ import annotations

import asyncio
import json
from xml.etree import ElementTree as ET

import httpx
import pytest

from ise_mcp.client import ISEAPIError, ISEClient, ISEConnectionError, _xml_to_dict
from ise_mcp.config import Settings, load_settings
from ise_mcp.spec import SpecCache


def run(coro):
    return asyncio.run(coro)


def _settings(ers_port: int = 443, retries: int = 2) -> Settings:
    return Settings(base_url="https://ise.example.com", username="admin",
                    password="pw", ers_port=ers_port, verify_ssl=False,
                    timeout=5, retries=retries)


def _client(handler, ers_port: int = 443, retries: int = 2) -> ISEClient:
    c = ISEClient(_settings(ers_port, retries))
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
# transport-error wrapping + retry
# --------------------------------------------------------------------------
def test_transport_error_wrapped_as_connection_error():
    calls = {"n": 0}

    def handler(_req):
        calls["n"] += 1
        raise httpx.ConnectError("connection refused")

    with pytest.raises(ISEConnectionError) as ei:
        run(_client(handler, retries=0).openapi("GET", "/api/v1/x"))
    assert ei.value.status_code == 0 and "ConnectError" in str(ei.value)
    assert calls["n"] == 1


def test_transient_transport_error_is_retried():
    calls = {"n": 0}

    def handler(_req):
        calls["n"] += 1
        if calls["n"] == 1:
            raise httpx.ConnectError("transient")
        return httpx.Response(200, json={"ok": True})

    assert run(_client(handler, retries=2).openapi("GET", "/api/v1/x")) == {"ok": True}
    assert calls["n"] == 2


def test_protocol_error_is_not_retried():
    calls = {"n": 0}

    def handler(_req):
        calls["n"] += 1
        raise httpx.RemoteProtocolError("illegal header line")

    with pytest.raises(ISEConnectionError):
        run(_client(handler, retries=2).openapi("GET", "/api/v1/x"))
    assert calls["n"] == 1


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
# ers_update: GET -> merge non-None changes -> PUT full object
# --------------------------------------------------------------------------
def test_ers_update_merges_and_puts():
    captured = {}

    def handler(req):
        if req.method == "GET":
            return httpx.Response(200, json={"Sgt": {
                "id": "x", "name": "Old", "value": 10, "description": "d"}})
        captured["put"] = json.loads(req.content)
        return httpx.Response(200, json={"UpdatedFieldsList": {}})

    run(_client(handler).ers_update("/ers/config/sgt", "x", "Sgt",
                                    {"name": "New", "description": None}))
    # name changed, description (None) left as-is, other fields preserved
    assert captured["put"] == {"Sgt": {"id": "x", "name": "New",
                                       "value": 10, "description": "d"}}


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


# --------------------------------------------------------------------------
# TACACS+ device admin (#24): deviceadmin + policy kind= + node enable
# --------------------------------------------------------------------------
import json as _json  # noqa: E402

from mcp.server.fastmcp import FastMCP  # noqa: E402

from ise_mcp.tools import deployment as _deployment  # noqa: E402
from ise_mcp.tools import deviceadmin as _deviceadmin  # noqa: E402
from ise_mcp.tools import network_devices as _netdev  # noqa: E402
from ise_mcp.tools import policy as _policy  # noqa: E402


def _reg(module, handler):
    c = _client(handler)
    m = FastMCP("t")
    module.register(m, c, SpecCache(c))
    return m


def _call(m, tool, **args):
    res = run(m.call_tool(tool, args))
    return res[0][0].text if isinstance(res, tuple) else res[0].text


def test_create_tacacs_command_set_body_and_id():
    seen = {}

    def handler(req):
        seen["path"], seen["method"] = req.url.path, req.method
        seen["body"] = _json.loads(req.content)
        return httpx.Response(201, headers={
            "Location": "https://ise.example.com/ers/config/tacacscommandsets/abc-123"})

    out = _call(_reg(_deviceadmin, handler), "ise_create_tacacs_command_set",
                name="TAC-CmdSet-ReadOnly", permit_unmatched=False,
                commands=[{"grant": "PERMIT", "command": "show", "arguments": "*"}])
    assert seen["path"].endswith("/ers/config/tacacscommandsets")
    cs = seen["body"]["TacacsCommandSets"]
    assert cs["name"] == "TAC-CmdSet-ReadOnly" and cs["permitUnmatched"] is False
    assert cs["commands"]["commandList"][0]["command"] == "show"
    assert _json.loads(out)["id"] == "abc-123"  # Location -> id


def test_create_tacacs_profile_sets_priv_lvl():
    seen = {}

    def handler(req):
        seen["body"] = _json.loads(req.content)
        return httpx.Response(201, headers={
            "Location": "https://ise.example.com/ers/config/tacacsprofile/p-9"})

    _call(_reg(_deviceadmin, handler), "ise_create_tacacs_profile",
          name="TAC_Shell_Priv15", privilege=15)
    attrs = seen["body"]["TacacsProfile"]["sessionAttributes"]["sessionAttributeList"]
    assert attrs == [{"type": "MANDATORY", "name": "priv-lvl", "value": "15"}]


def test_network_device_tacacs_settings_added_when_secret_given():
    seen = {}

    def handler(req):
        seen["body"] = _json.loads(req.content)
        return httpx.Response(201, headers={
            "Location": "https://ise.example.com/ers/config/networkdevice/nd-1"})

    _call(_reg(_netdev, handler), "ise_create_network_device", name="TAC-RTR",
          ip="198.18.128.68", radius_shared_secret="r", tacacs_shared_secret="TACkey123")
    nd = seen["body"]["NetworkDevice"]
    assert nd["tacacsSettings"]["sharedSecret"] == "TACkey123"
    assert nd["authenticationSettings"]["radiusSharedSecret"] == "r"


def test_network_device_no_tacacs_settings_by_default():
    seen = {}

    def handler(req):
        seen["body"] = _json.loads(req.content)
        return httpx.Response(201, headers={
            "Location": "https://ise.example.com/ers/config/networkdevice/nd-2"})

    _call(_reg(_netdev, handler), "ise_create_network_device", name="R", ip="1.1.1.1",
          radius_shared_secret="r")
    assert "tacacsSettings" not in seen["body"]["NetworkDevice"]


def test_policy_base_helper():
    assert _policy._base("device-admin").endswith("/device-admin")
    assert _policy._base("network-access").endswith("/network-access")
    with pytest.raises(ValueError):
        _policy._base("bogus")


def test_create_policy_set_device_admin_path_and_service():
    seen = {}

    def handler(req):
        # the condition-name lookup GET (no body) hits /condition first
        if req.method == "GET" and req.url.path.endswith("/condition"):
            return httpx.Response(200, json=[{"id": "c1", "name": "TAC_Devices"}])
        seen["path"] = req.url.path
        seen["body"] = _json.loads(req.content)
        return httpx.Response(200, json={"response": {"id": "ps-1"}})

    _call(_reg(_policy, handler), "ise_create_policy_set", name="TAC-DeviceAdmin",
          condition_name="TAC_Devices", kind="device-admin")
    assert "/device-admin/policy-set" in seen["path"]
    assert seen["body"]["serviceName"] == "Default Device Admin"


def test_enable_device_admin_noop_when_present():
    def handler(req):
        return httpx.Response(200, json={
            "hostname": "ise35", "roles": ["Standalone"],
            "services": ["Profiler", "Session", "DeviceAdmin"], "nodeStatus": "Connected"})

    out = _call(_reg(_deployment, handler), "ise_enable_device_admin", hostname="ise35")
    d = _json.loads(out)
    assert d["changed"] is False and "DeviceAdmin" in d["services"]


def test_enable_device_admin_put_body_is_roles_services_only(monkeypatch):
    seen = {"phase": "before"}

    async def _no_sleep(_secs):
        seen["phase"] = "after"  # next GET should report DeviceAdmin present

    monkeypatch.setattr(_deployment.asyncio, "sleep", _no_sleep)

    def handler(req):
        if req.method == "GET":
            services = (["Profiler", "Session", "DeviceAdmin"] if seen["phase"] == "after"
                        else ["Profiler", "Session"])
            return httpx.Response(200, json={
                "hostname": "ise35", "roles": ["Standalone"], "fqdn": "ise35.x",
                "ipAddress": "1.2.3.4", "services": services, "nodeStatus": "Connected"})
        seen["put"] = _json.loads(req.content)  # PUT
        return httpx.Response(200, json={})

    out = _call(_reg(_deployment, handler), "ise_enable_device_admin", hostname="ise35",
                wait_minutes=1)
    assert set(seen["put"]) == {"roles", "services"}  # no fqdn/ipAddress/nodeStatus
    assert seen["put"]["services"] == ["Profiler", "Session", "DeviceAdmin"]
    assert _json.loads(out)["changed"] is True


# --------------------------------------------------------------------------
# posture (#25) routing + guest sponsor REST-access toggle
# --------------------------------------------------------------------------
from ise_mcp.tools import guest as _guest  # noqa: E402
from ise_mcp.tools import posture as _posture  # noqa: E402


def test_posture_condition_paths_by_type():
    seen = {}

    def handler(req):
        seen.setdefault("paths", []).append((req.method, req.url.path))
        return httpx.Response(200, json={"response": []})

    m = _reg(_posture, handler)
    run(m.call_tool("ise_list_posture_conditions", {"condition_type": "file"}))
    run(m.call_tool("ise_list_posture_conditions", {"condition_type": "service"}))
    run(m.call_tool("ise_get_posture_condition",
                    {"condition_type": "file", "cond_id": "c1"}))
    paths = seen["paths"]
    assert ("GET", "/api/v1/posture/condition/file") in paths
    assert ("GET", "/api/v1/posture/condition/service") in paths
    assert ("GET", "/api/v1/posture/condition/file/c1") in paths


def test_posture_settings_validated():
    def handler(req):
        return httpx.Response(200, json={"response": {}})

    m = _reg(_posture, handler)
    run(m.call_tool("ise_get_posture_settings", {"setting": "reassessment"}))
    with pytest.raises(Exception):  # noqa: B017 - MCP wraps ValueError
        run(m.call_tool("ise_get_posture_settings", {"setting": "bogus"}))


def test_enable_sponsor_rest_access_sets_flag():
    seen = {}

    def handler(req):
        p = req.url.path
        if req.method == "GET" and p.endswith("/sponsorgroup"):
            return httpx.Response(200, json={"SearchResult": {"total": 1, "resources": [
                {"id": "sg-1", "name": "ALL_ACCOUNTS (default)"}]}})
        if req.method == "GET" and p.endswith("/sponsorgroup/sg-1"):
            return httpx.Response(200, json={"SponsorGroup": {
                "id": "sg-1", "name": "ALL_ACCOUNTS (default)",
                "otherPermissions": {"canDeleteGuestAccounts": True,
                                     "canAccessViaRest": False}}})
        seen["put"] = _json.loads(req.content)  # PUT
        return httpx.Response(200, json={"UpdatedFieldsList": {}})

    out = _call(_reg(_guest, handler), "ise_enable_sponsor_rest_access",
                group_name="ALL_ACCOUNTS (default)", enable=True)
    op = seen["put"]["SponsorGroup"]["otherPermissions"]
    assert op["canAccessViaRest"] is True and op["canDeleteGuestAccounts"] is True
    assert _json.loads(out)["canAccessViaRest"] is True


def test_enable_sponsor_rest_access_unknown_group():
    def handler(req):
        return httpx.Response(200, json={"SearchResult": {"total": 0, "resources": []}})
    with pytest.raises(Exception):  # noqa: B017
        _call(_reg(_guest, handler), "ise_enable_sponsor_rest_access", group_name="nope")


# --------------------------------------------------------------------------
# ANC (#30) — policy body + apply/clear operation shape
# --------------------------------------------------------------------------
from ise_mcp.tools import anc as _anc  # noqa: E402


def test_create_anc_policy_body_and_action():
    seen = {}

    def handler(req):
        seen["body"] = _json.loads(req.content)
        return httpx.Response(201, headers={
            "Location": "https://ise.example.com/ers/config/ancpolicy/anc-1"})

    out = _call(_reg(_anc, handler), "ise_create_anc_policy",
                name="ANC-Quarantine", action="QUARANTINE")
    p = seen["body"]["ErsAncPolicy"]
    assert p["name"] == "ANC-Quarantine" and p["actions"] == ["QUARANTINE"]
    assert _json.loads(out)["id"] == "anc-1"


def test_create_anc_policy_rejects_bad_action():
    with pytest.raises(Exception):  # noqa: B017 - MCP wraps ValueError
        _call(_reg(_anc, lambda _r: httpx.Response(200)),
              "ise_create_anc_policy", name="x", action="NUKE")


def test_apply_anc_operation_body():
    seen = {}

    def handler(req):
        seen["path"] = req.url.path
        seen["body"] = _json.loads(req.content)
        return httpx.Response(204)

    _call(_reg(_anc, handler), "ise_apply_anc",
          mac="AA:BB:CC:DD:EE:FF", policy_name="ANC-Quarantine")
    assert seen["path"].endswith("/ers/config/ancendpoint/apply")
    data = {d["name"]: d["value"]
            for d in seen["body"]["OperationAdditionalData"]["additionalData"]}
    assert data == {"macAddress": "AA:BB:CC:DD:EE:FF", "policyName": "ANC-Quarantine"}


def test_clear_anc_hits_clear_endpoint():
    seen = {}

    def handler(req):
        seen["path"] = req.url.path
        return httpx.Response(204)

    _call(_reg(_anc, handler), "ise_clear_anc", mac="A", policy_name="ANC-Quarantine")
    assert seen["path"].endswith("/ers/config/ancendpoint/clear")


# --------------------------------------------------------------------------
# TrustSec SXP + IP-SGT mappings (#32)
# --------------------------------------------------------------------------
from ise_mcp.tools import trustsec as _trustsec  # noqa: E402


def test_create_sxp_connection_body_and_id():
    seen = {}

    def handler(req):
        seen["path"], seen["method"] = req.url.path, req.method
        seen["body"] = _json.loads(req.content)
        return httpx.Response(201, headers={
            "Location": "https://ise.example.com/ers/config/sxpconnections/sxp-77"})

    out = _call(_reg(_trustsec, handler), "ise_create_sxp_connection",
                sxp_peer="10.50.0.2", ise_node="ise35", ise_node_ip="198.18.134.35")
    assert seen["path"].endswith("/ers/config/sxpconnections")
    conn = seen["body"]["ERSSxpConnection"]
    # verified live: sxpNode + ipAddress both required, version enum is VERSION_n
    assert conn["sxpPeer"] == "10.50.0.2"
    assert conn["sxpNode"] == "ise35" and conn["ipAddress"] == "198.18.134.35"
    assert conn["sxpMode"] == "SPEAKER" and conn["sxpVersion"] == "VERSION_4"
    assert conn["sxpVpn"] == "default" and conn["enabled"] is True
    assert _json.loads(out)["id"] == "sxp-77"  # Location -> id


def test_list_sxp_connections_hits_ers_path():
    seen = {}

    def handler(req):
        seen["path"] = req.url.path
        return httpx.Response(200, json={"SearchResult": {"resources": []}})

    _call(_reg(_trustsec, handler), "ise_list_sxp_connections")
    assert seen["path"].endswith("/ers/config/sxpconnections")


def test_create_ip_sgt_mapping_formats_sgt_and_defaults_domain():
    seen = {}

    def handler(req):
        seen["path"] = req.url.path
        seen["body"] = _json.loads(req.content)
        return httpx.Response(200, json={"id": "m-1"})

    _call(_reg(_trustsec, handler), "ise_create_ip_sgt_mapping",
          ip_host="10.40.0.10", sgt_name="Employees", sgt_value=4)
    assert seen["path"].endswith("/api/v1/trustsec/ip-sgt-mapping")
    # ISE wants the SGT as "Name (tag/0-padded-tag)" and a non-null domain list
    assert seen["body"]["ipHost"] == "10.40.0.10"
    assert seen["body"]["sgt"] == "Employees (4/0004)"
    assert seen["body"]["sgtDomains"] == ["default"]


# --------------------------------------------------------------------------
# AuthN policy depth: allowed protocols + identity source sequences (#33)
# --------------------------------------------------------------------------
from ise_mcp.tools import authn as _authn  # noqa: E402


def test_allowed_protocols_nested_block_present_only_when_method_enabled():
    seen = {}

    def handler(req):
        seen["path"], seen["body"] = req.url.path, _json.loads(req.content)
        return httpx.Response(201, headers={
            "Location": "https://ise.example.com/ers/config/allowedprotocols/ap-1"})

    out = _call(_reg(_authn, handler), "ise_create_allowed_protocols",
                name="EAP-TLS-only", allow_eap_tls=True, allow_ms_chap_v2=True)
    ap = seen["body"]["AllowedProtocols"]
    assert seen["path"].endswith("/ers/config/allowedprotocols")
    assert ap["allowEapTls"] is True and ap["allowMsChapV2"] is True and ap["allowPeap"] is False
    # ISE rejects both "allowed but settings missing" and "not allowed but settings
    # not null" -> the nested block exists iff its method is enabled.
    assert "eapTls" in ap
    assert not any(k in ap for k in ("peap", "eapFast", "eapTtls", "teap"))
    assert ap["requireMessageAuth"] is False  # mandatory scalar always sent
    assert _json.loads(out)["id"] == "ap-1"


def test_allowed_protocols_peap_attaches_default_block():
    seen = {}

    def handler(req):
        seen["body"] = _json.loads(req.content)
        return httpx.Response(201, headers={
            "Location": "https://ise.example.com/ers/config/allowedprotocols/ap-2"})

    _call(_reg(_authn, handler), "ise_create_allowed_protocols", name="peap",
          allow_peap=True)
    ap = seen["body"]["AllowedProtocols"]
    assert ap["allowPeap"] is True and ap["peap"]["allowPeapEapMsChapV2"] is True


def test_create_identity_source_sequence_orders_stores_and_defaults_cert_profile():
    seen = {}

    def handler(req):
        seen["path"], seen["body"] = req.url.path, _json.loads(req.content)
        return httpx.Response(201, headers={
            "Location": "https://ise.example.com/ers/config/idstoresequence/seq-1"})

    _call(_reg(_authn, handler), "ise_create_identity_source_sequence",
          name="seq", id_stores=["Internal Users", "All_AD_Join_Points"])
    seq = seen["body"]["IdStoreSequence"]
    assert seen["path"].endswith("/ers/config/idstoresequence")
    assert seq["idSeqItem"] == [{"idstore": "Internal Users", "order": 1},
                                {"idstore": "All_AD_Join_Points", "order": 2}]
    assert seq["certificateAuthenticationProfile"] == "Preloaded_Certificate_Profile"
    assert seq["breakOnStoreFail"] is False
