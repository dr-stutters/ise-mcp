"""Certificate tools (OpenAPI). Inventory reads (system/trusted/CSR) plus
management: generate a CSR, generate a self-signed cert, import a trusted cert,
and delete certs/CSRs."""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from ..client import ISEClient
from ..spec import SpecCache
from . import dumps

_CSR = "/api/v1/certs/certificate-signing-request"
_SYS = "/api/v1/certs/system-certificate"
_TRUST = "/api/v1/certs/trusted-certificate"


def register(mcp: FastMCP, client: ISEClient, spec: SpecCache) -> None:
    async def _default_host() -> str:
        nodes = await client.openapi("GET", "/api/v1/deployment/node")
        lst = nodes.get("response", nodes) if isinstance(nodes, dict) else nodes
        return lst[0]["hostname"] if isinstance(lst, list) and lst else "ise"

    @mcp.tool()
    async def ise_list_system_certs(hostname: str | None = None) -> str:
        """List a node's system (identity) certificates.

        Args:
            hostname: the node hostname; defaults to the first deployment node.
        """
        host = hostname or await _default_host()
        return dumps(await client.openapi(
            "GET", f"/api/v1/certs/system-certificate/{host}"))

    @mcp.tool()
    async def ise_get_system_cert(cert_id: str, hostname: str | None = None) -> str:
        """Get one system certificate by id (with node hostname)."""
        host = hostname or await _default_host()
        return dumps(await client.openapi(
            "GET", f"/api/v1/certs/system-certificate/{host}/{cert_id}"))

    @mcp.tool()
    async def ise_list_trusted_certs() -> str:
        """List certificates in the trusted-certificate store."""
        return dumps(await client.openapi("GET", "/api/v1/certs/trusted-certificate"))

    @mcp.tool()
    async def ise_get_trusted_cert(cert_id: str) -> str:
        """Get one trusted certificate by id."""
        return dumps(await client.openapi(
            "GET", f"/api/v1/certs/trusted-certificate/{cert_id}"))

    @mcp.tool()
    async def ise_list_csrs() -> str:
        """List pending certificate signing requests (CSRs)."""
        return dumps(await client.openapi("GET", _CSR))

    # ---- certificate management (writes) ----
    @mcp.tool()
    async def ise_generate_csr(common_name: str, hostname: str | None = None,
                               used_for: str = "MULTI-USE", key_length: str = "2048",
                               key_type: str = "RSA", digest: str = "SHA-256",
                               san_dns: list[str] | None = None) -> str:
        """Generate a certificate signing request (CSR).

        Args:
            common_name: subject CN.
            hostname: node to generate on (defaults to the first deployment node).
            used_for: 'MULTI-USE' (default), 'ADMIN', 'EAP-AUTH', 'PORTAL',
                'PXGRID', 'SAML', 'DTLS-AUTH'.
            key_length: '2048' (default), '4096', etc.
            key_type: 'RSA' (default) or 'ECDSA'.
            digest: signature digest, e.g. 'SHA-256'.
            san_dns: optional list of DNS SANs.
        """
        host = hostname or await _default_host()
        body: dict = {"digestType": digest, "keyLength": key_length,
                      "keyType": key_type, "usedFor": used_for,
                      "hostnames": [host], "subjectCommonName": common_name,
                      "allowWildCardCert": False}
        if san_dns:
            body["sanDNS"] = san_dns
        return dumps(await client.openapi("POST", _CSR, json_body=body))

    @mcp.tool()
    async def ise_generate_csr_raw(body: str) -> str:
        """Generate a CSR from a full JSON body (see ise_get_definition 'CSRRequest')."""
        return dumps(await client.openapi("POST", _CSR, json_body=json.loads(body)))

    @mcp.tool()
    async def ise_delete_csr(cert_id: str, hostname: str | None = None) -> str:
        """Delete a pending CSR by id (with node hostname)."""
        host = hostname or await _default_host()
        return dumps(await client.openapi("DELETE", f"{_CSR}/{host}/{cert_id}"))

    @mcp.tool()
    async def ise_import_trusted_cert(name: str, cert_pem: str, description: str = "",
                                      trust_for_ise_auth: bool = True,
                                      trust_for_client_auth: bool = False) -> str:
        """Import a certificate into the trusted-certificate store.

        Args:
            name: friendly name for the trusted cert.
            cert_pem: the certificate in PEM format.
            description: optional.
            trust_for_ise_auth: trust for infrastructure auth within ISE (default
                true). Note: ISE rejects enabling client auth without ISE auth.
            trust_for_client_auth: trust for client/endpoint auth (default false).
        """
        body = {"name": name, "description": description, "data": cert_pem,
                "allowBasicConstraintCAFalse": True, "allowOutOfDateCert": True,
                "allowSHA1Certificates": True, "trustForIseAuth": trust_for_ise_auth,
                "trustForClientAuth": trust_for_client_auth,
                "trustForCertificateBasedAdminAuth": False,
                "trustForCiscoServicesAuth": False, "validateCertificateExtensions": False}
        return dumps(await client.openapi("POST", f"{_TRUST}/import", json_body=body))

    @mcp.tool()
    async def ise_delete_trusted_cert(cert_id: str) -> str:
        """Delete a trusted certificate by id."""
        return dumps(await client.openapi("DELETE", f"{_TRUST}/{cert_id}"))

    @mcp.tool()
    async def ise_delete_system_cert(cert_id: str, hostname: str | None = None) -> str:
        """Delete a system certificate by id (with node hostname)."""
        host = hostname or await _default_host()
        return dumps(await client.openapi("DELETE", f"{_SYS}/{host}/{cert_id}"))

    @mcp.tool()
    async def ise_generate_selfsigned_cert(common_name: str, hostname: str | None = None,
                                           used_for: str = "portal", days: int = 365,
                                           key_length: str = "2048", key_type: str = "RSA",
                                           portal_group_tag: str | None = None) -> str:
        """Generate a self-signed system (identity) certificate on a node.

        Invasive: installs a cert on the node. Won't replace an existing cert
        (allowReplacementOfCertificates is false), and allows non-resolvable SANs
        so it works in a lab.

        Args:
            common_name: subject CN.
            hostname: node to install on (defaults to the first deployment node).
            used_for: role - 'portal' (default), 'admin', 'eap', 'radius',
                'pxgrid', 'saml', or 'tacacs'. Note: the admin/eap/radius roles
                already have a cert on every node, so those fail unless replaced.
            days: validity in days.
            key_length: '2048' (default), '4096'. key_type: 'RSA' or 'ECDSA'.
            portal_group_tag: required when used_for='portal' (the portal tag).
        """
        host = hostname or await _default_host()
        roles = {r: (r == used_for) for r in
                 ("admin", "eap", "radius", "portal", "pxgrid", "saml", "tacacs")}
        body = {"hostName": host, "subjectCommonName": common_name,
                "keyLength": key_length, "keyType": key_type, "digestType": "SHA-256",
                "expirationTTL": days, "expirationTTLUnit": "days",
                "allowExtendedValidity": True, "allowReplacementOfCertificates": False,
                "allowReplacementOfPortalGroupTag": True,
                "allowPortalTagTransferForSameSubject": True,
                "allowRoleTransferForSameSubject": True,
                "allowSanDnsBadName": True, "allowSanDnsNonResolvable": True, **roles}
        if portal_group_tag:
            body["portalGroupTag"] = portal_group_tag
        return dumps(await client.openapi(
            "POST", f"{_SYS}/generate-selfsigned-certificate", json_body=body))

    @mcp.tool()
    async def ise_generate_selfsigned_cert_raw(body: str) -> str:
        """Generate a self-signed system certificate from a full JSON body.

        Invasive (installs an identity cert on the node). See ise_get_definition
        'GenerateSelfsignedCertRequest' for the (many) required fields.
        """
        return dumps(await client.openapi(
            "POST", f"{_SYS}/generate-selfsigned-certificate", json_body=json.loads(body)))
