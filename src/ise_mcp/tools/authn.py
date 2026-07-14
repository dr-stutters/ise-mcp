"""Authentication policy depth: Allowed Protocols + Identity Source Sequences.

Both are **ERS** resources (writes need ERS enabled). Allowed Protocols is the
service referenced by an authentication rule that decides which EAP/PAP methods
are permitted; Identity Source Sequences are the ordered list of identity stores
an authentication rule falls through. Enabling a tunnelled EAP method (PEAP,
EAP-FAST, TEAP) requires its nested settings block, so the convenience creators
bake in ISE's default blocks; use the `_raw` creator for full control of the
inner-method knobs.
"""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from ..client import ISEClient
from ..spec import SpecCache
from . import dumps

_AP = "/ers/config/allowedprotocols"       # ERS AllowedProtocols
_IDSEQ = "/ers/config/idstoresequence"     # ERS IdStoreSequence

# ISE default nested EAP-method settings blocks (captured from "Default Network
# Access"). Sent whenever the matching method is allowed so ISE doesn't reject the
# create with "protocol is allowed but settings are missing".
_EAP_TLS = {"allowEapTlsAuthOfExpiredCerts": False,
            "eapTlsEnableStatelessSessionResume": False}
_PEAP = {"allowPeapEapMsChapV2": True, "allowPeapEapMsChapV2PwdChange": True,
         "allowPeapEapMsChapV2PwdChangeRetries": 1, "allowPeapEapGtc": True,
         "allowPeapEapGtcPwdChange": True, "allowPeapEapGtcPwdChangeRetries": 1,
         "allowPeapEapTls": True, "allowPeapEapTlsAuthOfExpiredCerts": False,
         "requireCryptobinding": False, "allowPeapV0": False}
_EAP_FAST = {"allowEapFastEapMsChapV2": True, "allowEapFastEapMsChapV2PwdChange": True,
             "allowEapFastEapMsChapV2PwdChangeRetries": 3, "allowEapFastEapGtc": True,
             "allowEapFastEapGtcPwdChange": True, "allowEapFastEapGtcPwdChangeRetries": 3,
             "allowEapFastEapTls": True, "allowEapFastEapTlsAuthOfExpiredCerts": False,
             "eapFastUsePacs": True, "eapFastUsePacsTunnelPacTtl": 90,
             "eapFastUsePacsTunnelPacTtlUnits": "DAYS",
             "eapFastUsePacsUseProactivePacUpdatePrecentage": 90,
             "eapFastUsePacsAllowAnonymProvisioning": False,
             "eapFastUsePacsAllowAuthenProvisioning": True,
             "eapFastUsePacsServerReturns": True, "eapFastUsePacsAcceptClientCert": False,
             "eapFastUsePacsAllowMachineAuthentication": True,
             "eapFastUsePacsMachinePacTtl": 1, "eapFastUsePacsMachinePacTtlUnits": "WEEKS",
             "eapFastUsePacsStatelessSessionResume": True,
             "eapFastUsePacsAuthorizationPacTtl": 1,
             "eapFastUsePacsAuthorizationPacTtlUnits": "HOURS",
             "eapFastEnableEAPChaining": False}
_EAP_TTLS = {"eapTtlsPapAscii": True, "eapTtlsChap": True, "eapTtlsMsChapV1": True,
             "eapTtlsMsChapV2": True, "eapTtlsEapMd5": True, "eapTtlsEapMsChapV2": True,
             "eapTtlsEapMsChapV2PwdChange": True, "eapTtlsEapMsChapV2PwdChangeRetries": 1}
_TEAP = {"allowTeapEapMsChapV2": True, "allowTeapEapMsChapV2PwdChange": True,
         "allowTeapEapMsChapV2PwdChangeRetries": 3, "allowTeapEapTls": True,
         "allowTeapEapTlsAuthOfExpiredCerts": False, "acceptClientCertDuringTunnelEst": True,
         "enableEapChaining": False, "allowDowngradeMsk": True}


def register(mcp: FastMCP, client: ISEClient, spec: SpecCache) -> None:
    # ------------------------------------------------------------------
    # Allowed Protocols
    # ------------------------------------------------------------------
    @mcp.tool()
    async def ise_list_allowed_protocols() -> str:
        """List Allowed Protocols services (ERS). Each decides which authentication
        methods (PAP/CHAP/MSCHAP/EAP-*) a matching authentication rule permits."""
        return dumps(await client.ers_list_all(_AP))

    @mcp.tool()
    async def ise_get_allowed_protocols(protocol_id: str) -> str:
        """Get one Allowed Protocols service by id (ERS) - includes the nested
        per-method (peap/eapFast/teap/eapTtls/eapTls) settings blocks."""
        return dumps(await client.ers("GET", f"{_AP}/{protocol_id}"))

    @mcp.tool()
    async def ise_create_allowed_protocols(
            name: str, *, allow_pap_ascii: bool = False, allow_chap: bool = False,
            allow_ms_chap_v1: bool = False, allow_ms_chap_v2: bool = False,
            allow_eap_md5: bool = False, allow_leap: bool = False,
            allow_eap_tls: bool = False, allow_eap_ttls: bool = False,
            allow_peap: bool = False, allow_eap_fast: bool = False,
            allow_teap: bool = False, process_host_lookup: bool = True,
            description: str = "") -> str:
        """Create an Allowed Protocols service (ERS); returns the new id.

        Flip the methods you want on; everything else defaults off. For any allowed
        tunnelled EAP method (PEAP/EAP-FAST/TEAP) ISE's default inner-method settings
        are sent automatically. Use ise_create_allowed_protocols_raw to control the
        inner knobs (PAC TTLs, EAP chaining, GTC/MSCHAP-in-tunnel, etc.).

        Args:
            name: service name.
            allow_*: enable that authentication method.
            process_host_lookup: honour MAB / host-lookup (default True).
            description: optional.
        """
        ap = {
            "name": name, "description": description,
            "processHostLookup": process_host_lookup,
            "allowPapAscii": allow_pap_ascii, "allowChap": allow_chap,
            "allowMsChapV1": allow_ms_chap_v1, "allowMsChapV2": allow_ms_chap_v2,
            "allowEapMd5": allow_eap_md5, "allowLeap": allow_leap,
            "allowEapTls": allow_eap_tls, "allowEapTtls": allow_eap_ttls,
            "allowEapFast": allow_eap_fast, "allowPeap": allow_peap,
            "allowTeap": allow_teap,
            "allowPreferredEapProtocol": False, "eapTlsLBit": False,
            "allowWeakCiphersForEap": False, "requireMessageAuth": False,
        }
        # A nested settings block must be present iff its method is allowed - ISE
        # rejects both "allowed but settings missing" and "not allowed but settings
        # not null". Attach ISE's default block for each enabled method.
        for enabled, key, block in (
                (allow_eap_tls, "eapTls", _EAP_TLS), (allow_peap, "peap", _PEAP),
                (allow_eap_fast, "eapFast", _EAP_FAST),
                (allow_eap_ttls, "eapTtls", _EAP_TTLS), (allow_teap, "teap", _TEAP)):
            if enabled:
                ap[key] = dict(block)
        return dumps(await client.ers("POST", _AP, json_body={"AllowedProtocols": ap}))

    @mcp.tool()
    async def ise_create_allowed_protocols_raw(body: str) -> str:
        """Create an Allowed Protocols service from a full JSON body
        ({'AllowedProtocols': {...}}); returns its id. ERS. Use this for full control
        of the nested peap/eapFast/teap/eapTtls/eapTls inner-method settings."""
        return dumps(await client.ers("POST", _AP, json_body=json.loads(body)))

    @mcp.tool()
    async def ise_delete_allowed_protocols(protocol_id: str) -> str:
        """Delete an Allowed Protocols service by id (ERS)."""
        return dumps(await client.ers("DELETE", f"{_AP}/{protocol_id}"))

    # ------------------------------------------------------------------
    # Identity Source Sequences
    # ------------------------------------------------------------------
    @mcp.tool()
    async def ise_list_identity_source_sequences() -> str:
        """List Identity Source Sequences (ERS) - the ordered identity stores an
        authentication rule falls through (e.g. Internal Users -> AD -> Guest)."""
        return dumps(await client.ers_list_all(_IDSEQ))

    @mcp.tool()
    async def ise_get_identity_source_sequence(seq_id: str) -> str:
        """Get one Identity Source Sequence by id (ERS)."""
        return dumps(await client.ers("GET", f"{_IDSEQ}/{seq_id}"))

    @mcp.tool()
    async def ise_create_identity_source_sequence(
            name: str, id_stores: list[str],
            cert_auth_profile: str = "Preloaded_Certificate_Profile",
            break_on_store_fail: bool = False, description: str = "") -> str:
        """Create an Identity Source Sequence (ERS); returns the new id.

        Args:
            id_stores: ordered list of identity-store names, e.g.
                ["Internal Users", "All_AD_Join_Points"]; order is assigned 1..n.
            cert_auth_profile: certificate authentication profile name (ERS-mandatory);
                defaults to the built-in "Preloaded_Certificate_Profile".
            break_on_store_fail: stop the sequence if a store is unreachable
                (default False - keep falling through).
            description: optional.
        """
        seq = {
            "name": name, "description": description,
            "idSeqItem": [{"idstore": s, "order": i}
                          for i, s in enumerate(id_stores, start=1)],
            "certificateAuthenticationProfile": cert_auth_profile,
            "breakOnStoreFail": break_on_store_fail,
        }
        return dumps(await client.ers("POST", _IDSEQ, json_body={"IdStoreSequence": seq}))

    @mcp.tool()
    async def ise_delete_identity_source_sequence(seq_id: str) -> str:
        """Delete an Identity Source Sequence by id (ERS)."""
        return dumps(await client.ers("DELETE", f"{_IDSEQ}/{seq_id}"))
