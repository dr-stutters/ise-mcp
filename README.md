# ise-mcp

MCP server for **Cisco Identity Services Engine (ISE)** — identity, NAC, and
TrustSec automation over ISE's REST APIs. Python 3.11+, [uv](https://docs.astral.sh/uv/),
FastMCP, async httpx.

Sibling to [`cml-mcp`](../CML_MCP) and [`firepower-mcp`](../Firepower_MCP); wired
into the CML MCP project as the `ise` server (see `CML_MCP/.mcp.json`), where the
**ise-engineer** agent drives its `mcp__ise__*` tools.

## Three API surfaces, one client

ISE spreads configuration and monitoring across three REST surfaces — all HTTP
**Basic auth**, no token dance. This server exposes all three through one client
plus dedicated tools:

| Surface | Port / base | Covers | Tools |
|---|---|---|---|
| **OpenAPI** | `443` `/api/…` | endpoints, TrustSec (SGT/SGACL/egress), policy sets, deployment/nodes | dedicated + `ise_openapi_call` |
| **ERS** | `443` `/ers/config/…` | network devices (NADs), internal users, identity/endpoint groups | dedicated + `ise_ers_call` |
| **MnT** | `443` `/admin/API/mnt/…` | read-only session monitoring, version, failure reasons (XML→dict) | dedicated + `ise_mnt_call` |

> **Enabling ERS:** ERS is **disabled by default**. Turn it on in the ISE GUI:
> *Administration → System → Settings → API Settings → API Service Settings →*
> **ERS (Read/Write)**. Until then ISE redirects ERS calls to `/admin/` and the
> ERS tools report "ERS not enabled". ERS is served on **port 443** (modern,
> ISE 3.1+); the legacy **9060** port also serves ERS but is deprecated and often
> off/firewalled — set `ISE_ERS_PORT=9060` only for older ISE. Call
> **`ise_check_surfaces`** first to see what actually answers.

## The OpenAPI surface is schema-driven

ISE 3.x publishes per-service OpenAPI (swagger) specs. Rather than hand-code
every endpoint, this server fetches, caches, and searches them:

- `ise_openapi_groups` — list the OpenAPI groups (23 on 3.4, 30 on 3.5).
- `ise_search_spec` — substring-search operations + schemas across every group.
- `ise_get_definition` — dump a schema's fields/enums.
- `ise_openapi_call` — call any endpoint (auto-handles the `X-CSRF-Token` fetch
  on writes).

So new/rare endpoints work without a code change — find the path + schema, then
call it.

## Dedicated tools (184)

Every read tool plus create→verify→delete round-trips for all writable resources
(NAD, endpoint, SGT, SGACL, internal user, dACL, authZ profile, device/identity/
endpoint groups, policy set + authZ rule) are verified end-to-end against live
ISE 3.4 and 3.5. Most objects also support **update (PUT)** (partial edits via a
GET-merge-PUT), and high-traffic lists (NADs, internal users, endpoints) take a
`filter`.

- **system / deployment** — `ise_version`, `ise_check_surfaces`,
  `ise_deployment_nodes`, `ise_get_node`, `ise_node_services`,
  `ise_enable_device_admin` (turn on the TACACS+ Device Admin persona)
- **device admin (TACACS+)** — TACACS command sets (list/get/create/delete) and
  shell profiles (privilege level) via ERS; device-admin policy sets + authZ rules
  via the OpenAPI Policy surface (`ise_*_policy_set` / `*_authz_rule_raw` with
  `kind="device-admin"`); NADs take a `tacacs_shared_secret`. See the TACACS+ note
  under Test.
- **endpoints** — list/get/create/update/delete endpoints (OpenAPI; create returns
  the id) + endpoint custom-attribute definitions (CRUD) + **bulk** create/update/
  delete by MAC list (`ise_bulk_*_endpoints`, e.g. mass MAB registration + static
  group assignment) — each returns an async task id to poll with `ise_get_task_status`
- **trustsec** — SGTs create/list/get/delete, SGACLs create/list/get/delete,
  egress matrix (SGT reads via OpenAPI; writes + SGACL/egress via ERS)
- **trustsec SXP / IP-SGT** — IP-SGT static mappings (list/create/delete, OpenAPI)
  and SXP peer connections (list/get/create/delete, ERS) as SPEAKER/LISTENER, plus
  SXP domains (`ise_list_sxp_vpns`) and the SXP static-binding view
  (`ise_list_sxp_local_bindings`) — how ISE advertises IP-SGT bindings to switches/
  firewalls (`sxpVersion` enum is `VERSION_1`..`VERSION_4`; a connection needs the
  hosting ISE node's hostname + IP)
- **authn depth** — Allowed Protocols services (list/get/create/delete + `_raw`; the
  convenience creator flips PAP/CHAP/MSCHAP/EAP-* on and auto-attaches ISE's default
  inner-method block for each enabled tunnelled EAP method - a block must be present
  iff its method is allowed) and Identity Source Sequences (list/get/create/delete;
  ordered `id_stores` + a certificate authentication profile)
- **ANC (adaptive network control)** — quarantine policies (create/list/delete)
  and apply/clear them on an endpoint by MAC (`ise_apply_anc`/`ise_clear_anc`);
  each issues a CoA, so a detection can contain an endpoint in seconds — the
  basis for rapid threat containment (SIEM/firewall → ISE → network)
- **policy (read)** — policy sets, authN/authZ rules, conditions
- **policy authoring** — authorization profiles (create with VLAN/dACL), downloadable
  ACLs, policy sets + authZ rules (condition resolved by name, e.g. `Wired_802.1X`)
- **sessions / monitoring (MnT)** — active session count/list, session by
  MAC/IP/username (clean "no active session" when idle), session counts summary,
  `ise_auth_status_by_mac` (recent auth attempts + pass/fail), `ise_recent_authentications`
  (deployment-wide recent-auth report), failure reasons
- **operations (day-2)** — repositories, last-backup status, installed patches,
  smart-licensing status, node groups, `ise_get_task_status` (poll any async task:
  bulk endpoint ops, certificate renew), and `ise_system_summary` (one-call
  version/nodes/license/patch/backup/sessions dashboard)
- **certificates** — system & trusted certificate inventory + management: generate
  CSR, import trusted cert, generate self-signed, delete certs/CSRs
- **guest / sponsor (ERS)** — guest types, sponsor portals & groups; guest *users*
  (create/delete, sponsor-authed); `ise_enable_sponsor_rest_access` toggles a sponsor
  group's REST-API permission (the gate for API guest provisioning)
- **posture (config)** — posture conditions (list/get/create-raw/delete by type),
  requirements, and posture policies (raw-first — bodies are large + type-specific),
  plus posture settings reads (general / reassessment / AUP / update)
- **profiler (ERS)** — endpoint profiling policies (compact list + get; raw create/delete)
- **rbac / admin** — admin users (ERS, 3.4+) and admin groups + admin-user create
  (OpenAPI Rbac Catalog, 3.5+; e.g. create an ERS-Admin account)
- **network_devices (ERS)** — onboard/list/get/delete NADs + device groups (CRUD)
- **identity (ERS)** — internal users (create/list/get/delete, group name→id
  resolved), identity & endpoint groups (create/list/delete), plus external
  identity reads: Active Directory join points and external RADIUS servers
- **deployment** — nodes, node-group CRUD (PSN session-failover groups)
- **raw / spec** — `ise_openapi_call`, `ise_ers_call`, `ise_mnt_call`,
  `ise_openapi_groups`, `ise_search_spec`, `ise_get_definition`

## Install

```bash
git clone https://github.com/dr-stutters/ise-mcp
cd ise-mcp && uv sync
```

## Configure

Copy `.env.example` to `.env` (gitignored) and set:

```ini
ISE_URL=https://198.18.129.30      # ISE admin/PAN node
ISE_USERNAME=admin
ISE_PASSWORD=C1sco12345
ISE_ERS_PORT=443                   # ERS port: 443 (modern) or legacy 9060
ISE_VERIFY_SSL=false               # lab certs are self-signed
ISE_TIMEOUT=60                     # seconds
ISE_RETRIES=2                      # retries on transient transport failures
```

Point `ISE_URL` at any ISE PAN; one server instance targets one deployment.

## How to use this

Run standalone (stdio): `uv run ise-mcp` — or register it in any MCP client:

```json
{ "mcpServers": { "ise": { "command": "uv",
    "args": ["run", "--directory", "/path/to/ise-mcp", "ise-mcp"] } } }
```

It's built to be driven by an AI agent. In the
[cml-mcp](https://github.com/dr-stutters/cml-mcp) lab suite it's wired in as the
`ise` server (plus an `ise35` instance pointed at a second deployment), owned by
the **ise-engineer** agent (tool prefix `mcp__ise__*`) — identity/NAC work in lab
requests fans out to it automatically, and the validated ISE NAC lab rebuilds
from that repo's `Custom Designs/ISE NAC Lab/` runbook + topology spec.
Standalone, just describe what you want:

> "Onboard the switch at 198.18.128.66 as a NAD with RADIUS secret ISEsecret123."

> "Create an authorization profile that assigns VLAN 100 and a dACL, and wire it
> into the wired-MAB policy set."

> "Who's authenticated right now, and why did aa:bb:cc:dd:ee:ff fail?"

Call **`ise_check_surfaces`** first — it reports which of the three surfaces
answer (and whether ERS is enabled) before anything else is attempted.

## Test

```bash
uv run pytest                                   # unit tests - no ISE needed
uv run python tests/smoke_test.py               # quick read-only live check
uv run python tests/integration_test.py         # full read-only suite (live)
uv run python tests/integration_test.py --write # + create/verify/delete round-trips
```

- **`tests/test_client_unit.py`** — 22 ISE-free unit tests (httpx `MockTransport`):
  XML→dict parsing, ERS `Location`-id extraction, the "ERS not enabled" `/admin/`
  redirect, error-message extraction, content-type dispatch, CSRF fetch+retry,
  transport-error wrapping + retry, `ers_list_all` paging, config loading, and
  spec search/get-definition. Runs anywhere — `ruff` + these run in CI on every
  push ([.github/workflows/ci.yml](.github/workflows/ci.yml)).
- **`tests/integration_test.py`** — drives every tool through the MCP layer against
  a live ISE. Read-only by default (safe anytime); `--write` adds
  create→verify→delete round-trips for all writable resources (NAD, SGT, SGACL,
  dACL, authZ profile, groups, internal user, endpoint, policy set + rule, trusted
  cert). Version/feature-gated tools (RBAC on 3.4, sponsor-gated guest users) are
  reported as skips, not failures.

Verified against **ISE 3.4.0.608** and **ISE 3.5.0.527** — all three surfaces
(OpenAPI, MnT, ERS-over-443) pass once ERS is enabled in API Settings.

**TACACS+ device admin — config plane validated:** command sets (permit-all + a
show/exit/enable read-only set), shell profiles (priv-lvl 15/1), a NAD with a
`tacacs_shared_secret`, and a full device-admin policy set (`kind="device-admin"`)
with two authZ rules were all created + read back live on ISE 3.5. Field notes:
device-admin authZ rules take `commands` (a list of command-set names) + `profile`
(a shell-profile name) and **require** a rule condition (no catch-all); the
`DEVICE:Device IP Address` attribute is illegal for the device-admin scope (use
`Device Type`); TACACS *profile* names allow only alphanumeric/underscore/space (no
hyphens). **Proven end-to-end** once the **Device Admin service** is enabled on the node
(ISE only answers TACACS+ on TCP 49 with it on): `test aaa` authenticates both a
priv-15 admin and a restricted operator; SSH logins show ISE driving the shell
privilege (15 vs 1) *and* per-command authorization (AAA debug shows `service=shell
priv-lvl=N` on exec + `AUTHOR/CMD PASS_ADD/FAIL` per command). Two field notes: (1)
differentiate users by **identity group** in the rule condition — conditioning only
on `DEVICE:Device Type` makes the rank-0 rule match everyone; (2) `ise_enable_device_admin`
sends the correct `NodeUpdateRequest`, but a **standalone** ISE node rejects the
persona change over the API (`Exception occurred while making REST call`) — enable it
in the GUI (Administration ▸ System ▸ Deployment ▸ *node* ▸ **Enable Device Admin
Service**).

**Posture + guest — config-side validated:** posture conditions/requirements/policies
and settings all read live on ISE 3.5; creates are raw-first (bodies are large and
per-type — file conditions, for instance, need a `FilePath` enum like `root` plus a
check-type-appropriate `Operator`). **The guest sponsor flow works end-to-end over
the API** (beating the usual "sponsors are GUI-only" assumption): create an internal
user in a sponsor identity group (e.g. `ALL_ACCOUNTS (default)`), grant the sponsor
group REST access (`ise_enable_sponsor_rest_access` — off by default, and the exact
gate for the 401 *"Sponsor does not have permission to access REST Apis"*), then
POST `/ers/config/guestuser` **as the sponsor** (a separate sponsor-cred client — the
admin-authed server always 401s here) with `guestType` + `portalId` +
`guestInfo` (omit `password` to auto-generate) + `guestAccessInfo` (`fromDate`/`toDate`
mandatory). Live: created a Contractor guest (`AWAITING_INITIAL_LOGIN`), read it back,
and deleted it as the sponsor. Live *posture assessment* and *CWA/BYOD* need a
posture-capable client (Windows/macOS Secure Client) — out of scope for Linux-only
CML endpoints.

**NAD-side NAC is validated too:** MAB (`Wired_MAB` → `PermitAccess`) authenticates
end-to-end against both 3.4 and 3.5 from a Catalyst 9000v access switch (NAD
onboarded + endpoint + authZ rule via these tools, auth confirmed on the switch and
in MnT on the patched 3.5 node). Gotcha worth knowing: the cat9000v auth-manager
RADIUS must source from a **front-panel global-table interface**, not the OOB
Mgmt-vrf port (IOSd RADIUS works over Mgmt-vrf and masks the problem); the
lightweight L2 sims (iosvl2, ioll2-xe) can't do MAB at all.

**AD-integrated 802.1X — both methods validated:** ISE 3.5 joined to a Windows AD
domain (ERS `activedirectory` create + `joinAllNodes`), then **PEAP-MSCHAPv2** (a
domain user against AD) **and EAP-TLS** (a CA-signed client cert, mutual TLS) both
authenticated end-to-end from a wpa_supplicant client through the cat9000v to ISE,
Authorized on the switch and passed in MnT. The EAP-TLS chain: CA cert →
`ise_import_trusted_cert` (client-auth trust) + ISE CSR → CA-signed → bound as the
EAP identity cert. Nice trick: point the Dot1X authN rule at the built-in
**`All_User_ID_Stores`** sequence — it already bundles the cert-auth profile
(→ EAP-TLS) + `All_AD_Join_Points` (→ PEAP/AD) + Internal Users, so one source
handles all methods. ERS join gotchas: `/joinAllNodes` (not `/join`, which wants a
node target) with `username`+`password` only — `domainName` is rejected; the
identity-sequence resource is `/ers/config/idstoresequence` (wrapper
`IdStoreSequence`, items `idSeqItem`).

**Enforcement, TrustSec & CoA validated:** dynamic authZ pushes a downloadable ACL
(`ise_create_dacl`) and a dynamic VLAN (`ise_create_authz_profile`) that the switch
applies and enforces; **TrustSec** assigns an SGT as a rule result and enforces an
SGACL (egress matrix `/ers/config/egressmatrixcell`) in the cat9000v hardware
(HW-Denied counters); **CoA** re-authorizes a live session in place (MnT
`/CoA/Reauth/{node}/{mac}/{reauthType}`, numeric reauthType) with no link bounce;
and **full CTS** — with the NAD's `trustsecsettings` device-auth set — has the
switch download the environment data + SGACL policy from ISE. Two quirks worth
noting: the CoA `dynamic-author` client must live in the same VRF/table as the
RADIUS source, and the ERS `trustsecsettings` schema misspells its fields
(`downlaod…`).

## Roadmap

- **pxGrid (phase 2)** — pxGrid is a cert-based pub/sub surface (WebSocket/STOMP,
  client certificate enrollment + approval) rather than Basic-auth REST, so it's
  a separate build: session/topic subscription, ANC (Adaptive Network Control)
  quarantine actions, and bulk session download. Not in v1.
- ~~Guest-user provisioning via a sponsor account~~ — **done** (sponsor-authed
  create/get/delete proven end-to-end; `ise_enable_sponsor_rest_access` unlocks it).
- Live posture assessment + CWA/BYOD flows (need a posture-capable OS client).

## Security notes

`.env` is gitignored — never commit credentials. Use a least-privilege ISE admin
(e.g. a dedicated ERS-Admin account, which these tools can create). TLS
verification is off by default for lab self-signed certs; set
`ISE_VERIFY_SSL=true` against a trusted CA.
