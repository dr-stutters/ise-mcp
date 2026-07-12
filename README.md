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

## Dedicated tools (108)

Every read tool plus create→verify→delete round-trips for all writable resources
(NAD, endpoint, SGT, SGACL, internal user, dACL, authZ profile, device/identity/
endpoint groups, policy set + authZ rule) are verified end-to-end against live
ISE 3.4 and 3.5.

- **system / deployment** — `ise_version`, `ise_check_surfaces`,
  `ise_deployment_nodes`, `ise_get_node`
- **endpoints** — list/get/create/delete endpoints (OpenAPI; create returns the id)
- **trustsec** — SGTs create/list/get/delete, SGACLs create/list/get/delete,
  egress matrix (SGT reads via OpenAPI; writes + SGACL/egress via ERS)
- **policy (read)** — policy sets, authN/authZ rules, conditions
- **policy authoring** — authorization profiles (create with VLAN/dACL), downloadable
  ACLs, policy sets + authZ rules (condition resolved by name, e.g. `Wired_802.1X`)
- **sessions / monitoring (MnT)** — active session count/list, session by
  MAC/IP/username (clean "no active session" when idle), session counts summary,
  `ise_auth_status_by_mac` (recent auth attempts + pass/fail), failure reasons
- **operations (day-2)** — repositories, last-backup status, installed patches,
  smart-licensing status, node groups, and `ise_system_summary` (one-call
  version/nodes/license/patch/backup/sessions dashboard)
- **certificates** — system & trusted certificate inventory + management: generate
  CSR, import trusted cert, generate self-signed, delete certs/CSRs
- **guest / sponsor (ERS)** — guest types, sponsor portals & groups (guest *users*
  need a sponsor account)
- **profiler (ERS)** — endpoint profiling policies (compact list + get; raw create/delete)
- **rbac / admin** — admin users (ERS, 3.4+) and admin groups + admin-user create
  (OpenAPI Rbac Catalog, 3.5+; e.g. create an ERS-Admin account)
- **network_devices (ERS)** — onboard/list/get/delete NADs + device groups (CRUD)
- **identity (ERS)** — internal users (create/list/get/delete, group name→id
  resolved), identity & endpoint groups (create/list/delete)
- **raw / spec** — `ise_openapi_call`, `ise_ers_call`, `ise_mnt_call`,
  `ise_openapi_groups`, `ise_search_spec`, `ise_get_definition`

## Configuration

Copy `.env.example` to `.env` (gitignored) and set:

```ini
ISE_URL=https://198.18.129.30      # ISE admin/PAN node
ISE_USERNAME=admin
ISE_PASSWORD=C1sco12345
ISE_ERS_PORT=443                   # ERS port: 443 (modern) or legacy 9060
ISE_VERIFY_SSL=false               # lab certs are self-signed
ISE_TIMEOUT=60                     # seconds
```

Point `ISE_URL` at any ISE PAN; one server instance targets one deployment.

## Run

```bash
uv run ise-mcp                     # stdio transport (for MCP clients)
```

## Tests

```bash
uv run pytest                                   # unit tests - no ISE needed
uv run python tests/smoke_test.py               # quick read-only live check
uv run python tests/integration_test.py         # full read-only suite (live)
uv run python tests/integration_test.py --write # + create/verify/delete round-trips
```

- **`tests/test_client_unit.py`** — 18 ISE-free unit tests (httpx `MockTransport`):
  XML→dict parsing, ERS `Location`-id extraction, the "ERS not enabled" `/admin/`
  redirect, error-message extraction, content-type dispatch, CSRF fetch+retry,
  `ers_list_all` paging, config loading, and spec search/get-definition. Runs
  anywhere, including CI.
- **`tests/integration_test.py`** — drives every tool through the MCP layer against
  a live ISE. Read-only by default (safe anytime); `--write` adds
  create→verify→delete round-trips for all writable resources (NAD, SGT, SGACL,
  dACL, authZ profile, groups, internal user, endpoint, policy set + rule, trusted
  cert). Version/feature-gated tools (RBAC on 3.4, sponsor-gated guest users) are
  reported as skips, not failures.

Verified against **ISE 3.4.0.608** and **ISE 3.5.0.527** — all three surfaces
(OpenAPI, MnT, ERS-over-443) pass once ERS is enabled in API Settings.

## Roadmap

- **pxGrid (phase 2)** — pxGrid is a cert-based pub/sub surface (WebSocket/STOMP,
  client certificate enrollment + approval) rather than Basic-auth REST, so it's
  a separate build: session/topic subscription, ANC (Adaptive Network Control)
  quarantine actions, and bulk session download. Not in v1.
- Guest-user provisioning via a sponsor account (guest *users* are sponsor-gated;
  guest types / sponsor portals & groups are already covered).
