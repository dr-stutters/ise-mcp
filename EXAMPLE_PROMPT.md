# Example prompts — ISE MCP

Copy any prompt below to an AI agent (Claude Code, Claude Desktop, …) with the
**`ise`** MCP server connected. Describe the outcome — the agent picks the tools.
Names in `code` show which tools each prompt exercises.

**Always start with:** *"Check which ISE surfaces are reachable."* → `ise_check_surfaces`
(reports whether OpenAPI / ERS / MnT answer; ERS is off by default until you enable
it in the ISE GUI).

## One end-to-end scenario

> **"Onboard the Catalyst switch at 198.18.128.66 as a RADIUS network device (secret
> `ISEsecret123`). Create an SGT called `Employees` (value 4) and an authorization
> profile that assigns VLAN 100 plus a downloadable ACL permitting only DNS + web.
> Wire it into a Wired-802.1X policy set so a domain user lands in `Employees` with
> that profile, then show me who's authenticated right now."**

Exercises: `ise_create_network_device` → `ise_create_sgt` → `ise_create_dacl` →
`ise_create_authz_profile` → `ise_create_policy_set` + `ise_create_authz_rule`
(condition resolved by name, e.g. `Wired_802.1X`) → `ise_active_sessions`.

## Focused tasks (one area each)

**Onboard a NAD**
> "Add the switch at 198.18.128.66 as a network device with RADIUS secret
> `ISEsecret123` and TACACS secret `TACkey123`."  *(`ise_create_network_device`)*

**TrustSec / segmentation**
> "Create SGTs `Employees` and `Contractors`, an SGACL that denies Contractors→Servers,
> and place it in the egress matrix."  *(`ise_create_sgt` / `ise_create_sgacl` /
> egress matrix)*

**TrustSec SXP**
> "Advertise the IP→SGT binding 10.40.0.10→Employees, and peer ISE as an SXP SPEAKER
> to the switch at 10.50.0.2."  *(`ise_create_ip_sgt_mapping` / `ise_create_sxp_connection`)*

**TACACS+ device admin**
> "Create a read-only command set (show/exit/enable only), a priv-1 shell profile, and
> a device-admin policy set that gives operators read-only on this switch."
> *(`ise_create_tacacs_command_set` / `ise_create_tacacs_profile` / device-admin policy set)*

**Bulk endpoints (mass MAB)**
> "Bulk-register these 200 MACs as endpoints in the `Printers` group, then tell me when
> the task finishes."  *(`ise_bulk_create_endpoints` → `ise_get_task_status`)*

**Rapid containment (ANC)**
> "Quarantine endpoint aa:bb:cc:dd:ee:ff now, then clear it."  *(`ise_apply_anc` /
> `ise_clear_anc` — issues a CoA)*

**Troubleshoot auth**
> "Who's authenticated right now, and why did aa:bb:cc:dd:ee:ff fail its last attempt?"
> *(`ise_active_sessions` / `ise_auth_status_by_mac` / `ise_failure_reasons`)*

**Day-2 / health**
> "Give me a one-call health summary: version, nodes, licensing, patches, last backup,
> live sessions."  *(`ise_system_summary`)*

## Tips

- **`ise_check_surfaces` first**, every time — ERS is disabled by default.
- **Discover anything** with `ise_search_spec` + `ise_get_definition`, and call it via
  `ise_openapi_call` / `ise_ers_call` / `ise_mnt_call` when no dedicated tool fits.
- Conditions in policy rules are **resolved by name** (e.g. `Wired_802.1X`,
  `Wired_MAB`) — you don't need the UUID.
