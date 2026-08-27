# Home Assistant MCP service

Version 2.6.1 exposes 99 typed MCP tools, including seven privileged, read-only
host and LAN diagnostic tools. The service keeps the Home Assistant API private, uses OAuth
for the public MCP transport, and provides bounded Home Assistant, host,
container, and route evidence without exposing a general administration
interface.

The three LAN tools (`get_lan_gateway_status`, `list_lan_nodes`, and
`probe_lan_node`) operate only on opaque `node-001` through `node-254` IDs in
the configured fixed `/24` subnet. They accept a closed list of ten TCP services, cap scan
output at 100 nodes and concurrency at 64 probes, send no application payload,
and expose no arbitrary address, port, URL, shell, or device-control input.
Raw LAN addresses are deliberately omitted from results.

## Capability synchronization

The service polls Home Assistant's service registry every five minutes and
persists a release-bound compatibility baseline in `/data/ha-capability-sync.json`.
Added or removed services and field/required-field schema changes remain visible
through `get_capability_sync_status` across MCP restarts. Deploying a reviewed
new MCP version acknowledges the then-current Home Assistant surface and starts
the next drift window. The monitor never invokes a Home Assistant service and
does not dynamically expose unreviewed writes.

## Host diagnostics architecture

A boot-enabled, root-owned systemd collector runs independently of Home
Assistant and the MCP container. Its code is installed under
`/opt/ha-host-diagnostics`; persistent state and sanitized exports live under
`/var/lib/ha-host-diagnostics`.

The collector has no listener and accepts no caller-selected path, command,
container, service, log expression, or URL. It reads only compiled-in Docker,
procfs/cgroup, journal, and fixed endpoint sources. The MCP container receives
only the sanitized export directory through a fixed read-only bind mount. It
does not receive the Docker socket, host journals, systemd control, or a host
write path.

The collector writes an atomic current snapshot every 60 seconds. The MCP
reader reports the exact snapshot age and marks it stale after 180 seconds
(three missed collection intervals). Daily event and sample ledgers use a
eight-segment UTC retention window (current day plus seven completed days),
with a one-time bounded eight-day historical backfill. Each ledger is capped
at 1.75 MiB, the current snapshot at 256 KiB, and all exported ledgers together
at 32 MiB; aggregate pressure stops appends and marks truncation without
removing in-window evidence. After backfill, fixed event sources are polled with a
two-minute overlap and stable deduplication so short-lived transitions survive
between snapshots. Root-only state stores source cursors and the key used to
hash runtime identities; raw IDs and raw logs are not exported.

## Diagnostic tools

All four tools are annotated read-only and require `mcp:read` plus either the
dedicated least-privilege `mcp:diagnostics` scope or the existing strongest
`mcp:write` connection scope. Read-only, write-only, and diagnostics-only grants
are rejected. The legacy default remains `mcp:read mcp:write`; a new
least-privilege diagnostics client should request
`mcp:read mcp:diagnostics`. Calls are audited by tool name and bounded input
metadata plus status/count flags only; returned diagnostic evidence and
authentication material are not logged.

### `get_host_runtime_health`

No inputs. Returns the observation time, collector status and freshness,
host boot/uptime and resource data, fixed runtime/container state and start
times, restart policy/count, current exit/OOM evidence, limits, cgroup counters,
local reachability, evidence completeness, and unavailable sources.

### `get_restart_outage_diagnostics`

Accepts either `since_hours` (default 24, greater than 0 and at most 168) or
both `start_time` and `end_time` as strict UTC RFC 3339 timestamps. These forms
cannot be combined. `limit` defaults to 100 and must be 1 through 200. Returns
classified lifecycle/outage events, at most 60 bounded resource samples,
per-source availability, completeness, and explicit truncation.

Cause values are:

`oom_kill`, `process_crash`, `operator_restart`, `deployment_restart`,
`host_reboot`, `docker_restart`, `watchdog_restart`, `tunnel_failure`,
`endpoint_failure`, and `unknown`.

Exit code 137 alone is not classified as an OOM kill. Direct Docker, kernel, or
cgroup evidence is required. Likewise, operator, deployment, and watchdog
attribution requires a matching direct marker; otherwise the cause remains
`unknown`.

### `list_diagnostic_events`

Uses the same bounded window and `limit`. Optional `components` and
`severities` inputs are enum lists, never free-form searches. Component lists
contain at most 10 entries and severity lists at most 4.

Components:

`home_assistant`, `mcp`, `docker`, `kernel`, `cgroup`, `systemd`,
`cloudflare_tunnel`, `wireguard`, `reverse_proxy`, `endpoint_probe`.

Severities: `info`, `warning`, `error`, `critical`.

Each event contains only a UTC timestamp, component, severity, event type,
sanitized summary, bounded evidence fields, evidence category, cause, and
complete/truncated/inferred flags. The result also reports its effective
window, filters, count, source-file completeness, and truncation.

### `get_fixed_route_health`

No inputs and no arbitrary URL support. It checks only the configured
`FRONTEND_PUBLIC_URL` and `PUBLIC_BASE_URL` routes, keeping results separate. Each route
reports safe DNS success, TLS validity/expiration, HTTP status and latency,
expected authentication behavior, and local-origin comparison. The frontend
also reports bootstrap and safe WebSocket-greeting reachability; the MCP route
reports protocol/auth-gate reachability. Collector-owned tunnel state is
included when available, including the connected-replica count read from the
fixed loopback-only Cloudflare metrics listener on port 49312. DNS answers never
include addresses.

## Security boundary

Diagnostic output is allowlisted, size-bounded, recursively sanitized, and
serialized through a second redaction boundary. It excludes credentials,
tokens, cookies, headers, environment variables, addresses, hardware
identifiers, cloud resource identifiers, usernames, home paths, configuration
contents, process arguments, signed query strings, stack traces, and raw
provider responses.

The tools cannot retrieve arbitrary logs, read arbitrary files, run shell
commands, administer Docker, restart services, open ports, or change Home
Assistant/device state. Fixed probes use only read-only HTTP/TLS/DNS/WebSocket
operations. No public listener, firewall rule, tunnel route, or broad host
privilege is added for diagnostics.

## Incident workflow

1. Call `get_home_overview` to establish current MCP-to-Home-Assistant health.
2. Call `get_fixed_route_health` to compare each public route with its local
   origin.
3. Call `get_restart_outage_diagnostics` for the smallest relevant UTC window.
4. Use `list_diagnostic_events` only when the structured restart result needs
   more event detail.
5. Report confirmed evidence, supported inference, and unresolved gaps
   separately. A currently healthy server with no matching host event may
   support a transient client/network failure, but does not prove its cause.

Never change a thermostat, light, lock, vacuum, sprinkler, camera, television,
router, or other device as a connectivity test.

See [docs/operations.md](docs/operations.md) for deployment, verification,
rollback, and incident procedures, and [CHANGELOG.md](CHANGELOG.md) for release
notes.

## External references

- [OpenAI: Build an MCP server](https://developers.openai.com/plugins/build/mcp-server)
- [OpenAI: Authenticate users](https://developers.openai.com/plugins/build/auth)
- [Cloudflare: Monitor tunnels](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/monitor-tunnels/)
- [Cloudflare: Tunnel metrics](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/monitor-tunnels/metrics/)
