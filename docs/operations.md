# Production diagnostics operations

This runbook covers the read-only host diagnostics introduced in MCP 2.4.0 and
the bounded home-LAN diagnostics added in MCP 2.5.0, and persistent Home
Assistant capability synchronization added in MCP 2.6.0 and the SolarEdge
one-sample power-flow artifact filter added in MCP 2.6.1, and exact configured
sprinkler/forecast automation actions added in MCP 2.6.2.
It also covers the transactional Wyze sprinkler overlay and typed MCP 2.7.0
read/command boundary.
It does not authorize device actions, ad hoc service restarts, firewall changes,
or raw-log collection. The sole Home Assistant restart described below is the
transactional, rollback-guarded overlay load step.

## Components and data flow

1. The included systemd unit starts the root-owned collector at boot from
   `/opt/ha-host-diagnostics`.
2. The collector samples fixed sources every 60 seconds and persists root-only
   state under `/var/lib/ha-host-diagnostics/state`. MCP independently polls
   the HA service registry every five minutes and stores its release-bound
   capability baseline beneath `/data`.
3. It atomically publishes only sanitized `current.json`, daily event ledgers,
   and daily sample ledgers beneath `/var/lib/ha-host-diagnostics/export`.
4. The MCP container mounts that export directory read-only and opens only
   `current.json`, `events-YYYY-MM-DD.jsonl`, and
   `samples-YYYY-MM-DD.jsonl`. Symlinks, malformed files, oversized files, and
   non-fixed names are rejected.

The collector is the only component with host diagnostic privileges. Its
systemd sandbox denies privilege escalation, limits CPU/memory/tasks, protects
the host filesystem and kernel controls, and grants writes only within
`/var/lib/ha-host-diagnostics`. It exposes no HTTP, TCP, or Unix-socket API.
It retains only `CAP_CHOWN`, solely to assign sanitized exports to the MCP
reader's GID 10001; all other Linux capabilities remain denied.
It reads the fixed Cloudflare metrics listener only through loopback port 49312;
that listener must never bind to a public interface.

### Persistence and bounds

- Collection cadence: 60 seconds.
- Freshness: exact age is returned; more than 180 seconds is stale.
- Retention window: eight UTC daily segments (current plus seven completed
  days). Aggregate pressure stops appends and marks truncation without removing
  in-window evidence.
- Initial backfill: one bounded eight-day attempt from fixed Docker events,
  fixed journal sources, and classified fixed tunnel logs.
- Incremental event collection: fixed sources are polled with a two-minute
  overlap and stable deduplication after the initial backfill.
- Per daily event or sample ledger: 1.75 MiB.
- Aggregate exported ledgers: 32 MiB.
- MCP current snapshot read: at most 256 KiB.
- MCP ledger read: at most 4 MiB per file, 64 KiB per line, and 50,000 lines per
  request; tool results are additionally limited to 200 records.
- Historical source capture: at most 20,000 lines and 1 MiB per fixed command.

When a per-ledger cap is reached, the collector stops appending to that ledger
and records truncation. When the aggregate cap is reached, it stops appending
and records aggregate truncation. It removes only segments older than the
retention window; it never removes in-window evidence merely to meet the cap.
Missing, partial, malformed, or stale evidence lowers
completeness instead of being silently treated as healthy.

## Install or upgrade

Use the established production deployment script, which requires a clean Git
checkout, exports the exact commit with `git archive`, validates every tracked
build input, builds and smoke-tests the immutable image, runs the full suite
with networking disabled, creates timestamped backups, installs or restarts the
included systemd unit only when its immutable content hash changes, deploys the Wyze overlay and MCP 2.7.0 from one exact
public commit, and performs read-only health checks.
Do not hand-copy secrets or add a Docker-socket mount.

Before deployment:

1. Confirm the release version is 2.7.0 and the expected tool count is 107.
2. Review the complete diff, especially OAuth scope defaults, fixed probe
   targets, collector command constants, Compose mounts, and systemd hardening.
3. Confirm backups exclude credentials and include the previous application,
   Compose definition, collector code/unit, and rollback image reference.
4. Require the public audit, manifest-integrity check, all unit/integration/
   schema/security tests, exact-image hermetic suite, package build, startup
   smoke test, and GitHub CI to pass on the exact candidate commit.

During deployment, record `started` and `completed` markers with the collector's
fixed `mark-deployment` operation. Marker inputs accept only a semantic version
and `started`, `completed`, or `rolled_back`; they are not exposed through MCP.
Do not restart Home Assistant merely to deploy diagnostics.

After deployment, keep `/var/lib/ha-host-diagnostics` intact. It is operational
evidence, not disposable application state.

### Wyze sprinkler overlay

`scripts/deploy-production.ps1` invokes `scripts/deploy-wyzeapi-overlay.ps1`
from the same 40-character release commit only after the MCP image has passed
clean-archive, build, integrity, hermetic-suite, smoke, Compose, and host-security
preflight. The overlay runs immediately before MCP container cutover. For an
independently reviewed overlay-only deployment, use:

```powershell
.\scripts\deploy-wyzeapi-overlay.ps1 `
  -AwsProfile <profile> -AwsRegion <region> -InstanceName <instance> `
  -ReleaseCommit <exact-public-main-commit>
```

The deployer accepts only a clean checkout at that commit and archives only the
tracked overlay. It requires every destination runtime file to match either the
documented 0.1.39 base hash or the exact 0.1.40 candidate hash. Before copying,
it creates a root-only component backup under
`/opt/homeassistant/wyzeapi-overlay-backups`, syntax-checks all Python modules,
parses `services.yaml`, and runs the Home Assistant configuration checker.

Loading new Python modules requires a full `homeassistant` container restart;
a config-entry reload is not acceptance. After the restart, the deployer
requires the eight exact `wyzeapi` services and invokes only
`get_sprinkler_snapshot`, `get_sprinkler_schedule_runs`,
`get_sprinkler_schedules`, and `get_sprinkler_capabilities` with response data.
It never calls refresh, run, sequence, stop, or an automation. A post-copy
failure restores the exact backup and performs another full Home Assistant
restart; rollback failure exits distinctly rather than claiming recovery.
The combined deployer's outer rollback also restores and revalidates the prior
overlay whenever a later MCP cutover or acceptance step fails, preventing a new
overlay from remaining paired with the old MCP image.
The MCP cutover force-recreates only `ha-chatgpt-mcp`. It leaves the collector
and `cloudflared` running when their content/configuration and image identities
are unchanged; a changed collector or tunnel is restarted independently and
rolled back symmetrically. The outer overlay backup is allocated before the
child deployer can mutate Home Assistant, and rollback clears its transaction
flag only after file, restart, config-entry, service, and entity validation all
succeed.

The source distribution retains the upstream Apache-2.0 license, NOTICE, SPDX
headers, and modification attribution. The public audit rejects their removal
and rejects workstation user-profile paths in release files.

## Production verification

Verify each layer independently and do not intentionally create a production
failure:

1. **Collector:** the service is boot-enabled and active; `validate` reports no
   listener, fixed containers/routes, valid schema, at least eight days of
   retention, and enabled byte caps. Two observations about one minute apart
   advance `current.json` without unbounded growth.
2. **Filesystem boundary:** collector state is root-only; exports have the
   intended read-only consumer permissions; the MCP mount is read-only. Confirm
   there is no Docker socket, journal, procfs, sysfs, or systemd-control mount in
   MCP.
3. **Network boundary:** compare listening sockets and infrastructure rules with
   the pre-deployment baseline. There must be no new public listener, firewall
   or security-group opening, public route, or broadened tunnel permission.
   Confirm Cloudflare metrics port 49312 remains loopback-only.
4. **MCP registry:** authenticated discovery reports version 2.7.0 and exactly
   107 tools. Compare every live input schema, output schema, annotation, and
   tool name with `tests/fixtures/server-contract-2.7.0.json`.
5. **Sprinkler inventory:** compare the MCP normalized zone IDs, native IDs, and
   count with the read-only `wyzeapi.get_sprinkler_snapshot` response. The
   deployed configuration is eight zones, and acceptance fails if either side
   omits or invents a live controller zone.
6. **Authorization:** unauthenticated and invalid-token requests are rejected.
   Each diagnostic tool rejects read-only, write-only, and diagnostics-only
   grants. Both `mcp:read mcp:diagnostics` and the existing strongest
   `mcp:read mcp:write` grant succeed.
7. **Diagnostic results:** call all seven tools through the production OAuth path.
   Verify 60-second snapshot cadence, age/completeness fields, bounded windows,
   result limits, fixed route separation, redaction, and no prohibited
   identifiers.
8. **Regression:** use read-only calls to verify overview, dashboards,
   schedules, automations, SolarEdge summaries, thermostat summaries, media
   capabilities, vacuum rooms, all sprinkler read tools, and backup status. Do
   not call refresh, run, sequence, stop, schedule mutation, or any device-state
   service during acceptance.
9. **Capability persistence:** call `get_capability_sync_status` with refresh,
   require `in_sync`, verify a 300-second interval and a persisted baseline for
    version 2.7.0, then confirm the file remains under `/data` across MCP restart.
10. **Persistence:** restart only the collector in a controlled maintenance
   check if necessary. Confirm prior ledgers remain readable and the next sample
   appends normally. Do not restart Home Assistant to test persistence.

Inspect the audit stream only to confirm diagnostic tool name, bounded input
metadata, and status/count flags. Returned snapshots/events, authorization
values, and raw diagnostic content must not appear there.

## Incident workflow

Use the narrowest window that covers the report:

1. Call `get_home_overview`.
2. Call `get_fixed_route_health`.
3. Call `get_restart_outage_diagnostics` with `since_hours`, or a strict UTC
   `start_time`/`end_time` pair. Do not combine the two forms.
4. If necessary, call `list_diagnostic_events` with the smallest component and
   severity set that can resolve the remaining question.
5. Correlate current health, local origins, the two public routes, container
   transitions, host boot identity, cgroup/kernel evidence, deployment markers,
   and tunnel transitions.

Classify conclusions in three groups:

- **Confirmed:** directly recorded lifecycle, OOM, boot, deployment, watchdog,
  tunnel, or endpoint evidence.
- **Supported inference:** multiple sources agree but do not directly identify
  an initiating subsystem.
- **Unresolved:** sources are absent, incomplete, truncated, outside retention,
  or do not establish attribution.

Never identify a person, provider, policy, or client as the cause without direct
audit evidence. A healthy host/container with no corresponding server event can
support a client-only or network-only failure hypothesis, but cannot prove it.

## Safe troubleshooting

### Snapshot is stale

Check whether the collector service is active and whether its last successful
iteration advances. Use the collector's bounded `validate` operation and
systemd status metadata. Do not dump the environment or full journal. If a
fixed source is unavailable, preserve the returned unavailable-source field and
repair only that source permission or dependency.

### Events or samples are incomplete

Inspect `source`, `sources`, `unavailable_sources`, `complete`, and `truncated`
before interpreting absence as evidence. Missing daily files may mean the
window predates installation/retention or collection stopped at a byte cap. A
capped ledger means later records for that day may be
unavailable. Do not bypass the cap or expose raw logs through MCP.

### One route fails and its origin is healthy

Keep the frontend and MCP route results separate. Check DNS success, TLS,
expected HTTP/authentication response, WebSocket or MCP protocol gate, and
collector tunnel state. Cloudflare documents tunnel health, notifications, and
Prometheus metrics in its [monitoring guide](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/monitor-tunnels/)
and [metrics reference](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/monitor-tunnels/metrics/).
Do not change DNS, tunnel routes, or firewall rules merely to test a hypothesis.

### Authorization fails after upgrade

The legacy default grant remains `mcp:read mcp:write` and is accepted as the
existing strongest connection level. A new least-privilege diagnostics client
should reconnect through OAuth and request `mcp:read mcp:diagnostics`; neither
scope works alone. Do not broaden a read-only client to `mcp:write` merely to
obtain diagnostics. The implementation follows OpenAI's MCP
[server](https://developers.openai.com/plugins/build/mcp-server) and
[authentication](https://developers.openai.com/plugins/build/auth) guidance.

## Rollback

Rollback must restore the prior application, Compose definition, collector
code/unit, and MCP image from the timestamped pre-deployment backup. Reload
systemd, recreate the prior MCP service, and restore the previous collector
version only after verifying file ownership and fixed paths.

Do not delete, overwrite, or roll back `/var/lib/ha-host-diagnostics`; preserving
its ledgers is essential for post-incident analysis. Record a bounded
`rolled_back` deployment marker, then repeat the read-only production
verification above. If the prior MCP version cannot read the diagnostics export,
leave the collector evidence intact and remove only the application-side mount
through the restored Compose definition.

Never roll back by exposing a public port, mounting the Docker socket, weakening
OAuth scopes, or returning raw logs.
