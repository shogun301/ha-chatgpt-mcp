# Changelog

## 2.6.3 - 2026-08-29

- Builds and tests release images only from an exact Git archive of the public
  candidate commit, with tracked Docker-input and manifest validation.
- Runs the complete server, collector, and Home Assistant test suites inside the
  exact image with networking disabled and a minimal sanitized environment.
- Adds immutable source labels, pre-deployment startup smoke testing, and CI
  parity for clean-context, packaging, schema, security, and runtime gates.

## 2.6.2 - 2026-08-29

- Added a fail-closed automation exception for `button.press` that accepts only
  one of at most three exact, deployment-configured sprinkler-zone buttons.
  Other, unknown, multiple, or templated button targets remain rejected.
- Added a separate exact daily `weather.get_forecasts` exception limited to one
  configured weather entity, `type: daily`, and a bounded literal
  `response_variable`. Automation creation and updates still require explicit
  current-turn confirmation.
- Split controller and zone entity prefixes so sanitized source can preserve
  deployment-specific sprinkler entity naming through ignored runtime
  configuration instead of committed household identifiers.

## 2.6.1 - 2026-08-27

- Added a timestamp-deduplicated SolarEdge bridge filter that omits all six
  instantaneous power metrics for one abrupt strong-to-near-zero observation.
  A distinct second low observation is accepted so sustained outages remain
  visible after one five-minute confirmation interval.
- The filter preserves current cumulative energy, battery state of energy, and
  storage-plan data while the suspect power tuple is omitted, and serializes
  transitions so duplicate provider-cache reads cannot confirm an outage.

## 2.6.0 - 2026-08-27

- Added a persistent five-minute Home Assistant service-registry synchronizer.
  It records a release-bound baseline in `/data`, detects added, removed, and
  field-schema changes across restarts, and exposes drift through
  `get_capability_sync_status`.
- Replaced inferred Wyze sprinkler button telemetry with the new native live
  status, active-zone, remaining-time, configuration, history, and zone
  metadata entities. Added typed sequence, refresh, and controller-native
  run/stop services while retaining explicit confirmation for watering starts.
- Added bounded calendar event reads and writes, generic schedule reads, and
  exact time-entity writes. The service now advertises 99 tools.

## 2.5.0 - 2026-08-25

### Added

- Three typed, privileged read-only LAN tools: `get_lan_gateway_status`,
  `list_lan_nodes`, and `probe_lan_node`. The service now advertises 89 tools.
- Fixed-subnet opaque node IDs and a closed ten-service TCP diagnostic allowlist.
  Scans are bounded to 254 hosts, 64 concurrent connection attempts, 100 returned
  nodes, and short timeouts; no application payload is sent.

### Security and operations

- LAN tools require `mcp:read` plus `mcp:diagnostics` or the existing strongest
  `mcp:write` scope, and expose no arbitrary address, port, URL, command, or
  physical-device control.
- Results omit raw LAN IP and MAC addresses. Rich local inventory remains routed
  through the separately pinned ASUS router helper rather than copying router
  credentials into the cloud service.

## 2.4.0 - 2026-08-24

### Added

- Four typed, read-only tools: `get_host_runtime_health`,
  `get_restart_outage_diagnostics`, `list_diagnostic_events`, and
  `get_fixed_route_health`. The service now advertises 86 tools.
- A dedicated least-privilege `mcp:diagnostics` scope. Diagnostic tools require
  `mcp:read` plus either `mcp:diagnostics` or the existing strongest
  `mcp:write` connection scope.
- A root-owned, boot-enabled host collector with no listener, a fixed read-only
  export mount, atomic snapshots, persistent event/sample ledgers, hashed
  runtime identities, and explicit source availability/completeness.
- Separate local-origin and external-route probes for the Home Assistant
  frontend and MCP endpoint, plus safe TLS, DNS, WebSocket, authentication-gate,
  and tunnel observations. Cloudflare replica state comes from its fixed
  loopback-only metrics listener on port 49312.
- Evidence-based outage cause classification. Exit 137 requires corroborating
  OOM evidence; deployment, operator, and watchdog causes require direct
  markers.
- Defense-in-depth redaction and tests for secrets, authentication material,
  network and hardware addresses, cloud identifiers, identity/location data,
  paths, signed URLs, environment data, raw logs, and stack traces.
- Eight persistent UTC daily segments (current plus seven completed days) with
  an eight-day historical backfill, 1.75 MiB per-ledger caps, a 32 MiB
  aggregate export cap, and explicit truncation.

### Security and operations

- The MCP container receives sanitized diagnostics read-only and never receives
  the Docker socket or host control surfaces.
- Diagnostic inputs accept only strict UTC windows, hard result limits, and
  allowlisted enums. There are no caller-supplied URLs, paths, commands,
  containers, services, or search expressions.
- Diagnostic calls are audited without recording returned evidence or
  authentication material.
- Deployment records bounded lifecycle markers and preserves collector evidence
  across application deployment and rollback.

## 2.3.2 - prior production baseline

- Advertised 82 typed Home Assistant tools.
- Provided OAuth-protected Home Assistant, dashboards, schedules, automations,
  SolarEdge, thermostat, media, vacuum, sprinkler, and backup capabilities.
- Did not expose structured AWS-host, Docker lifecycle, kernel/cgroup OOM,
  tunnel-history, or separate fixed-route diagnostics.
