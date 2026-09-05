# Changelog

## 2.7.10 - 2026-09-04

- Accept Claude clients at the OAuth authorization server: HTTPS callbacks on `claude.ai` and `claude.com` join the existing ChatGPT/OpenAI hosts, RFC 8252 loopback redirects (`http://localhost`, `127.0.0.1`, `::1`, any port) are accepted for native clients such as Claude Code, and `claude.ai`/`claude.com` client ID metadata documents are recognized.
- Reject redirect URIs carrying fragments, keep non-loopback `http` and unknown hosts fail-closed, and make the authorization page wording client-neutral.
- No MCP tool, schema, or authorization-scope change; the 110-tool registry contract is carried forward unchanged.
- Reconcile the live SolarEdge bridge into source: export-with-headroom qualification now uses a dedicated 95% state-of-charge threshold (`export_with_headroom_soc_pct`) instead of the 99.5% alert threshold, matching the bridge deployed on 2026-09-04.

## 2.7.9 - 2026-09-02

- Reconcile the live SolarEdge Monitoring Bridge 1.3.1 into maintained source, including the privacy-filtered full-data response service, expanded scalar sensors, capability/connectivity binary sensors, and durable export-with-battery-headroom event history.
- Add authenticated WebSocket event reads and CSV export backed by the same persisted event values, with bounded restart reconstruction and deterministic qualification/end semantics.
- Keep the new Home Assistant response service out of generic MCP service routing; existing narrow typed SolarEdge MCP tools remain the preferred client surface.
- Add focused parser, full-data client, event-state-machine, CSV, and idempotent reconstruction regression coverage and acknowledge the removed optional Jewish Calendar service in the release capability baseline.

## 2.7.8 - 2026-09-01

- Add typed, destructive, non-idempotent `pause_sprinklers`, `resume_sprinklers`, and `skip_sprinkler_zone` tools, each gated by explicit current-turn confirmation and restricted to the configured controller.
- Expose normalized logical-run status so clients can route only eligible operations; current-zone skip remains limited to an active dashboard-owned multi-zone Quick Run with another queued zone.
- Preserve native scheduled-program skip as unsupported, keep generic and automation service routing fail-closed, and never exercise physical sprinkler commands during release acceptance.
- Reconcile the immutable MCP release with the reviewed Wyze overlay 0.1.45 countdown, eleven-service verifier, and manual-sequence skip behavior.
- Extend the registry fixture to integrity-check client-visible tool titles and descriptions in addition to names, schemas, and safety annotations.

## 2.7.7 - 2026-08-30

- Acknowledge the reviewed Home Assistant Hubitat service-registry expansion without exposing new writes.
- Keep lock-code reads/writes, arbitrary commands, alarm/security mode, delay settings, hub identifiers, and free-text hub mode fail-closed pending separately reviewed typed adapters.
- Mark the reviewed Hubitat exclusions in `list_services` so clients do not mistake schema discovery for authorization.

## 2.7.6 - 2026-08-30

- Add coordinator-owned logical sprinkler runs with ordered queue state and bounded pause, resume, and stop services for scheduled and dashboard sequences.
- Make Home Assistant own every sequence transition so stop abandons all queued zones and resume continues the captured current-zone remainder before advancing in order.
- Allow automation writes only for the exact current controller, literal bounded logical-run services, and existing daily forecast reads; remove the legacy sprinkler-button exception.

## 2.7.5 - 2026-08-29

- Recognize Wyze's controller-reported `past` schedule-run state as finished so completed quick runs produce idle telemetry and subsequent manual runs are accepted.
- Keep truly unknown watering state fail-closed, reject retries before any provider mutation, and require affirmative idle evidence between Home Assistant-timed zones.

## 2.7.4 - 2026-08-29

- Accept exact sprinkler durations from 1 through 10800 seconds in the typed MCP and Home Assistant service schemas.
- Make Home Assistant own sub-minute timing: it sends the provider's 60-second minimum, stops at the requested second, verifies controller-reported idle, and only then advances a managed sequence.
- Cancel and stop any active HA-timed run when the integration unloads; a Home Assistant outage remains bounded by the provider's 60-second command.

## 2.7.3 - 2026-08-29

- Permit Wyze native 12-digit device/zone identifiers in sprinkler acceptance while continuing to reject contextual AWS account IDs, credentials, IPs, and home paths.
- Include the exact tool name in production verifier sanitization failures so rollback evidence is actionable.
- Add a live, read-only candidate sidecar preflight that must pass before any MCP release mutation; `-PreflightOnly` runs it without requiring GitHub publication or deploying a service.
- Permit reuse of an already-live Wyze overlay only after byte-for-byte comparison with the candidate, avoiding an unnecessary Home Assistant restart.
- Stream remote deployment output and preserve the original failure stage through rollback for actionable production evidence.
- Make fixed-route cutover readiness bounded and version-aware before production MCP verification.

## 2.7.2 - 2026-08-29

- Treat upstream history source sentinels such as `unknown`, `unavailable`, and
  `unsupported` as explicit unsupported values with no evidence, matching the
  typed Gantt contract and live Wyze recorder payloads.

## 2.7.1 - 2026-08-29

- Made the two vacuum-room tool schemas independent of the private configured
  vacuum entity while preserving the configured runtime default. This keeps
  the exact public registry contract deterministic across deployment hosts.
- Hardened MCP rollback into one fail-closed application restore that validates
  the backup archive, prior image reference, Compose configuration, recreated
  container image, and health endpoint before reporting success.

## 2.7.0 - 2026-08-29

- Added eight typed sprinkler tools for capability discovery, separated command
  and controller state, native schedule reads, upcoming runs, weather/skip
  decisions, redacted diagnostics, and exact-second zone/sequence commands.
- Expanded all sprinkler reads with stable normalized zone IDs, retained native
  identifiers, advanced zone configuration, modeled moisture labels, explicit
  unsupported results, and provenance that never equates cloud/controller state
  with physical valve feedback.
- Rebuilt watering history as a rolling, default 48-hour one-row-per-zone Gantt
  contract with time-zone-aware intervals, source/outcome/interruption fields,
  command duration when available, run/program IDs, and controller-reported or
  reconstructed evidence.
- Added an Apache-2.0-attributed Home Assistant Wyze overlay with four
  response-only services and exact-second command construction, plus a
  base-hash-guarded transactional deployment with backup, full Home Assistant
  restart, all-loaded-entry preservation, read-only acceptance, and automatic
  inner plus MCP-cutover outer rollback.
- Production acceptance now compares live input/output schemas and annotations
  against the exact release contract and invokes every sprinkler read under
  `mcp:read`; command tools are inspected but never executed. It independently
  reconciles the eight-zone MCP inventory with the read-only integration
  snapshot, including normalized and native zone IDs.
- Deployment now restarts the diagnostics collector only when its immutable
  content hash changes, recreates the tunnel only for a tunnel configuration or
  image change, and otherwise cuts over only the MCP container. Overlay rollback
  is fail-closed at every restore and verification step.
- Confirmed upstream limits remain explicit: no verified native schedule
  mutation/manual-run schema, lifetime-history pagination, raw Wyze weather
  feed, full Sprinkler Plus calculation, physical valve-open signal, measured
  flow, electrical load, or valve-fault telemetry.

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
