# Host diagnostics collector

This root-owned service has no listener. Every input is compiled into the
collector: four container names and four local/public endpoint probes. It reads
Docker, procfs/cgroup, and bounded journal history, then writes only sanitized
structured output beneath `/var/lib/ha-host-diagnostics/export`. The MCP
container should mount that directory read-only; it must never receive the
Docker socket.

The systemd sandbox retains only `CAP_CHOWN`, which is required to publish new
sanitized files as `root:10001`; it grants no host-control or network-admin
capability.

`current.json` is replaced atomically. Daily `events-YYYY-MM-DD.jsonl` and
`samples-YYYY-MM-DD.jsonl` ledgers survive container restarts and host reboots.
Eight days are retained, every daily ledger is capped at 1.75 MiB,
`current.json` is capped at 256 KiB, and all exported ledgers together are
capped at 32 MiB. Root-only state contains the stable
identity hashing key and source cursors. Raw logs and raw container/boot IDs are
never exported. Root-only `state.json` is capped at 2 MiB; event deduplication,
active historical-run starts, and truncation keys are each explicitly bounded.

On first run the collector performs exactly one bounded eight-day backfill from
Docker events, journald, and the fixed cloudflared and reverse-proxy container
logs. It stores
source availability/completeness and emits classified events, not raw messages.
Every subsequent iteration polls those fixed sources incrementally with a
two-minute overlap and stable deduplication, so short-lived events are retained.
Exit 137 is `unknown` unless an explicit Docker OOM event or direct kernel/cgroup
evidence establishes `oom_kill`. SIGTERM does not imply an operator or
deployment; deployment attribution requires `mark-deployment` evidence.

## Install

Copy this directory to `/opt/ha-host-diagnostics`, install the unit as
`/etc/systemd/system/ha-host-diagnostics.service`, and run:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now ha-host-diagnostics.service
sudo /usr/bin/python3 /opt/ha-host-diagnostics/ha_host_diagnostics.py validate
```

Deployments may record a bounded marker using only a validated semantic version:

```sh
sudo /usr/bin/python3 /opt/ha-host-diagnostics/ha_host_diagnostics.py mark-deployment --phase completed --version 2.6.0
```

Do not add parameters for URLs, paths, containers, services, commands, log
expressions, or network listeners.
