from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from collector.ha_host_diagnostics import (
    MAX_CURRENT_BYTES,
    MAX_EXPORT_BYTES,
    Collector,
    CollectorConfig,
    CommandRunner,
    build_parser,
    sanitize_text,
    PUBLIC_FRONTEND_URL,
)


class FakeRunner:
    def __init__(self, replies=None):
        self.replies = replies or {}
        self.calls = []

    def run(self, argv, timeout=12.0):
        args = tuple(argv)
        self.calls.append(args)
        for prefix, reply in self.replies.items():
            if args[: len(prefix)] == prefix:
                return reply(args) if callable(reply) else reply
        return 127, ""


@pytest.fixture
def collector(tmp_path: Path) -> Collector:
    return Collector(
        CollectorConfig(
            export_dir=tmp_path / "export",
            state_dir=tmp_path / "state",
            require_root=False,
        ),
        FakeRunner(),
    )


def inspect_payload(*, identity="a" * 64, running=True, exit_code=0, oom=False, restarts=0, error=""):
    return json.dumps(
        [
            {
                "Id": identity,
                "RestartCount": restarts,
                "State": {
                    "Running": running,
                    "Status": "running" if running else "exited",
                    "StartedAt": "2026-08-24T19:53:06Z",
                    "FinishedAt": "" if running else "2026-08-24T19:53:05Z",
                    "ExitCode": exit_code,
                    "Error": error,
                    "OOMKilled": oom,
                },
                "HostConfig": {
                    "RestartPolicy": {"Name": "unless-stopped"},
                    "Memory": 0,
                    "MemorySwap": 0,
                    "NanoCpus": 0,
                    "PidsLimit": None,
                },
            }
        ]
    )


def event_lines(path: Path):
    files = sorted(path.glob("events-*.jsonl"))
    return [json.loads(line) for file in files for line in file.read_text().splitlines() if line]


def test_healthy_snapshot_atomic_schema_and_fixed_sources(tmp_path: Path):
    runner = FakeRunner(
        {
            ("docker", "inspect"): (0, inspect_payload()),
            ("docker", "stats"): (0, '{"CPUPerc":"1.00%","MemPerc":"2.00%"}\n'),
        }
    )
    c = Collector(CollectorConfig(tmp_path / "export", tmp_path / "state", require_root=False), runner)
    c.state["historical_backfill"] = {"completed": True, "complete": True}
    with patch.object(c, "_host_metrics", return_value=({"cpu_percent": 1}, [])), patch.object(
        c, "_boot", return_value={"identity": "boot_hash", "uptime_seconds": 10, "boot_time": "2026-08-24T00:00:00Z"}
    ), patch.object(c, "_cgroup", return_value=({"oom": 0, "oom_kill": 0}, True)), patch.object(
        c, "_probes", return_value={
            "local_home_assistant": {"http": {"reachable": True}},
            "public_frontend": {"dns_resolved": True, "tls": {"valid": True}, "bootstrap": {"reachable": True}},
            "local_mcp": {"health": {"reachable": True}},
            "public_mcp": {"dns_resolved": True, "tls": {"valid": True}, "health": {"reachable": True}},
        }
    ), patch.object(c, "_systemd_state", return_value=({"docker": {"available": True}}, [])), patch.object(
        c, "_cloudflare_metrics", return_value=({"available": True, "connected_replicas": 4}, [])
    ), patch.object(c, "collect_incremental", return_value={"complete": True}):
        current = c.once()
    assert current["schema_version"] == 1
    assert current["collector"]["fresh_for_seconds"] == 180
    assert current["evidence"]["complete"] is True
    assert set(current["containers"]) == {"home_assistant", "mcp", "cloudflare_tunnel", "reverse_proxy"}
    assert (tmp_path / "export" / "current.json").stat().st_size > 0
    assert not list((tmp_path / "export").glob(".*current*"))
    assert all(call[0] == "docker" for call in runner.calls)


@pytest.mark.parametrize(
    "exit_code,oom,cgroup,cause,signal_name",
    [
        (137, False, {"oom": 0, "oom_kill": 0}, "unknown", "SIGKILL"),
        (137, True, {"oom": 0, "oom_kill": 0}, "oom_kill", "SIGKILL"),
        (137, False, {"oom": 1, "oom_kill": 1}, "oom_kill", "SIGKILL"),
        (143, False, {"oom": 0, "oom_kill": 0}, "unknown", "SIGTERM"),
    ],
)
def test_run_transition_conservative_cause(collector: Collector, exit_code, oom, cgroup, cause, signal_name):
    collector.state["containers"] = {
        "home_assistant": {
            "run_identity": "run_old",
            "running": False,
            "exit_code": exit_code,
            "oom_killed_current_run": oom,
            "cgroup_memory_events": cgroup,
        }
    }
    collector.runner = FakeRunner(
        {
            ("docker", "inspect"): (0, inspect_payload(identity="b" * 64)),
            ("docker", "stats"): (0, '{"CPUPerc":"1%","MemPerc":"2%"}'),
        }
    )
    with patch.object(collector, "_cgroup", return_value=({}, False)):
        collector._container_state("home_assistant", "homeassistant", "2026-08-24T19:53:06Z")
    record = event_lines(collector.config.export_dir)[-1]
    assert record["cause"] == cause
    assert record["signal"] == signal_name
    if signal_name == "SIGTERM":
        assert record["cause"] not in {"operator_restart", "deployment_restart"}


def test_boot_and_docker_restart_events_are_direct(collector: Collector):
    collector.state["boot_identity"] = "run_prior"
    collector._detect_boot_change({"identity": "run_new"}, "2026-08-24T19:53:00Z")
    docker_line = json.dumps(
        {"__REALTIME_TIMESTAMP": str(int(dt.datetime(2026, 8, 24, 19, 52, tzinfo=dt.timezone.utc).timestamp() * 1_000_000)), "MESSAGE": "Docker daemon has completed initialization"}
    )
    collector.runner = FakeRunner(
        {
            ("journalctl", "--kernel"): (0, ""),
            ("journalctl", "--unit", "docker.service"): (0, docker_line),
        }
    )
    collector._backfill_journal("2026-08-20T00:00:00Z", "2026-08-25T00:00:00Z")
    records = event_lines(collector.config.export_dir)
    assert any(x["cause"] == "host_reboot" for x in records)
    assert any(x["event_type"] == "docker_start" and x["cause"] == "unknown" for x in records)


def test_docker_backfill_exit_137_without_oom_stays_unknown(collector: Collector):
    event = json.dumps(
        {
            "Action": "die",
            "time": int(dt.datetime(2026, 8, 24, 5, 31, tzinfo=dt.timezone.utc).timestamp()),
            "Actor": {"ID": "d" * 64, "Attributes": {"exitCode": "137"}},
        }
    )
    collector.runner = FakeRunner({("docker", "events"): (0, event)})
    result = collector._backfill_docker("2026-08-16T00:00:00Z", "2026-08-25T00:00:00Z")
    assert result["events"] == 4
    records = event_lines(collector.config.export_dir)
    assert all(x["exit_code"] == 137 and x["cause"] == "unknown" for x in records)
    assert all(x["run_identity"].startswith("run_") and "d" * 64 not in json.dumps(x) for x in records)


def test_docker_event_run_interval_survives_fast_restart(collector: Collector):
    first = json.dumps({"Action": "start", "time": 1787540000, "Actor": {"ID": "e" * 64, "Attributes": {}}})
    last = json.dumps({"Action": "die", "time": 1787540060, "Actor": {"ID": "e" * 64, "Attributes": {"exitCode": "1"}}})
    collector.runner = FakeRunner({("docker", "events"): (0, first + "\n" + last)})
    collector._backfill_docker("2026-08-16T00:00:00Z", "2026-08-25T00:00:00Z")
    deaths = [x for x in event_lines(collector.config.export_dir) if x["event_type"] == "container_die"]
    assert deaths and deaths[0]["run_started_at"] < deaths[0]["run_finished_at"]
    assert deaths[0]["cause"] == "process_crash"


def test_unfinished_historical_run_state_is_bounded(collector: Collector):
    collector.state["historical_run_starts"] = {
        f"run_{index:020d}": f"2026-08-{17 + (index % 8):02d}T00:00:00Z" for index in range(200)
    }
    collector.runner = FakeRunner()
    collector._backfill_docker("2026-08-17T00:00:00Z", "2026-08-25T00:00:00Z")
    assert len(collector.state["historical_run_starts"]) <= 64


def test_explicit_docker_oom_backfill_is_direct(collector: Collector):
    event = json.dumps({"Action": "oom", "time": 1787560000, "Actor": {"Attributes": {}}})
    collector.runner = FakeRunner({("docker", "events"): (0, event)})
    collector._backfill_docker("2026-08-16T00:00:00Z", "2026-08-25T00:00:00Z")
    assert all(x["cause"] == "oom_kill" for x in event_lines(collector.config.export_dir))


def test_tunnel_transitions_are_classifications_not_raw_logs(collector: Collector):
    data = "\n".join(
        [
            "2026-08-24T19:50:00Z ERR failed to serve tunnel token=verysecret 192.0.2.1",
            "2026-08-24T19:51:00Z INF Registered tunnel connection connIndex=0 ip=203.0.113.5",
        ]
    )
    collector.runner = FakeRunner({("docker", "logs"): (0, data)})
    result = collector._backfill_cloudflared("2026-08-16T00:00:00Z", "2026-08-25T00:00:00Z")
    assert result["events"] == 2
    text = "\n".join(x["summary"] for x in event_lines(collector.config.export_dir))
    assert "verysecret" not in text and "192.0.2.1" not in text and "203.0.113.5" not in text


def test_independent_route_transitions(collector: Collector):
    collector.state["probe_states"] = {"public_frontend": True, "public_mcp": True}
    probes = {
        "public_frontend": {
            "dns_resolved": True, "tls": {"valid": True}, "bootstrap": {"status": 530},
            "api_auth_gate": {"status": 530}, "websocket": {"status": 530},
        },
        "public_mcp": {
            "dns_resolved": True, "tls": {"valid": True}, "health": {"status": 200},
            "protocol_auth_gate": {"status": 401},
        },
    }
    collector._record_probe_transitions(probes, "2026-08-24T19:53:00Z")
    records = event_lines(collector.config.export_dir)
    assert len(records) == 1
    assert records[0]["cause"] == "endpoint_failure"
    assert "public_frontend" in records[0]["summary"]


def test_missing_sources_and_first_backfill_completeness(collector: Collector):
    result = collector.backfill_once("2026-08-24T19:53:00Z")
    assert result["completed"] is True
    assert result["complete"] is False
    assert result["docker_events"]["available"] is False
    assert result["journald"]["kernel"]["available"] is False
    assert collector.backfill_once("2026-08-25T19:53:00Z")["attempted_at"] == "2026-08-24T19:53:00Z"


def test_readiness_snapshot_defers_history_without_dropping_scope(collector: Collector):
    with patch.object(collector, "backfill_once") as backfill, patch.object(
        collector, "collect_incremental"
    ) as incremental, patch.object(
        collector, "_host_metrics", return_value=({}, [])
    ), patch.object(
        collector, "_boot", return_value={"identity": "boot_hash"}
    ), patch.object(
        collector, "_container_state", return_value=({}, [])
    ), patch.object(
        collector, "_probes", return_value={}
    ), patch.object(
        collector, "_systemd_state", return_value=({}, [])
    ), patch.object(
        collector, "_cloudflare_metrics", return_value=({}, [])
    ):
        current = collector.once(defer_history=True)

    backfill.assert_not_called()
    incremental.assert_not_called()
    assert current["collector"]["historical_backfill"]["deferred_until_next_cycle"] is True
    assert current["collector"]["incremental_sources"]["deferred_until_next_cycle"] is True
    assert (collector.config.export_dir / "current.json").is_file()


def test_redacts_every_prohibited_category():
    raw = " ".join(
        [
            "Authorization:Bearer abc.def.ghi",
            "eyJabcdefghi.abcdefghij.abcdefghij",
            "AKIA" + "ABCDEFGHIJKLMNOP",
            "secret=supersecret",
            "cookie=session123",
            "arn:aws:ec2:us-west-2:" + "123456789012:instance/i-0123456789abcdef0",
            "subnet-0123456789abcdef0 sg-0123456789abcdef0",
            "192.0.2.1 2001:db8::1 00:11:22:33:44:55",
            "/home/" + "alice/secrets C:\\Users\\" + "bob\\file",
            "https://user:pass@example.test/camera?X-Amz-Signature=secret&token=x",
            "PASSWORD=hunter2 SSID=PrivateWiFi",
            "Traceback (most recent call last): File /home/alice/x.py secret",
            "sk-" + "abcdefghijklmnopqrstuvwxyz ghp_" + "abcdefghijklmnopqrstuvwxyz123456",
            "code=oauthcode state=oauthstate abcdefghijklmnopqrstuvwxyz123456",
            "-----BEGIN " + "PRIVATE KEY----- abcdef -----END PRIVATE KEY-----",
        ]
    )
    clean = sanitize_text(raw, limit=5000)
    for forbidden in (
        "abc.def.ghi", "eyJabcdefghi", "AKIA", "supersecret", "session123", "123456789012",
        "i-0123456789abcdef0", "subnet-", "sg-", "192.0.2.1", "2001:db8", "00:11:22",
        "alice", "bob", "user:pass", "X-Amz", "hunter2", "PrivateWiFi", "File ",
        "sk-", "ghp_", "oauthcode", "oauthstate", "abcdefghijklmnopqrstuvwxyz123456", "BEGIN PRIVATE",
    ):
        assert forbidden not in clean
    assert sanitize_text("2026-08-24T19:53:06Z") == "2026-08-24T19:53:06Z"


def test_state_persists_identity_and_backfill(tmp_path: Path):
    config = CollectorConfig(tmp_path / "export", tmp_path / "state", require_root=False)
    first = Collector(config, FakeRunner())
    identity = first._identity("container-id")
    first.state["historical_backfill"] = {"completed": True, "complete": False}
    first._save_state()
    second = Collector(config, FakeRunner())
    assert second._identity("container-id") == identity
    assert second.state["historical_backfill"]["completed"] is True
    assert (tmp_path / "state" / "identity.key").read_bytes() != b"container-id"


def test_retention_at_least_eight_days_and_removes_old(collector: Collector):
    export = collector.config.export_dir
    for day in ("2026-08-14", "2026-08-17", "2026-08-24"):
        (export / f"events-{day}.jsonl").write_text("{}\n")
    result = collector._retention("2026-08-24T12:00:00Z")
    assert collector.config.retention_days >= 8
    assert not (export / "events-2026-08-14.jsonl").exists()
    assert (export / "events-2026-08-17.jsonl").exists()
    assert result["hard_cap_bytes"] == MAX_EXPORT_BYTES


def test_retention_never_evicts_in_window_to_meet_cap(collector: Collector, monkeypatch):
    import collector.ha_host_diagnostics as module

    monkeypatch.setattr(module, "MAX_EXPORT_BYTES", 5)
    export = collector.config.export_dir
    (export / "events-2026-08-24.jsonl").write_bytes(b"event")
    (export / "samples-2026-08-24.jsonl").write_bytes(b"sample")
    collector._retention("2026-08-24T12:00:00Z")
    assert (export / "events-2026-08-24.jsonl").exists()
    assert (export / "samples-2026-08-24.jsonl").exists()


def test_watchdog_failed_check_does_not_imply_restart(collector: Collector):
    timestamp = str(int(dt.datetime(2026, 8, 24, 19, 52, tzinfo=dt.timezone.utc).timestamp() * 1_000_000))
    ordinary = json.dumps({"__REALTIME_TIMESTAMP": timestamp, "MESSAGE": "frontend failed check 1/3"})
    action = json.dumps({"__REALTIME_TIMESTAMP": str(int(timestamp) + 1_000_000), "MESSAGE": "frontend failed three checks; restarting cloudflared"})
    collector.runner = FakeRunner(
        {("journalctl", "--unit", "home-assistant-watchdog.service"): (0, ordinary + "\n" + action)}
    )
    collector._backfill_journal("2026-08-24T00:00:00Z", "2026-08-25T00:00:00Z")
    records = [x for x in event_lines(collector.config.export_dir) if x["event_type"].startswith("watchdog")]
    assert [x["cause"] for x in records] == ["unknown", "watchdog_restart"]


def test_event_append_hard_cap_marks_truncation(collector: Collector, monkeypatch):
    import collector.ha_host_diagnostics as module

    monkeypatch.setattr(module, "MAX_LEDGER_FILE_BYTES", 1)
    ok = collector._append("events", {"timestamp": "2026-08-24T00:00:00Z", "value": "x"})
    assert ok is False
    assert collector.state["truncation"]["events-2026-08-24"] is True


def test_cli_has_only_safe_actions_and_semver_validation(collector: Collector):
    parser = build_parser()
    assert parser.parse_args(["once"]).action == "once"
    args = parser.parse_args(["mark-deployment", "--phase", "completed", "--version", "2.4.0"])
    assert args.phase == "completed"
    with pytest.raises(SystemExit):
        parser.parse_args(["shell", "id"])
    with pytest.raises(ValueError):
        collector.mark_deployment("../../bad", "completed")
    marker = collector.mark_deployment("2.4.0", "completed")
    assert marker["event_type"] == "deployment_completed"


def test_deployment_marker_does_not_take_daemon_lock(collector: Collector):
    collector.acquire_lock()
    marker = collector.mark_deployment("2.4.0", "started")
    assert marker["event_type"] == "deployment_started"


def test_incremental_sources_polled_every_iteration_with_overlap(collector: Collector):
    collector.state["source_cursor"] = "2026-08-24T19:50:00Z"
    with patch.object(collector, "_backfill_docker", return_value={"available": True}) as docker, patch.object(
        collector, "_backfill_journal", return_value={"kernel": {"available": True}}
    ) as journal, patch.object(collector, "_backfill_cloudflared", return_value={"available": True}) as tunnel:
        collector.collect_incremental("2026-08-24T19:53:00Z")
        collector.collect_incremental("2026-08-24T19:54:00Z")
    assert docker.call_count == journal.call_count == tunnel.call_count == 2
    assert docker.call_args_list[0].args[0] == "2026-08-24T19:48:00Z"
    assert docker.call_args_list[1].args[0] == "2026-08-24T19:51:00Z"


def test_docker_stats_include_current_and_limit_bytes(collector: Collector):
    collector.runner = FakeRunner(
        {("docker", "stats"): (0, '{"CPUPerc":"2.5%","MemPerc":"25%","MemUsage":"256MiB / 1GiB"}')}
    )
    result = collector._stats("homeassistant")
    assert result["memory_current_bytes"] == 256 * 1024**2
    assert result["memory_limit_bytes"] == 1024**3


def test_systemd_fixed_units_only(collector: Collector):
    output = "ActiveState=active\nSubState=running\nActiveEnterTimestampMonotonic=1000000\nNRestarts=2\nExecMainStatus=0\n"
    collector.runner = FakeRunner({("systemctl", "show"): (0, output)})
    with patch.object(Path, "read_text", return_value="100.0 0"), patch("time.time", return_value=200.0):
        state, unavailable = collector._systemd_state()
    assert unavailable == []
    assert state["docker"]["restart_count"] == 2
    units = {call[2] for call in collector.runner.calls}
    assert units == {"docker.service", "wg-quick@wg0.service", "home-assistant-watchdog.service"}
    assert state["docker"]["active_since"].endswith("Z")


def test_http_error_statuses_are_not_route_health(collector: Collector):
    assert collector._route_ok("local_mcp", {"health": {"status": 503}, "protocol_auth_gate": {"status": 401}}) is False
    assert collector._route_ok(
        "public_frontend",
        {"dns_resolved": True, "tls": {"valid": True}, "bootstrap": {"status": 530},
         "api_auth_gate": {"status": 530}, "websocket": {"status": 530}},
    ) is False


def test_home_assistant_probes_do_not_request_authentication_endpoints(collector: Collector):
    with patch.object(collector, "_probe_http", return_value={"reachable": True, "status": 200}) as http, patch.object(
        collector, "_probe_websocket", return_value={"reachable": True, "status": 101}
    ), patch.object(collector, "_probe_dns", return_value=True), patch.object(
        collector, "_probe_tls", return_value={"valid": True}
    ):
        probes = collector._probes()

    requested_urls = [call.args[0] for call in http.call_args_list]
    assert "http://127.0.0.1:8123/" in requested_urls
    assert f"{PUBLIC_FRONTEND_URL}/" in requested_urls
    assert not any(url.rstrip("/").endswith("/api") for url in requested_urls)
    assert "api_auth_gate" not in probes["public_frontend"]
    assert collector._route_ok(
        "local_home_assistant",
        {"http": {"status": 200}, "websocket": {"status": 101}},
    ) is True
    assert collector._route_ok(
        "public_frontend",
        {
            "dns_resolved": True,
            "tls": {"valid": True},
            "bootstrap": {"status": 200},
            "websocket": {"status": 101},
        },
    ) is True


def test_running_to_stopped_uses_current_exit_evidence(collector: Collector):
    run_id = collector._identity("a" * 64)
    collector.state["containers"] = {
        "home_assistant": {"run_identity": run_id, "running": True, "exit_code": 0,
                           "oom_killed_current_run": False, "cgroup_memory_events": {}}
    }
    collector.runner = FakeRunner(
        {("docker", "inspect"): (0, inspect_payload(running=False, exit_code=1)),
         ("docker", "stats"): (127, "")}
    )
    with patch.object(collector, "_cgroup", return_value=({}, True)):
        collector._container_state("home_assistant", "homeassistant", "2026-08-24T19:53:06Z")
    record = event_lines(collector.config.export_dir)[-1]
    assert record["exit_code"] == 1
    assert record["cause"] == "process_crash"


def test_container_error_is_bounded_and_sanitized(collector: Collector):
    collector.runner = FakeRunner(
        {("docker", "inspect"): (0, inspect_payload(error="dial 192.0.2.1 /home/alice/x token=secret")),
         ("docker", "stats"): (127, "")}
    )
    with patch.object(collector, "_cgroup", return_value=({}, False)):
        state, _ = collector._container_state("home_assistant", "homeassistant", "2026-08-24T19:53:06Z")
    assert state["error"] is not None
    assert "192.0.2.1" not in state["error"] and "alice" not in state["error"] and "secret" not in state["error"]


def test_cgroup_counter_delta_is_persisted(collector: Collector):
    run_id = collector._identity("a" * 64)
    collector.state["containers"] = {
        "home_assistant": {"run_identity": run_id, "running": True, "exit_code": 0,
                           "oom_killed_current_run": False, "cgroup_memory_events": {"oom_kill": 0}}
    }
    collector.runner = FakeRunner(
        {("docker", "inspect"): (0, inspect_payload()),
         ("docker", "stats"): (127, "")}
    )
    with patch.object(collector, "_cgroup", return_value=({"oom_kill": 1}, True)):
        collector._container_state("home_assistant", "homeassistant", "2026-08-24T19:53:06Z")
    record = event_lines(collector.config.export_dir)[-1]
    assert record["component"] == "cgroup" and record["cause"] == "oom_kill" and record["counter"] == 1


def test_current_snapshot_hard_cap(collector: Collector):
    with pytest.raises(ValueError, match="hard cap"):
        collector._atomic_json(
            collector.config.export_dir / "current.json",
            {"value": ["x" * 320 for _ in range(MAX_CURRENT_BYTES // 160)]},
            public=True,
        )
    assert not (collector.config.export_dir / "current.json").exists()


@pytest.mark.parametrize(
    "argv",
    [
        ["sh", "-c", "id"],
        ["/usr/bin/docker", "inspect", "homeassistant"],
        ["docker", "inspect", "arbitrary"],
        ["docker", "restart", "homeassistant"],
        ["systemctl", "show", "ssh.service", CommandRunner._PROPERTIES, "--no-pager"],
        ["journalctl", "--unit", "ssh.service", "--since", "2026-08-24T00:00:00Z", "--until", "2026-08-25T00:00:00Z", "--output=json", "--no-pager"],
    ],
)
def test_command_runner_rejects_every_nonfixed_argv(argv):
    with pytest.raises(ValueError, match="allowlist"):
        CommandRunner().run(argv)


def test_stale_contract_is_explicit(collector: Collector):
    # Reader determines staleness from these explicit collector values.
    with patch("collector.ha_host_diagnostics.rfc3339", return_value="2026-08-24T00:00:00Z"):
        collector.state["historical_backfill"] = {"completed": True, "complete": False}
        with patch.object(collector, "_host_metrics", return_value=({}, ["proc_meminfo"])), patch.object(
            collector, "_boot", return_value={"identity": "x", "uptime_seconds": 1, "boot_time": "2026-08-23T00:00:00Z"}
        ), patch.object(collector, "_container_state", return_value=({"available": False}, ["docker_inspect"])), patch.object(
            collector, "_probes", return_value={}
        ):
            current = collector.once()
    assert current["collector"]["observed_at"] == "2026-08-24T00:00:00Z"
    assert current["collector"]["fresh_for_seconds"] == 180
    assert current["evidence"]["complete"] is False
    assert "proc_meminfo" in current["evidence"]["unavailable_sources"]


def test_diagnostics_code_contains_no_device_mutation_surfaces():
    source = Path(__file__).parents[1].joinpath("ha_host_diagnostics.py").read_text().lower()
    for forbidden in (
        "climate.set_temperature", "light.turn_", "vacuum.start", "sprinkler", "lock.unlock",
        "camera.snapshot", "media_player.turn", "call_service", "docker restart", "systemctl restart",
    ):
        assert forbidden not in source
