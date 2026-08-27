from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, patch

from app.diagnostics import (
    Cause,
    DiagnosticError,
    DiagnosticsReader,
    MAX_CURRENT_BYTES,
    MAX_JSONL_LINE_BYTES,
    sanitize,
    sanitize_text,
    validate_limit,
    validate_window,
)


NOW = datetime(2026, 8, 24, 20, 0, tzinfo=UTC)


class DiagnosticsFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.reader = DiagnosticsReader(self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_current(self, **overrides: object) -> None:
        current: dict[str, object] = {
            "schema_version": 1,
            "timestamp": "2026-08-24T19:59:30Z",
            "host": {
                "boot": {"identity": "sha256:opaque", "uptime_seconds": 3600},
                "resources": {"cpu_percent": 8.0, "memory": {"percent": 41.2}},
            },
            "containers": {
                "home_assistant": {"running": True, "health": "healthy", "restart_count": 0},
                "mcp": {"running": True, "health": "healthy", "restart_count": 0},
                "cloudflare_tunnel": {
                    "running": True,
                    "metrics": {"active_replicas": 2},
                },
            },
            "collector": {"status": "healthy", "fresh_for_seconds": 180},
            "evidence": {"complete": True, "unavailable_sources": []},
            "complete": True,
            "unavailable_sources": [],
        }
        current.update(overrides)
        (self.root / "current.json").write_text(json.dumps(current), encoding="utf-8")

    def write_jsonl(self, prefix: str, *records: dict[str, object]) -> None:
        path = self.root / f"{prefix}-2026-08-24.jsonl"
        path.write_text(
            "".join(json.dumps(record) + "\n" for record in records), encoding="utf-8"
        )

    @staticmethod
    def event(
        event_type: str,
        *,
        timestamp: str = "2026-08-24T19:53:06Z",
        component: str = "home_assistant",
        severity: str = "warning",
        **values: object,
    ) -> dict[str, object]:
        return {
            "schema_version": 1,
            "timestamp": timestamp,
            "component": component,
            "severity": severity,
            "event_type": event_type,
            "summary": "Fixed sanitized evidence",
            "evidence_source": "docker_event",
            "cause": "unknown",
            "complete": True,
            "truncated": False,
            "inferred": False,
            **values,
        }


class WindowAndBoundsTests(unittest.TestCase):
    def test_since_hours_and_explicit_window_are_mutually_exclusive(self) -> None:
        with self.assertRaisesRegex(DiagnosticError, "cannot be combined"):
            validate_window(
                since_hours=1,
                start="2026-08-24T18:00:00Z",
                end="2026-08-24T19:00:00Z",
                now=NOW,
            )

    def test_explicit_window_requires_both_values_and_utc(self) -> None:
        with self.assertRaisesRegex(DiagnosticError, "supplied together"):
            validate_window(start="2026-08-24T18:00:00Z", now=NOW)
        with self.assertRaisesRegex(DiagnosticError, "UTC"):
            validate_window(
                start="2026-08-24T18:00:00-07:00",
                end="2026-08-24T19:00:00-07:00",
                now=NOW,
            )

    def test_window_order_and_168_hour_cap(self) -> None:
        with self.assertRaisesRegex(DiagnosticError, "after start"):
            validate_window(
                start="2026-08-24T19:00:00Z", end="2026-08-24T18:00:00Z", now=NOW
            )
        with self.assertRaisesRegex(DiagnosticError, "168"):
            validate_window(
                start="2026-08-17T19:59:59Z", end="2026-08-24T20:00:00Z", now=NOW
            )
        with self.assertRaisesRegex(DiagnosticError, "168"):
            validate_window(since_hours=169, now=NOW)
        with self.assertRaisesRegex(DiagnosticError, "future"):
            validate_window(
                start="2026-08-24T19:00:00Z",
                end="2026-08-24T20:00:02Z",
                now=NOW,
            )

    def test_result_limit_is_hard_bounded(self) -> None:
        self.assertEqual(validate_limit(200), 200)
        for value in (0, 201, True, 1.5):
            with self.subTest(value=value), self.assertRaises(DiagnosticError):
                validate_limit(value)  # type: ignore[arg-type]


class SanitizerTests(unittest.TestCase):
    def test_redacts_every_prohibited_identifier_and_secret_category(self) -> None:
        sources = [
            "Authorization: Bearer " + "eyJhbGciOiJIUzI1NiJ9.abcdefghijk.signature123",
            "Cookie: session=topsecret",
            "token=abcdef password=hunter2",
            "https://ha.example/path?token=signed&code=oauth",
            "192.0.2.22 2001:db8::99 aa:bb:cc:dd:ee:ff",
            "123456789012 arn:aws:ec2:us-west-2:123456789012:instance/i-1234567890abcdef0",
            "subnet-1234567890abcdef0 sg-1234567890abcdef0",
            r"C:\Users\alice\secret.txt /home/bob/.config user=carol",
        ]
        cleaned_values = [sanitize_text(source) for source in sources]
        cleaned = " ".join(cleaned_values)
        for forbidden in (
            "eyJhbGci", "topsecret", "abcdef", "hunter2", "signed", "oauth",
            "192.0.2.22", "2001:db8::99", "aa:bb:cc:dd:ee:ff", "123456789012",
            "i-1234567890abcdef0", "subnet-1234567890abcdef0", "sg-1234567890abcdef0",
            "alice", "bob", "carol",
        ):
            self.assertNotIn(forbidden, cleaned)
        self.assertEqual(cleaned_values[3], "https://ha.example/path")

    def test_recursive_sanitizer_blocks_sensitive_keys_process_args_and_provider_text(self) -> None:
        cleaned = sanitize(
            {
                "authorization": "Bearer secret",
                "environment": {"TOKEN": "secret"},
                "process_args": ["python", "--token", "secret"],
                "exception": "provider secret at 192.0.2.3",
                "provider_response": "cookie: session=secret",
                "summary": "safe failure at 192.0.2.4",
            }
        )
        self.assertEqual(cleaned["authorization"], "[REDACTED]")
        self.assertEqual(cleaned["environment"], "[REDACTED]")
        self.assertEqual(cleaned["process_args"], "[REDACTED]")
        self.assertEqual(cleaned["exception"], "[REDACTED]")
        self.assertEqual(cleaned["provider_response"], "[REDACTED]")
        self.assertNotIn("192.0.2.4", cleaned["summary"])

    def test_summary_is_single_line_and_bounded(self) -> None:
        cleaned = sanitize_text("x\n" * 1000)
        self.assertNotIn("\n", cleaned)
        self.assertLessEqual(len(cleaned), 512)
        self.assertTrue(cleaned.endswith("...[truncated]"))


class SnapshotTests(DiagnosticsFixture):
    def test_healthy_snapshot_reports_freshness_and_tunnel_metrics(self) -> None:
        self.write_current()
        result = self.reader.get_current_health(now=NOW)
        self.assertTrue(result["collector"]["available"])
        self.assertTrue(result["fresh"])
        self.assertTrue(result["complete"])
        self.assertEqual(result["freshness_seconds"], 30.0)
        self.assertEqual(
            result["health"]["containers"]["cloudflare_tunnel"]["metrics"]["active_replicas"],
            2,
        )

    def test_stale_missing_and_malformed_sources_fail_closed(self) -> None:
        missing = self.reader.get_current_health(now=NOW)
        self.assertFalse(missing["collector"]["available"])
        self.assertNotIn("health", missing)
        self.write_current(timestamp="2026-08-24T19:00:00Z")
        stale = self.reader.get_current_health(now=NOW)
        self.assertFalse(stale["fresh"])
        self.assertFalse(stale["complete"])
        (self.root / "current.json").write_text("not json", encoding="utf-8")
        malformed = self.reader.get_current_health(now=NOW)
        self.assertEqual(malformed["collector"]["reason"], "malformed")

    def test_oversized_current_file_is_not_partially_parsed(self) -> None:
        (self.root / "current.json").write_bytes(b"{" + b"x" * MAX_CURRENT_BYTES)
        result = self.reader.get_current_health(now=NOW)
        self.assertEqual(result["collector"]["reason"], "oversized")
        self.assertTrue(result["collector"]["truncated"])
        self.assertNotIn("health", result)

    def test_fixed_path_rejects_symlink(self) -> None:
        target = self.root / "outside.json"
        target.write_text("{}", encoding="utf-8")
        link = self.root / "current.json"
        try:
            link.symlink_to(target)
        except OSError:
            self.skipTest("symlinks are unavailable on this platform")
        with self.assertRaises(DiagnosticError):
            self.reader.get_current_health(now=NOW)


class EventAndCauseTests(DiagnosticsFixture):
    def test_absent_event_file_is_complete_when_collector_coverage_proves_zero_events(self) -> None:
        self.write_current(
            collector={
                "status": "healthy",
                "historical_backfill": {
                    "completed": True,
                    "complete": True,
                    "window_start": "2026-08-16T19:59:30Z",
                    "window_end": "2026-08-24T19:50:00Z",
                },
                "incremental_sources": {
                    "window_start": "2026-08-24T19:58:30Z",
                    "window_end": "2026-08-24T19:59:30Z",
                    "docker_events": {"available": True, "truncated": False},
                    "journald": {
                        "kernel": {"available": True, "truncated": False},
                        "docker": {"available": True, "truncated": False},
                    },
                    "cloudflared_logs": {"available": True, "truncated": False},
                    "reverse_proxy_logs": {"available": True, "truncated": False},
                },
            }
        )
        result = self.reader.get_diagnostic_events(since_hours=2, now=NOW)
        self.assertEqual(result["events"], [])
        self.assertTrue(result["source"]["available"])
        self.assertTrue(result["source"]["complete"])
        self.assertEqual(
            result["source"]["files"][0]["reason"],
            "no_records_in_covered_window",
        )

    def test_absent_event_file_is_incomplete_when_backfill_is_incomplete(self) -> None:
        self.write_current(
            collector={
                "status": "healthy",
                "historical_backfill": {
                    "completed": True,
                    "complete": False,
                    "window_start": "2026-08-16T19:59:30Z",
                    "window_end": "2026-08-24T19:50:00Z",
                },
            }
        )
        result = self.reader.get_diagnostic_events(since_hours=2, now=NOW)
        self.assertFalse(result["source"]["available"])
        self.assertFalse(result["source"]["complete"])

    def test_filters_and_result_cap_are_enforced(self) -> None:
        records = [
            self.event(
                "probe_failure",
                timestamp=f"2026-08-24T19:{minute:02d}:00Z",
                component="endpoint_probe",
                severity="error" if minute % 2 else "warning",
            )
            for minute in range(10)
        ]
        self.write_jsonl("events", *records)
        result = self.reader.get_diagnostic_events(
            since_hours=2,
            components=["endpoint_probe"],
            severities=["error"],
            limit=3,
            now=NOW,
        )
        self.assertEqual(result["count"], 3)
        self.assertTrue(result["truncated"])
        self.assertTrue(all(item["severity"] == "error" for item in result["events"]))
        with self.assertRaises(DiagnosticError):
            self.reader.get_diagnostic_events(components=["arbitrary"], now=NOW)

    def test_home_assistant_restart_and_clean_sigterm_remain_unknown_without_audit(self) -> None:
        self.write_jsonl(
            "events",
            self.event("container_stop", signal="SIGTERM", exit_code=0),
            self.event("container_start", timestamp="2026-08-24T19:53:07Z", severity="info"),
        )
        self.write_jsonl("samples", {"timestamp": "2026-08-24T19:53:00Z", "memory": 41})
        result = self.reader.get_restart_outage_diagnostics(since_hours=2, now=NOW)
        stop = next(item for item in result["events"] if item["event_type"] == "container_stop")
        self.assertEqual(stop["cause"], Cause.UNKNOWN.value)
        self.assertEqual(result["sample_count"], 1)

    def test_exit_137_requires_direct_nearby_oom_evidence(self) -> None:
        exit_event = self.event("container_exit", exit_code=137)
        self.write_jsonl("events", exit_event)
        without_oom = self.reader.get_restart_outage_diagnostics(since_hours=2, now=NOW)
        self.assertEqual(without_oom["events"][0]["cause"], Cause.UNKNOWN.value)
        self.write_jsonl(
            "events",
            exit_event,
            self.event(
                "cgroup_oom_kill",
                timestamp="2026-08-24T19:53:05Z",
                component="cgroup",
                severity="critical",
            ),
        )
        with_oom = self.reader.get_restart_outage_diagnostics(since_hours=2, now=NOW)
        exit_result = next(item for item in with_oom["events"] if item.get("exit_code") == 137)
        self.assertEqual(exit_result["cause"], Cause.OOM_KILL.value)

    def test_crash_host_reboot_docker_restart_and_direct_markers_are_classified(self) -> None:
        self.write_jsonl(
            "events",
            self.event("container_exit", exit_code=1),
            self.event("host_boot", component="systemd", boot_changed=True),
            self.event("docker_restart", component="docker"),
            self.event("deployment_restart", component="mcp"),
            self.event("watchdog_restart", component="systemd", initiator="watchdog"),
        )
        result = self.reader.get_restart_outage_diagnostics(since_hours=2, now=NOW)
        causes = {item["event_type"]: item["cause"] for item in result["events"]}
        self.assertEqual(causes["container_exit"], Cause.PROCESS_CRASH.value)
        self.assertEqual(causes["host_boot"], Cause.HOST_REBOOT.value)
        self.assertEqual(causes["docker_restart"], Cause.DOCKER_RESTART.value)
        self.assertEqual(causes["deployment_restart"], Cause.DEPLOYMENT_RESTART.value)
        self.assertEqual(causes["watchdog_restart"], Cause.WATCHDOG_RESTART.value)

    def test_tunnel_and_independent_route_failures_are_distinct(self) -> None:
        self.write_jsonl(
            "events",
            self.event("disconnect", component="cloudflare_tunnel", severity="error"),
            self.event(
                "probe_failure",
                timestamp="2026-08-24T19:54:00Z",
                component="endpoint_probe",
                severity="error",
                http_status=530,
                summary="Frontend route failed while MCP remained healthy",
            ),
            self.event(
                "endpoint_failure",
                timestamp="2026-08-24T19:55:00Z",
                component="endpoint_probe",
                severity="error",
                http_status=502,
                summary="MCP route failed while frontend remained healthy",
            ),
        )
        result = self.reader.get_restart_outage_diagnostics(since_hours=2, now=NOW)
        causes = {item["event_type"]: item["cause"] for item in result["events"]}
        self.assertEqual(causes["disconnect"], Cause.TUNNEL_FAILURE.value)
        self.assertEqual(causes["probe_failure"], Cause.ENDPOINT_FAILURE.value)
        self.assertEqual(causes["endpoint_failure"], Cause.ENDPOINT_FAILURE.value)

    def test_missing_journal_cgroup_and_samples_are_explicit(self) -> None:
        self.write_jsonl(
            "events",
            self.event(
                "source_unavailable",
                component="kernel",
                severity="warning",
                summary="Kernel journal source unavailable",
                complete=False,
            ),
            self.event(
                "source_unavailable",
                component="cgroup",
                severity="warning",
                summary="Cgroup counters unavailable",
                complete=False,
            ),
        )
        result = self.reader.get_restart_outage_diagnostics(since_hours=2, now=NOW)
        self.assertIn("resource_samples", result["unavailable_sources"])
        self.assertFalse(result["complete"])

    def test_malformed_and_oversized_lines_are_skipped_and_marked_incomplete(self) -> None:
        path = self.root / "events-2026-08-24.jsonl"
        path.write_bytes(
            (json.dumps(self.event("container_start")) + "\n").encode()
            + b"not-json\n"
            + b"x" * (MAX_JSONL_LINE_BYTES + 1)
            + b"\n"
        )
        result = self.reader.get_diagnostic_events(since_hours=2, now=NOW)
        self.assertEqual(result["count"], 1)
        self.assertFalse(result["source"]["complete"])
        source = result["source"]["files"][0]
        self.assertEqual(source["malformed_records"], 1)
        self.assertEqual(source["oversized_records"], 1)

    def test_daily_files_preserve_events_across_reader_restart(self) -> None:
        self.write_jsonl("events", self.event("container_restart"))
        first = self.reader.get_diagnostic_events(since_hours=2, now=NOW)
        second = DiagnosticsReader(self.root).get_diagnostic_events(since_hours=2, now=NOW)
        self.assertEqual(first["events"], second["events"])


class FixedRouteTests(DiagnosticsFixture, unittest.IsolatedAsyncioTestCase):
    async def test_only_fixed_routes_are_probed_and_tunnel_snapshot_is_included(self) -> None:
        self.write_current()
        dns = AsyncMock(side_effect=[{"success": True}, {"success": True}])
        tls = AsyncMock(side_effect=[{"valid": True}, {"valid": True}])
        bootstrap = AsyncMock(
            side_effect=[
                {"reachable": True, "http_status": 200, "bootstrap_marker": True},
                {"reachable": True, "http_status": 200, "bootstrap_marker": True},
            ]
        )
        http = AsyncMock(
            side_effect=[
                {"reachable": True, "http_status": 200, "expected_response": True},
                {"reachable": True, "http_status": 200, "expected_response": True},
            ]
        )
        protocol = AsyncMock(
            side_effect=[
                {"protocol_auth_reachable": True, "http_status": 401},
                {"protocol_auth_reachable": True, "http_status": 401},
            ]
        )
        websocket = AsyncMock(
            side_effect=[
                {"reachable": True, "safe_greeting": True},
                {"reachable": True, "safe_greeting": True},
            ]
        )
        with (
            patch.object(self.reader, "_dns_probe", dns),
            patch.object(self.reader, "_tls_probe", tls),
            patch.object(self.reader, "_ha_bootstrap_probe", bootstrap),
            patch.object(self.reader, "_http_probe", http),
            patch.object(self.reader, "_mcp_protocol_probe", protocol),
            patch.object(self.reader, "_websocket_greeting_probe", websocket),
        ):
            result = await self.reader.get_fixed_route_health(now=NOW)
        called_urls = [call.args[0] for call in http.await_args_list]
        self.assertEqual(
            called_urls,
            [
                "https://mcp.example.com/healthz",
                "http://127.0.0.1:8000/healthz",
            ],
        )
        self.assertEqual(
            [call.args[0] for call in protocol.await_args_list],
            [
                "https://mcp.example.com/mcp",
                "http://127.0.0.1:8000/mcp",
            ],
        )
        self.assertTrue(result["fixed_routes_only"])
        self.assertTrue(
            result["routes"]["mcp"]["external"]["protocol"][
                "protocol_auth_reachable"
            ]
        )
        self.assertNotIn(
            "api_auth",
            result["routes"]["home_assistant_frontend"]["external"],
        )
        self.assertNotIn(
            "api_auth",
            result["routes"]["home_assistant_frontend"]["local_origin"],
        )
        self.assertEqual(
            result["cloudflare_tunnel"]["metrics"]["active_replicas"], 2
        )

    async def test_frontend_and_mcp_route_failures_remain_independent(self) -> None:
        bootstrap = AsyncMock(
            side_effect=[
                {"reachable": False},
                {"reachable": True, "http_status": 200, "expected_response": True},
            ]
        )
        http = AsyncMock(
            side_effect=[
                {"reachable": True, "http_status": 200, "expected_response": True},
                {"reachable": True, "http_status": 200, "expected_response": True},
            ]
        )
        protocol = AsyncMock(
            side_effect=[
                {"reachable": True, "http_status": 401, "expected_response": True},
                {"reachable": False, "protocol_auth_reachable": False},
            ]
        )
        with (
            patch.object(self.reader, "_dns_probe", AsyncMock(return_value={"success": True})),
            patch.object(self.reader, "_tls_probe", AsyncMock(return_value={"valid": True})),
            patch.object(self.reader, "_ha_bootstrap_probe", bootstrap),
            patch.object(self.reader, "_http_probe", http),
            patch.object(self.reader, "_mcp_protocol_probe", protocol),
            patch.object(
                self.reader,
                "_websocket_greeting_probe",
                AsyncMock(return_value={"reachable": False, "safe_greeting": False}),
            ),
        ):
            result = await self.reader.get_fixed_route_health(now=NOW)
        self.assertFalse(
            result["routes"]["home_assistant_frontend"]["external"]["frontend"][
                "reachable"
            ]
        )
        self.assertTrue(
            result["routes"]["mcp"]["external"]["protocol"]["reachable"]
        )

    async def test_mcp_probe_posts_minimal_initialize_and_requires_bearer_challenge(self) -> None:
        requests: list[tuple[str, dict[str, object]]] = []

        class Content:
            async def read(self, limit: int) -> bytes:
                self.limit = limit
                return b'{"error":"unauthorized"}'

        class Response:
            status = 401
            headers = {"WWW-Authenticate": 'Bearer resource_metadata="fixed"'}
            content = Content()

            async def __aenter__(self) -> "Response":
                return self

            async def __aexit__(self, *args: object) -> None:
                return None

        class Session:
            async def __aenter__(self) -> "Session":
                return self

            async def __aexit__(self, *args: object) -> None:
                return None

            def post(self, url: str, **kwargs: object) -> Response:
                requests.append((url, kwargs))
                return Response()

        with patch("app.diagnostics.aiohttp.ClientSession", return_value=Session()):
            result = await self.reader._mcp_protocol_probe(
                "https://mcp.example.com/mcp"
            )
        self.assertTrue(result["protocol_auth_reachable"])
        self.assertEqual(len(requests), 1)
        url, kwargs = requests[0]
        self.assertEqual(url, "https://mcp.example.com/mcp")
        self.assertFalse(kwargs["allow_redirects"])
        self.assertEqual(kwargs["json"]["method"], "initialize")  # type: ignore[index]
        self.assertNotIn("Authorization", kwargs["headers"])  # type: ignore[operator]


if __name__ == "__main__":
    unittest.main()
