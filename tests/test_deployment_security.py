"""Static regression tests for the production diagnostics privilege boundary.

These checks deliberately inspect the deployable artifacts instead of mocking
them. They make a future Compose, systemd, collector, or deployment edit fail
closed before it reaches the production host.
"""

from __future__ import annotations

import ast
import re
import shlex
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.yml"
DOCKERFILE = ROOT / "Dockerfile"
UNIT = ROOT / "collector" / "ha-host-diagnostics.service"
COLLECTOR = ROOT / "collector" / "ha_host_diagnostics.py"
DEPLOY = ROOT / "scripts" / "deploy-production.ps1"


def _without_comments(text: str) -> str:
    """Remove comment-only YAML/shell lines without altering quoted values."""
    return "\n".join(line for line in text.splitlines() if not re.match(r"^\s*#", line))


def _compose_service(text: str, name: str) -> str:
    """Return a top-level Compose service body using indentation, not spacing."""
    lines = text.splitlines()
    services_at = next(
        i for i, line in enumerate(lines) if re.match(r"^services\s*:\s*$", line)
    )
    service_re = re.compile(rf"^(?P<i>[ \t]+){re.escape(name)}\s*:\s*$")
    start = None
    indent = None
    for i in range(services_at + 1, len(lines)):
        match = service_re.match(lines[i])
        if match:
            start, indent = i + 1, len(match.group("i").expandtabs(8))
            break
    if start is None or indent is None:
        raise AssertionError(f"Compose service {name!r} is missing")
    end = len(lines)
    for i in range(start, len(lines)):
        line = lines[i]
        if not line.strip():
            continue
        current = len(line) - len(line.lstrip(" \t"))
        if current <= indent:
            end = i
            break
    return "\n".join(lines[start:end])


def _direct_value(block: str, key: str) -> str | None:
    """Read a scalar directly under a Compose service (not a nested mount)."""
    lines = [line for line in block.splitlines() if line.strip()]
    if not lines:
        return None
    base = min(len(line) - len(line.lstrip(" \t")) for line in lines)
    pattern = re.compile(
        rf"^[ \t]{{{base}}}{re.escape(key)}\s*:\s*(.*?)\s*$", re.IGNORECASE
    )
    for line in lines:
        match = pattern.match(line)
        if match:
            return match.group(1).strip().strip("'\"")
    return None


def _direct_sequence(block: str, key: str) -> list[str]:
    """Read a simple scalar/list value directly under a Compose service."""
    lines = block.splitlines()
    populated = [line for line in lines if line.strip()]
    if not populated:
        return []
    base = min(len(line) - len(line.lstrip(" \t")) for line in populated)
    header = re.compile(rf"^[ \t]{{{base}}}{re.escape(key)}\s*:\s*(.*?)\s*$", re.I)
    for index, line in enumerate(lines):
        match = header.match(line)
        if not match:
            continue
        inline = match.group(1).strip()
        if inline:
            if inline.startswith("[") and inline.endswith("]"):
                return [v.strip().strip("'\"") for v in inline[1:-1].split(",")]
            return shlex.split(inline, posix=True)
        values: list[str] = []
        for child in lines[index + 1 :]:
            if not child.strip():
                continue
            indent = len(child) - len(child.lstrip(" \t"))
            if indent <= base:
                break
            item = re.match(r"^\s*-\s*(.*?)\s*$", child)
            if item:
                values.append(item.group(1).strip().strip("'\""))
        return values
    return []


def _sequence_item_containing(block: str, needle: str) -> str:
    """Return the YAML list item which contains needle."""
    lines = block.splitlines()
    target = next((i for i, line in enumerate(lines) if needle in line), None)
    if target is None:
        raise AssertionError(f"No YAML item contains {needle!r}")
    start = None
    item_indent = None
    for i in range(target, -1, -1):
        match = re.match(r"^(?P<i>\s*)-\s+", lines[i])
        if match:
            start = i
            item_indent = len(match.group("i"))
            break
    if start is None or item_indent is None:
        raise AssertionError(f"No YAML sequence item owns {needle!r}")
    end = len(lines)
    for i in range(start + 1, len(lines)):
        match = re.match(r"^(?P<i>\s*)-\s+", lines[i])
        if match and len(match.group("i")) <= item_indent:
            end = i
            break
    return "\n".join(lines[start:end])


def _unit_directives(text: str, section: str = "Service") -> dict[str, list[str]]:
    current = None
    result: dict[str, list[str]] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        header = re.fullmatch(r"\[([^]]+)]", line)
        if header:
            current = header.group(1)
            continue
        if current == section and "=" in line:
            key, value = line.split("=", 1)
            result.setdefault(key.strip(), []).append(value.strip())
    return result


def _assignment_nodes(tree: ast.AST) -> dict[str, ast.AST]:
    assignments: dict[str, ast.AST] = {}
    for node in getattr(tree, "body", []):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            for target in targets:
                if isinstance(target, ast.Name) and value is not None:
                    assignments[target.id] = value
    return assignments


def _integer_expression(node: ast.AST) -> int:
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mult)):
        left, right = _integer_expression(node.left), _integer_expression(node.right)
        return left + right if isinstance(node.op, ast.Add) else left * right
    raise AssertionError(f"Expected a fixed integer expression, got {ast.dump(node)}")


def _literal_string_collection(node: ast.AST) -> set[str]:
    if not isinstance(node, (ast.Set, ast.Dict, ast.List, ast.Tuple)):
        raise AssertionError(
            f"Expected a fixed literal collection, got {ast.dump(node)}"
        )
    values = node.keys if isinstance(node, ast.Dict) else node.elts
    result = set()
    for item in values:
        if not isinstance(item, ast.Constant) or not isinstance(item.value, str):
            raise AssertionError(
                "Security allowlists must contain only string literals"
            )
        result.add(item.value)
    return result


class ComposeDeploymentSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = _without_comments(COMPOSE.read_text(encoding="utf-8"))
        cls.mcp = _compose_service(cls.text, "ha-chatgpt-mcp")
        cls.tunnel = _compose_service(cls.text, "cloudflared")

    def test_diagnostics_export_is_one_fixed_read_only_bind(self) -> None:
        self.assertEqual(self.text.count("/host-diagnostics"), 2)
        self.assertEqual(self.text.count("/var/lib/ha-host-diagnostics/export"), 1)
        item = _sequence_item_containing(
            self.mcp, "/var/lib/ha-host-diagnostics/export"
        )
        self.assertRegex(item, r"(?m)^\s*-\s*type\s*:\s*bind\s*$")
        self.assertRegex(
            item,
            r"(?m)^\s*source\s*:\s*['\"]?/var/lib/ha-host-diagnostics/export['\"]?\s*$",
        )
        self.assertRegex(
            item, r"(?m)^\s*target\s*:\s*['\"]?/host-diagnostics['\"]?\s*$"
        )
        self.assertRegex(item, r"(?mi)^\s*read_only\s*:\s*true\s*$")
        self.assertRegex(item, r"(?mi)^\s*create_host_path\s*:\s*false\s*$")

    def test_mcp_has_no_host_control_surface_mount(self) -> None:
        forbidden = (
            r"(?:/var)?/run/docker\.sock",
            r"(?<![-\w])/proc(?:/|\s|:|$)",
            r"(?<![-\w])/sys(?:/|\s|:|$)",
            r"/run/log/journal(?:/|\s|:|$)",
            r"/var/log/journal(?:/|\s|:|$)",
        )
        for pattern in forbidden:
            self.assertNotRegex(self.mcp, pattern)

    def test_both_containers_keep_their_sandbox(self) -> None:
        for name, block in (("ha-chatgpt-mcp", self.mcp), ("cloudflared", self.tunnel)):
            with self.subTest(service=name):
                self.assertEqual(
                    (_direct_value(block, "read_only") or "").lower(), "true"
                )
                self.assertIsNone(_direct_value(block, "privileged"))
                self.assertIsNone(_direct_value(block, "cap_add"))
                self.assertEqual(
                    {value.upper() for value in _direct_sequence(block, "cap_drop")},
                    {"ALL"},
                )
                self.assertIn(
                    "no-new-privileges:true",
                    {
                        value.lower().replace(" ", "")
                        for value in _direct_sequence(block, "security_opt")
                    },
                )
                groups = {
                    value.lower() for value in _direct_sequence(block, "group_add")
                }
                self.assertLessEqual(
                    groups,
                    {"0"},
                    "only the pre-existing root group may be retained",
                )

    def test_compose_publishes_no_port_and_metrics_are_loopback_only(self) -> None:
        for name, block in (("ha-chatgpt-mcp", self.mcp), ("cloudflared", self.tunnel)):
            with self.subTest(service=name):
                self.assertIsNone(_direct_value(block, "ports"))
                self.assertIsNone(_direct_value(block, "expose"))
        command = _direct_sequence(self.tunnel, "command")
        for index, token in enumerate(command):
            if token == "--metrics":
                self.assertLess(index + 1, len(command))
                self.assertRegex(command[index + 1], r"^127\.0\.0\.1:\d{2,5}$")
            elif token.startswith("--metrics="):
                self.assertRegex(token, r"^--metrics=127\.0\.0\.1:\d{2,5}$")
        self.assertNotRegex(" ".join(command), r"(?:0\.0\.0\.0|\[?::\]?):\d+")
        metrics_token = next(
            (
                command[index + 1]
                for index, token in enumerate(command[:-1])
                if token == "--metrics"
            ),
            next(
                (
                    token.removeprefix("--metrics=")
                    for token in command
                    if token.startswith("--metrics=")
                ),
                None,
            ),
        )
        if metrics_token is not None:
            port = metrics_token.rsplit(":", 1)[1]
            collector = COLLECTOR.read_text(encoding="utf-8")
            self.assertRegex(
                collector,
                rf"""["']http://127\.0\.0\.1:{re.escape(port)}/metrics["']""",
                "collector and cloudflared must use the same loopback metrics port",
            )

    def test_runtime_image_itself_is_non_root_and_loopback_only(self) -> None:
        dockerfile = _without_comments(DOCKERFILE.read_text(encoding="utf-8"))
        self.assertRegex(dockerfile, r"(?mi)^\s*USER\s+10001(?::10001)?\s*$")
        self.assertRegex(
            dockerfile,
            r"(?mi)^\s*(?:CMD|ENTRYPOINT)\b[^\n]*127\.0\.0\.1[^\n]*8000",
        )


class CollectorUnitSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = UNIT.read_text(encoding="utf-8")
        cls.directives = _unit_directives(cls.text)

    def test_unit_has_no_socket_activation_or_listener(self) -> None:
        self.assertNotRegex(self.text, r"(?mi)^\s*\[Socket]\s*$")
        self.assertNotRegex(
            self.text,
            r"(?mi)^\s*(?:ListenStream|ListenDatagram|ListenSequentialPacket|SocketUser|SocketGroup)\s*=",
        )
        starts = self.directives.get("ExecStart", [])
        self.assertEqual(len(starts), 1)
        self.assertEqual(
            shlex.split(starts[0], posix=True),
            [
                "/usr/bin/python3",
                "/opt/ha-host-diagnostics/ha_host_diagnostics.py",
                "run",
            ],
        )

    def test_unit_has_only_export_ownership_capability(self) -> None:
        expected = {
            "User": "root",
            "Group": "root",
            "NoNewPrivileges": "yes",
            "PrivateTmp": "yes",
            "PrivateDevices": "yes",
            "ProtectSystem": "strict",
            "ProtectHome": "yes",
            "ProtectKernelTunables": "yes",
            "ProtectKernelModules": "yes",
            "ProtectControlGroups": "yes",
            "RestrictNamespaces": "yes",
            "RestrictSUIDSGID": "yes",
            "LockPersonality": "yes",
        }
        for key, value in expected.items():
            with self.subTest(directive=key):
                self.assertEqual(self.directives.get(key), [value])
        self.assertEqual(self.directives.get("CapabilityBoundingSet"), ["CAP_CHOWN"])
        self.assertEqual(self.directives.get("AmbientCapabilities"), [""])

    def test_only_collector_state_is_writable(self) -> None:
        writable: list[str] = []
        for directive in self.directives.get("ReadWritePaths", []):
            writable.extend(shlex.split(directive, posix=True))
        self.assertEqual(writable, ["/var/lib/ha-host-diagnostics"])

    def test_deployment_restarts_collector_and_requires_fresh_snapshot(self) -> None:
        deploy = (ROOT / "scripts" / "deploy-production.ps1").read_text(encoding="utf-8")
        self.assertIn("sudo systemctl restart ha-host-diagnostics.service", deploy)
        self.assertIn("collector_started_epoch=$(date -u +%s)", deploy)
        self.assertIn("stage='awaiting_fresh_collector_snapshot'", deploy)
        self.assertIn('sudo test -s "$collector_state/export/current.json"', deploy)
        self.assertIn('sudo stat -c %Y "$collector_state/export/current.json"', deploy)
        self.assertIn('[ "$collector_snapshot_epoch" -ge "$collector_started_epoch" ]', deploy)
        self.assertIn("(payload.get('collector') or {}).get('observed_at')", deploy)
        self.assertIn("sudo python3 - <<'PY'", deploy)
        self.assertNotIn("systemctl enable --now ha-host-diagnostics.service", deploy)


class DeploymentScriptSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = DEPLOY.read_text(encoding="utf-8")
        cls.folded = re.sub(r"\\\r?\n\s*", " ", cls.text)
        cls.install_commands = []
        for line in cls.folded.splitlines():
            if re.match(r"^\s*(?:sudo\s+)?install\b", line):
                cls.install_commands.append(shlex.split(line.strip(), posix=True))

    def test_release_is_pinned_to_2_6_2(self) -> None:
        self.assertRegex(
            self.text,
            r"(?m)^\s*\$releaseVersion\s*=\s*['\"]2\.6\.2['\"]\s*$",
        )
        self.assertRegex(self.text, r"(?m)^\s*release_version=['\"]2\.6\.2['\"]\s*$")

    def test_tests_run_before_main_container_recreation(self) -> None:
        main = self.text[
            self.text.index("mutated=1") : self.text.index("record_marker completed")
        ]
        test = re.search(
            r"docker\s+compose\s+run\b[^\r\n]*(?:unittest|pytest)", main, re.I
        )
        recreate = re.search(
            r"(?m)^[^\r\n]*docker\s+compose\s+up\b[^\r\n]*--force-recreate\b[^\r\n]*$",
            main,
            re.I,
        )
        self.assertIsNotNone(
            test, "deployment must run the test suite in the built image"
        )
        self.assertIsNotNone(
            recreate, "deployment must use an explicit bounded recreation"
        )
        self.assertLess(test.start(), recreate.start())
        self.assertRegex(recreate.group(0), r"\bha-chatgpt-mcp\b")
        self.assertNotRegex(recreate.group(0), r"(?:^|\s)homeassistant(?:\s|$)")

    def test_protected_ha_route_accepts_only_expected_access_responses(self) -> None:
        self.assertIn("ha_public_status=$(curl", self.text)
        self.assertIn("200|302|403", self.text)
        self.assertNotIn("curl --fail --silent --max-time 10 http://", self.text)

    def test_retention_check_parses_full_iso_date_suffix(self) -> None:
        self.assertIn("dt.date.fromisoformat(path.stem[-10:])", self.text)
        self.assertNotIn("path.stem.rsplit('-', 1)[-1]", self.text)

    def test_host_security_tests_run_on_release_tree_not_runtime_image(self) -> None:
        dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
        self.assertIn("tests/test_deployment_security.py", dockerignore)
        host_test_at = self.text.index(
            "sudo /usr/bin/python3 -m unittest tests.test_deployment_security -v"
        )
        build_at = self.text.index('sudo docker build -t "ha-chatgpt-mcp:$release_version" .')
        self.assertLess(host_test_at, build_at)

    def test_collector_installation_uses_fixed_root_ownership(self) -> None:
        def installed(
            target: str, *, owner: str, group: str, mode: str
        ) -> list[list[str]]:
            matching = [
                command for command in self.install_commands if command[-1] == target
            ]
            self.assertTrue(matching, f"expected an install command for {target}")
            for command in matching:
                for option, value in (("-o", owner), ("-g", group), ("-m", mode)):
                    self.assertIn(option, command)
                    self.assertEqual(command[command.index(option) + 1], value)
            return matching

        state = installed(
            "$collector_state/state", owner="root", group="root", mode="0700"
        )
        export = installed(
            "$collector_state/export", owner="root", group="10001", mode="0750"
        )
        program = installed(
            "$collector_program", owner="root", group="root", mode="0750"
        )
        unit = installed("$collector_unit", owner="root", group="root", mode="0644")
        self.assertTrue(all("-d" in command for command in state))
        self.assertTrue(all("-d" in command for command in export))
        self.assertTrue(
            all(
                any(value.endswith("/ha_host_diagnostics.py") for value in command)
                for command in program
            )
        )
        self.assertTrue(
            any(
                any(value.endswith("/ha-host-diagnostics.service") for value in command)
                for command in unit
            )
        )
        self.assertIn("0:10001:750", self.text)
        self.assertIn("root:10001:640", self.text)

    def test_deployment_never_controls_home_assistant(self) -> None:
        forbidden = (
            r"(?mi)^\s*(?:sudo\s+)?docker\s+(?:container\s+)?(?:exec|restart|stop|kill|rm)\b[^\r\n]*(?:^|\s)['\"]?homeassistant['\"]?(?:\s|$)",
            r"(?mi)^\s*(?:sudo\s+)?docker\s+compose\s+(?:exec|restart|stop|kill|rm|up)\b[^\r\n]*(?:^|\s)['\"]?homeassistant['\"]?(?:\s|$)",
            r"(?mi)^\s*(?:sudo\s+)?systemctl\s+(?:restart|stop|start|reload|try-restart)\b[^\r\n]*(?:home-assistant|homeassistant)(?:\.service)?(?:\s|$)",
        )
        for pattern in forbidden:
            self.assertNotRegex(self.text, pattern)
        self.assertNotIn("/opt/homeassistant/config", self.text.lower())
        self.assertNotIn("configuration.yaml", self.text.lower())
        self.assertNotRegex(
            self.text,
            r"(?mi)^\s*(?:sudo\s+)?(?:caddy|systemctl)\b[^\r\n]*(?:reload|restart|stop|start)[^\r\n]*caddy",
        )

    def test_only_temporary_current_ip_ssh_firewall_is_changed(self) -> None:
        self.assertEqual(self.text.count("open-instance-public-ports"), 1)
        self.assertEqual(self.text.count("close-instance-public-ports"), 2)
        self.assertRegex(
            self.text, r"""\$temporarySshCidr\s*=\s*["']\$currentIp/32["']"""
        )
        ssh_rule = r"fromPort=22,toPort=22,protocol=tcp,cidrs=\$temporarySshCidr"
        self.assertEqual(len(re.findall(ssh_rule, self.text)), 3)
        self.assertIn("Start-Sleep -Seconds 1200", self.text)
        self.assertRegex(
            self.text,
            r"(?s)Start-Process.+?-WindowStyle\s+Hidden\s+-PassThru",
        )
        self.assertNotRegex(
            self.text,
            r"(?i)\b(?:put-instance-public-ports|authorize-security-group-ingress|revoke-security-group-ingress)\b",
        )
        finally_at = self.text.rfind("finally {")
        self.assertGreaterEqual(finally_at, 0)
        self.assertIn("close-instance-public-ports", self.text[finally_at:])

    def test_script_does_not_emit_secrets(self) -> None:
        self.assertIn("set +x", self.text)
        self.assertNotRegex(self.text, r"(?mi)^\s*set\s+-x\b")
        self.assertNotRegex(self.text, r"(?mi)^\s*(?:Write-Host|Write-Output)\b")
        self.assertNotRegex(
            self.text,
            r"(?mi)^\s*(?:echo|printf)\b[^\r\n]*(?:secret|token|password|credential|authorization|privateKey|certKey)",
        )
        self.assertNotRegex(self.text, r"(?mi)^\s*(?:env|printenv)\b")
        self.assertNotRegex(
            self.text,
            r"(?mi)^\s*(?:cat|Get-Content)\b[^\r\n]*(?:secret|token|credential|privateKey|certKey)",
        )


class CollectorSourceSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = COLLECTOR.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.text, filename=str(COLLECTOR))
        cls.assignments = _assignment_nodes(cls.tree)

    def test_no_shell_execution_primitives(self) -> None:
        for node in ast.walk(self.tree):
            if isinstance(node, ast.ImportFrom) and node.module == "subprocess":
                self.fail("subprocess must not be imported into unqualified call names")
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name):
                self.assertNotIn(
                    node.func.id,
                    {"system", "popen", "Popen", "call", "check_call", "check_output"},
                )
            if isinstance(node.func, ast.Attribute):
                owner = (
                    node.func.value.id
                    if isinstance(node.func.value, ast.Name)
                    else None
                )
                self.assertFalse(
                    owner == "os" and node.func.attr in {"system", "popen"},
                    "collector must never invoke a shell through os",
                )
                if owner == "subprocess":
                    self.assertIn(
                        node.func.attr,
                        {"run", "Popen"},
                        "only bounded argv-based subprocess execution is allowed",
                    )
                    self.assertTrue(node.args, "subprocess calls require an argv")
                    self.assertNotIsInstance(
                        node.args[0],
                        (ast.Constant, ast.JoinedStr),
                        "subprocess commands must not be shell strings",
                    )
                    shell = next(
                        (kw.value for kw in node.keywords if kw.arg == "shell"), None
                    )
                    if shell is not None:
                        self.assertIsInstance(shell, ast.Constant)
                        self.assertIs(shell.value, False)
        self.assertNotRegex(self.text, r"(?m)\bshell\s*=\s*True\b")

    def test_cli_has_only_fixed_actions_and_bounded_deployment_metadata(self) -> None:
        parser_names: set[str] = set()
        options: set[str] = set()
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call) or not isinstance(
                node.func, ast.Attribute
            ):
                continue
            if node.func.attr == "add_parser" and node.args:
                self.assertIsInstance(node.args[0], ast.Constant)
                parser_names.add(node.args[0].value)
            if node.func.attr == "add_argument" and node.args:
                for arg in node.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        options.add(arg.value)
        self.assertEqual(parser_names, {"run", "once", "validate", "mark-deployment"})
        self.assertEqual(options, {"--version", "--phase"})
        self.assertFalse(
            any(
                re.search(
                    r"url|path|command|container|service|host|endpoint", value, re.I
                )
                for value in options
            )
        )

    def test_components_containers_and_probe_endpoints_are_fixed(self) -> None:
        expected_components = {
            "home_assistant",
            "mcp",
            "docker",
            "kernel",
            "cgroup",
            "systemd",
            "cloudflare_tunnel",
            "wireguard",
            "reverse_proxy",
            "endpoint_probe",
        }
        self.assertEqual(
            _literal_string_collection(self.assignments["COMPONENTS"]),
            expected_components,
        )
        containers = self.assignments["CONTAINERS"]
        self.assertIsInstance(containers, ast.Dict)
        self.assertEqual(
            ast.literal_eval(containers),
            {
                "home_assistant": "homeassistant",
                "mcp": "ha-chatgpt-mcp",
                "cloudflare_tunnel": "ha-chatgpt-cloudflared",
                "reverse_proxy": "caddy",
            },
        )

        fixed_probe_values: set[str] = set()
        configured_probe_names: set[str] = set()
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call) or not isinstance(
                node.func, ast.Attribute
            ):
                continue
            if node.func.attr not in {
                "_probe_http",
                "_probe_dns",
                "_probe_tls",
                "_probe_websocket",
            }:
                continue
            self.assertTrue(node.args)
            first = node.args[0]
            if isinstance(first, ast.Constant):
                self.assertIsInstance(first.value, str)
                fixed_probe_values.add(first.value)
            else:
                configured_probe_names.update(
                    item.id for item in ast.walk(first) if isinstance(item, ast.Name)
                )
        metrics_probes = {
            value
            for value in fixed_probe_values
            if re.fullmatch(r"http://127\.0\.0\.1:\d{2,5}/metrics", value)
        }
        self.assertEqual(len(metrics_probes), 1)
        self.assertEqual(fixed_probe_values - metrics_probes, set())
        self.assertEqual(
            configured_probe_names,
            {
                "LOCAL_HA_HOST",
                "LOCAL_HA_URL",
                "LOCAL_MCP_URL",
                "PUBLIC_FRONTEND_HOST",
                "PUBLIC_FRONTEND_URL",
                "PUBLIC_MCP_HOST",
                "PUBLIC_MCP_URL",
            },
        )
        configured_defaults = {
            node.args[0].value: node.args[1].value
            for node in ast.walk(self.tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_configured_url"
            and len(node.args) == 2
            and all(isinstance(item, ast.Constant) for item in node.args)
        }
        self.assertEqual(
            configured_defaults,
            {
                "HA_LOCAL_URL": "http://127.0.0.1:8123",
                "MCP_LOCAL_BASE_URL": "http://127.0.0.1:8000",
                "FRONTEND_PUBLIC_URL": "https://ha.example.com",
                "PUBLIC_BASE_URL": "https://mcp.example.com",
            },
        )

    def test_retention_and_every_output_path_have_hard_byte_caps(self) -> None:
        retention = _integer_expression(self.assignments["RETENTION_DAYS"])
        history = _integer_expression(self.assignments["MAX_HISTORY_DAYS"])
        ledger_cap = _integer_expression(self.assignments["MAX_LEDGER_FILE_BYTES"])
        total_cap = _integer_expression(self.assignments["MAX_EXPORT_BYTES"])
        command_cap = _integer_expression(self.assignments["MAX_COMMAND_BYTES"])
        line_cap = _integer_expression(self.assignments["MAX_BACKFILL_LINES"])
        self.assertGreaterEqual(retention, 8)
        self.assertGreaterEqual(history, 8)
        self.assertGreater(ledger_cap, 0)
        self.assertGreaterEqual(total_cap, ledger_cap)
        self.assertGreater(command_cap, 0)
        self.assertGreater(line_cap, 0)
        loaded_names = [
            node.id
            for node in ast.walk(self.tree)
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
        ]
        for name in (
            "MAX_LEDGER_FILE_BYTES",
            "MAX_EXPORT_BYTES",
            "MAX_COMMAND_BYTES",
            "MAX_BACKFILL_LINES",
            "RETENTION_DAYS",
            "MAX_HISTORY_DAYS",
        ):
            with self.subTest(constant=name):
                self.assertIn(
                    name,
                    loaded_names,
                    f"{name} must enforce behavior, not just document it",
                )


if __name__ == "__main__":
    unittest.main()
