from __future__ import annotations

import argparse
import ast
import json
import re
import shlex
import subprocess
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "Dockerfile"


def _git(*args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(ROOT), *args], check=True, capture_output=True,
        text=True, encoding="utf-8",
    ).stdout


def _logical_lines(text: str) -> list[str]:
    result: list[str] = []
    pending = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        pending = f"{pending} {line}".strip()
        if pending.endswith("\\"):
            pending = pending[:-1].rstrip()
            continue
        result.append(pending)
        pending = ""
    if pending:
        raise AssertionError("incomplete Dockerfile continuation")
    return result


def docker_sources() -> list[str]:
    sources: list[str] = []
    for line in _logical_lines(DOCKERFILE.read_text(encoding="utf-8")):
        instruction, _, body = line.partition(" ")
        if instruction.upper() not in {"COPY", "ADD"}:
            continue
        if instruction.upper() == "ADD":
            raise AssertionError("ADD is forbidden; use explicit tracked COPY sources")
        tokens = shlex.split(body, posix=True)
        while tokens and tokens[0].startswith("--"):
            if tokens.pop(0).startswith("--from"):
                raise AssertionError("COPY --from is unsupported by this verifier")
        if len(tokens) < 2:
            raise AssertionError(f"invalid Dockerfile instruction: {line}")
        for source in tokens[:-1]:
            if any(char in source for char in "*?["):
                raise AssertionError(f"Dockerfile COPY globs are forbidden: {source}")
            if source.startswith(("/", "http://", "https://")) or ".." in Path(source).parts:
                raise AssertionError(f"unsafe Dockerfile COPY source: {source}")
            sources.append(source.rstrip("/"))
    if not sources:
        raise AssertionError("Dockerfile has no local COPY sources")
    return sources


def _tracked_files() -> set[str]:
    return {item.replace("\\", "/") for item in _git("ls-files", "-z").split("\0") if item}


def verify_docker_inputs(*, archive: bool) -> list[str]:
    tracked = None if archive else _tracked_files()
    verified: list[str] = []
    for source in docker_sources():
        path = ROOT / source
        if not path.exists():
            raise AssertionError(f"Dockerfile source is missing: {source}")
        if tracked is not None:
            normalized = source.replace("\\", "/")
            members = ({normalized} if path.is_file() else {
                item for item in tracked
                if item == normalized or item.startswith(f"{normalized}/")
            })
            if not members:
                raise AssertionError(f"Dockerfile source is not tracked: {source}")
        verified.append(source)
    return verified


def _literal_assignment(path: Path, name: str) -> object:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if any(isinstance(target, ast.Name) and target.id == name for target in targets):
            return ast.literal_eval(node.value)
    raise AssertionError(f"{name} is not a literal in {path.relative_to(ROOT)}")


def verify_versions() -> str:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    version = str(project["project"]["version"])
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise AssertionError("project version must be major.minor.patch")
    values = {
        "app/server.py": _literal_assignment(ROOT / "app/server.py", "SERVER_VERSION"),
        "scripts/production_mcp_verify.py": _literal_assignment(
            ROOT / "scripts/production_mcp_verify.py", "EXPECTED_VERSION"
        ),
    }
    for location, value in values.items():
        if value != version:
            raise AssertionError(f"{location} version {value!r} != {version!r}")
    texts = {
        "compose": (ROOT / "docker-compose.yml").read_text(encoding="utf-8"),
        "deploy": (ROOT / "scripts/deploy-production.ps1").read_text(encoding="utf-8"),
        "dockerfile": DOCKERFILE.read_text(encoding="utf-8"),
    }
    required = {
        "compose": f"ha-chatgpt-mcp:{version}",
        "deploy": f"$releaseVersion = '{version}'",
        "dockerfile": f'org.opencontainers.image.version="{version}"',
    }
    for location, literal in required.items():
        if literal not in texts[location]:
            raise AssertionError(f"{location} does not advertise {version}")
    if f"release_version='{version}'" not in texts["deploy"]:
        raise AssertionError("deploy shell version is stale")
    return version


def verify_manifests() -> list[str]:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    references = ["pyproject.toml", "uv.lock"]
    for field in ("readme", "license"):
        value = project.get("project", {}).get(field)
        if isinstance(value, str):
            references.append(value)
        elif isinstance(value, dict) and isinstance(value.get("file"), str):
            references.append(value["file"])
    for reference in references:
        if not (ROOT / reference).is_file():
            raise AssertionError(f"manifest reference is missing: {reference}")
    package_path = ROOT / "cloudflare/package.json"
    if package_path.is_file():
        package = json.loads(package_path.read_text(encoding="utf-8"))
        for section in ("dependencies", "devDependencies"):
            for name, value in package.get(section, {}).items():
                if str(value).startswith(("file:", "workspace:")):
                    raise AssertionError(f"unsupported local package reference: {name}={value}")
        references.append("cloudflare/package.json")
    package_find = project.get("tool", {}).get("setuptools", {}).get("packages", {}).get("find", {})
    expected_include = {"app", "app.*", "collector", "collector.*", "home_assistant.*"}
    expected_exclude = {
        "tests", "tests.*", "collector.tests", "home_assistant.tests",
        "cloudflare", "cloudflare.*",
    }
    if set(package_find.get("include", [])) != expected_include:
        raise AssertionError("Python package discovery include set is not explicit or complete")
    if set(package_find.get("exclude", [])) != expected_exclude:
        raise AssertionError("Python package discovery exclude set is not fail-closed")
    package_data = project.get("tool", {}).get("setuptools", {}).get("package-data", {})
    expected_data = {
        "collector": {"README.md", "ha-host-diagnostics.service"},
        "home_assistant.custom_components.solaredge_one_bridge": {
            "manifest.json", "strings.json", "translations/*.json",
        },
    }
    if {key: set(value) for key, value in package_data.items()} != expected_data:
        raise AssertionError("Python package-data manifest is stale or incomplete")
    return references


def verify_release_automation() -> None:
    workflow = (ROOT / ".github/workflows/public-safety.yml").read_text(encoding="utf-8")
    deploy = (ROOT / "scripts/deploy-production.ps1").read_text(encoding="utf-8")
    for literal in (
        "git archive HEAD", "docker build", "--network none", "collector/tests",
        "home_assistant/tests", "release_integrity.py --archive",
        "org.opencontainers.image.revision", 'chmod -R a+rX "$release_dir"',
    ):
        if literal not in workflow:
            raise AssertionError(f"CI is missing release gate: {literal}")
    for literal in (
        "git archive", "release_commit", "--network none", "collector/tests",
        "home_assistant/tests", "org.opencontainers.image.revision", "release_stage",
        'chmod -R a+rX "$release_stage"',
    ):
        if literal not in deploy:
            raise AssertionError(f"deployment is missing release gate: {literal}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", action="store_true")
    args = parser.parse_args()
    if not args.archive and _git("status", "--porcelain=v1", "--untracked-files=all").strip():
        raise AssertionError("release checkout is not clean")
    payload = {
        "archive": args.archive,
        "docker_sources": verify_docker_inputs(archive=args.archive),
        "manifest_references": verify_manifests(),
        "version": verify_versions(),
    }
    verify_release_automation()
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, KeyError, OSError, subprocess.CalledProcessError) as exc:
        print(f"release integrity failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
