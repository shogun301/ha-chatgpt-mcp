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
WYZE_OVERLAY_ROOT = ROOT / "home_assistant" / "wyzeapi_overlay"
WYZE_OVERLAY_FILES = {
    "README.md",
    "UPSTREAM_LICENSE",
    "NOTICE",
    "custom_components/wyzeapi/__init__.py",
    "custom_components/wyzeapi/const.py",
    "custom_components/wyzeapi/irrigation.py",
    "custom_components/wyzeapi/irrigation_data.py",
    "custom_components/wyzeapi/manifest.json",
    "custom_components/wyzeapi/sensor.py",
    "custom_components/wyzeapi/services.yaml",
}


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
        "home_assistant.wyzeapi_overlay": {"README.md", "UPSTREAM_LICENSE", "NOTICE"},
        "home_assistant.wyzeapi_overlay.custom_components.wyzeapi": {
            "manifest.json", "services.yaml",
        },
    }
    if {key: set(value) for key, value in package_data.items()} != expected_data:
        raise AssertionError("Python package-data manifest is stale or incomplete")
    return references


def verify_wyze_overlay(*, archive: bool) -> list[str]:
    actual = {
        path.relative_to(WYZE_OVERLAY_ROOT).as_posix()
        for path in WYZE_OVERLAY_ROOT.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
    }
    if actual != WYZE_OVERLAY_FILES:
        missing = sorted(WYZE_OVERLAY_FILES - actual)
        extra = sorted(actual - WYZE_OVERLAY_FILES)
        raise AssertionError(
            f"Wyze overlay file set is incomplete or unexpected: missing={missing}, extra={extra}"
        )
    if not archive:
        tracked = _tracked_files()
        prefix = "home_assistant/wyzeapi_overlay/"
        missing_tracked = sorted(
            relative
            for relative in WYZE_OVERLAY_FILES
            if f"{prefix}{relative}" not in tracked
        )
        if missing_tracked:
            raise AssertionError(f"Wyze overlay files are not tracked: {missing_tracked}")
    readme = (WYZE_OVERLAY_ROOT / "README.md").read_text(encoding="utf-8")
    manifest = json.loads(
        (WYZE_OVERLAY_ROOT / "custom_components/wyzeapi/manifest.json").read_text(
            encoding="utf-8"
        )
    )
    required_guards = (
        "version `0.1.39`",
        "version `0.1.42`",
        "8C1551778463D995413F6A71739ADC53D820DED0CB069EF08E7DBB7A6395F1BC",
        "F69AF27ABBF54435C1A978DBF791F8CDA8D8500187FE4067EE90C18D661A2950",
        "3AF7296A87C8B0EA0CDE2E98CE6A05BA81846FE8631D8DD09E5B1954E62DAC15",
        "1921AB036214028B63F3809EA7FE4B6DD2C4F16AD3F6F968741247D8DB311AED",
        "6C0937ACDDB9FCE385808E86AF9DFF66383AB36ED48C72A871E006096DE15A7A",
        "24531253DC5445C3D7F16D91CD6727BA9D2DB457CD81098A0471419AD88E2140",
        "CC5FEFBA7564F81BBDC6BFAD3FE99C883ACF818F49BFCF0878312D41E324DB6B",
        "8A19F358735444A72D816BDFF0E75D3FD653FB41EF660CA606E3BAE7E99294C2",
        "95D9B4FFDDFE3199C6C98B62D30338350DAA8E5F6F29C1E501E2BDB53AF604BA",
        "78AF1900649BBB53DC074F66B998C8F5EBFC16AA924B59BA6D788B7F04BA0E08",
    )
    for literal in required_guards:
        if literal not in readme:
            raise AssertionError(f"Wyze overlay base guard is missing {literal}")
    if manifest.get("domain") != "wyzeapi" or manifest.get("version") != "0.1.42":
        raise AssertionError("Wyze overlay manifest identity is stale")
    return sorted(WYZE_OVERLAY_FILES)


def verify_registry_contract() -> str:
    version = str(
        tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"][
            "version"
        ]
    )
    relative = f"tests/fixtures/server-contract-{version}.json"
    path = ROOT / relative
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("version") != version:
        raise AssertionError("registry contract version is stale")
    count = payload.get("tool_count")
    names = payload.get("tool_names")
    if not isinstance(count, int) or not isinstance(names, list):
        raise AssertionError("registry contract count or names are invalid")
    if count != len(names) or len(names) != len(set(names)) or names != sorted(names):
        raise AssertionError("registry contract tool names are incomplete or unstable")
    for field in (
        "tool_schema_sha256",
        "tool_output_schema_sha256",
        "tool_annotations_sha256",
    ):
        if not re.fullmatch(r"[0-9a-f]{64}", str(payload.get(field, ""))):
            raise AssertionError(f"registry contract {field} is invalid")
    return relative


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
        'chmod -R a+rX "$release_stage"', "deploy-wyzeapi-overlay.ps1",
        "$releaseCommit 'home_assistant/wyzeapi_overlay'",
        "stage='deploying_wyze_overlay'", "rollback_overlay",
    ):
        if literal not in deploy:
            raise AssertionError(f"deployment is missing release gate: {literal}")
    sync_at = workflow.index("uv sync --frozen")
    if workflow.index("python scripts/release_integrity.py") > sync_at:
        raise AssertionError("CI must validate the clean checkout before dependency setup")
    if workflow.index("git archive HEAD") > sync_at:
        raise AssertionError("CI must export the exact candidate before dependency setup")
    if "'--no-project'" not in deploy:
        raise AssertionError("deployment validators must not install or build the release project")


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
        "registry_contract": verify_registry_contract(),
        "version": verify_versions(),
        "wyze_overlay_files": verify_wyze_overlay(archive=args.archive),
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
