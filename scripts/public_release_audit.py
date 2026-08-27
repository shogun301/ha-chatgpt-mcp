#!/usr/bin/env python3
"""Fail closed when a public release contains private deployment material."""

from __future__ import annotations

import argparse
import ipaddress
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SELF = Path(__file__).resolve()
TEXT_SUFFIXES = {
    "",
    ".caddyfile",
    ".css",
    ".html",
    ".js",
    ".json",
    ".jsonc",
    ".md",
    ".ps1",
    ".py",
    ".service",
    ".sh",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
FORBIDDEN_FRAGMENTS = tuple(
    value.casefold()
    for value in (
        "inouye",
        "binouye",
        "jpl.nasa.gov",
        "homeassistant-cloud-4gb",
        "ha-mcp.44.236.204.143.sslip.io",
    )
)
SECRET_PATTERNS = {
    "AWS access key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "GitHub token": re.compile(r"\b(?:ghp_|github_pat_)[A-Za-z0-9_]{12,}\b"),
    "OpenAI token": re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"),
    "private key": re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    "authorization header": re.compile(
        r"(?i)\bauthorization\s*:\s*(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{12,}"
    ),
}
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})\b", re.I)
IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)


def candidate_paths() -> list[Path]:
    output = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT,
    )
    return [ROOT / item for item in output.decode().split("\0") if item]


def audit_file(path: Path) -> list[str]:
    relative = path.relative_to(ROOT).as_posix()
    lowered = relative.casefold()
    findings: list[str] = []
    if relative in {"scripts/public_release_audit.py", "uv.lock"}:
        return findings
    if any(part in {"secrets", ".wrangler", "data", "logs", "backups"} for part in path.parts):
        findings.append(f"{relative}: forbidden generated or secret directory")
    if path.name.casefold() in {".env", "credentials", "credentials.json"}:
        findings.append(f"{relative}: forbidden credential filename")
    if path.suffix.casefold() in {".pem", ".key", ".p12", ".pfx", ".sqlite", ".db"}:
        findings.append(f"{relative}: forbidden secret or database file type")
    if path.suffix.casefold() not in TEXT_SUFFIXES and path.name not in {"Caddyfile", "Dockerfile"}:
        return findings
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return findings
    folded = text.casefold()
    for fragment in FORBIDDEN_FRAGMENTS:
        if fragment in folded:
            findings.append(f"{relative}: private identifier {fragment!r}")
    for label, pattern in SECRET_PATTERNS.items():
        if pattern.search(text):
            findings.append(f"{relative}: possible {label}")
    for match in EMAIL_RE.finditer(text):
        if match.group().casefold().startswith("wg-quick@"):
            continue
        domain = match.group(1).casefold()
        if not (
            domain == "users.noreply.github.com"
            or domain == "example.com"
            or domain.endswith((".example", ".invalid", ".test"))
        ):
            findings.append(f"{relative}: non-example email address")
    for match in IPV4_RE.finditer(text):
        try:
            address = ipaddress.ip_address(match.group())
        except ValueError:
            continue
        if (
            address.is_private
            and not address.is_loopback
            and not any(address in network for network in DOCUMENTATION_NETWORKS)
        ):
            findings.append(f"{relative}: private IPv4 address")
    return findings


def audit_history() -> list[str]:
    findings: list[str] = []
    log = subprocess.check_output(
        ["git", "log", "--format=%H%x00%an%x00%ae%x00%cn%x00%ce"], cwd=ROOT
    ).decode(errors="replace")
    for line in log.splitlines():
        fields = line.split("\0")
        if len(fields) != 5:
            continue
        commit, *identity = fields
        joined = " ".join(identity).casefold()
        if any(fragment in joined for fragment in FORBIDDEN_FRAGMENTS):
            findings.append(f"history {commit}: private author or committer identity")
    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--history", action="store_true")
    args = parser.parse_args()
    findings = [item for path in candidate_paths() for item in audit_file(path)]
    if args.history:
        findings.extend(audit_history())
    if findings:
        print("Public release audit failed:")
        for finding in sorted(set(findings)):
            print(f"- {finding}")
        return 1
    print("Public release audit passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
