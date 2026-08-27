#!/usr/bin/env python3
"""Provision a passwordless Home Assistant service identity without printing secrets."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import secrets
import sys
from urllib.parse import parse_qs, urlencode, urlparse
from urllib.request import Request, urlopen

import aiohttp


ADMIN_CREDENTIALS = Path("/opt/ha-codex/credentials.json")
OUTPUT_TOKEN = Path("/opt/ha-chatgpt-mcp/secrets/ha_token")
BASE_URL = "http://127.0.0.1:8123"
SERVICE_NAME = "ChatGPT Work MCP"
STAGE = "startup"


def request_json(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
) -> dict:
    request = Request(url, method=method, headers=headers or {}, data=body)
    with urlopen(request, timeout=20) as response:
        raw = response.read()
    return json.loads(raw) if raw else {}


def admin_access_token() -> str:
    credentials = json.loads(ADMIN_CREDENTIALS.read_text(encoding="utf-8"))
    body = urlencode(
        {
            "grant_type": "refresh_token",
            "refresh_token": credentials["refresh_token"],
            "client_id": credentials["client_id"],
        }
    ).encode()
    result = request_json(
        f"{credentials['base_url']}/auth/token",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        body=body,
    )
    return result["access_token"]


async def ws_command(token: str, command: dict) -> dict:
    async with aiohttp.ClientSession() as session:
        async with session.ws_connect(f"{BASE_URL.replace('http://', 'ws://')}/api/websocket") as websocket:
            greeting = await websocket.receive_json()
            if greeting.get("type") != "auth_required":
                raise RuntimeError("Unexpected WebSocket greeting")
            await websocket.send_json({"type": "auth", "access_token": token})
            authenticated = await websocket.receive_json()
            if authenticated.get("type") != "auth_ok":
                raise RuntimeError("Home Assistant authentication failed")
            payload = dict(command)
            payload["id"] = 1
            await websocket.send_json(payload)
            while True:
                result = await websocket.receive_json()
                if result.get("id") == 1:
                    if not result.get("success"):
                        raise RuntimeError(f"WebSocket command failed: {result.get('error', {}).get('code', 'unknown')}")
                    return result.get("result")


def login(username: str, password: str) -> str:
    client_id = "http://localhost/"
    initial = request_json(
        f"{BASE_URL}/auth/login_flow",
        method="POST",
        headers={"Content-Type": "application/json"},
        body=json.dumps(
            {
                "client_id": client_id,
                "handler": ["homeassistant", None],
                "redirect_uri": client_id,
            }
        ).encode(),
    )
    completed = request_json(
        f"{BASE_URL}/auth/login_flow/{initial['flow_id']}",
        method="POST",
        headers={"Content-Type": "application/json"},
        body=json.dumps(
            {"client_id": client_id, "username": username, "password": password}
        ).encode(),
    )
    if completed.get("type") != "create_entry":
        raise RuntimeError("Temporary Home Assistant login failed")
    result_value = completed.get("result", "")
    code = result_value
    if isinstance(result_value, str) and "://" in result_value:
        code = parse_qs(urlparse(result_value).query).get("code", [None])[0]
    if not code:
        raise RuntimeError("Home Assistant login did not return an authorization code")
    token_result = request_json(
        f"{BASE_URL}/auth/token",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        body=urlencode(
            {"grant_type": "authorization_code", "code": code, "client_id": client_id}
        ).encode(),
    )
    return token_result["access_token"]


async def main() -> None:
    global STAGE
    if OUTPUT_TOKEN.exists() and OUTPUT_TOKEN.stat().st_size > 40:
        print(json.dumps({"status": "unchanged", "identity": SERVICE_NAME}))
        return
    STAGE = "admin_access_token"
    admin_token = admin_access_token()
    STAGE = "list_users"
    users = await ws_command(admin_token, {"type": "config/auth/list"})
    if any(user.get("name") == SERVICE_NAME for user in users):
        raise RuntimeError("Service identity already exists but its token file is missing")
    username = f"chatgpt_mcp_{secrets.token_hex(6)}"
    password = secrets.token_urlsafe(32)
    user_id: str | None = None
    credential_created = False
    try:
        STAGE = "create_user"
        created = await ws_command(
            admin_token,
            {
                "type": "config/auth/create",
                "name": SERVICE_NAME,
                "group_ids": ["system-admin"],
                "local_only": True,
            },
        )
        user_id = created["user"]["id"]
        STAGE = "create_temporary_credential"
        await ws_command(
            admin_token,
            {
                "type": "config/auth_provider/homeassistant/create",
                "user_id": user_id,
                "username": username,
                "password": password,
            },
        )
        credential_created = True
        STAGE = "temporary_login"
        service_access_token = login(username, password)
        STAGE = "create_long_lived_token"
        long_lived_token = await ws_command(
            service_access_token,
            {
                "type": "auth/long_lived_access_token",
                "client_name": "ChatGPT Work Home Assistant MCP",
                "lifespan": 3650,
            },
        )
        temporary = OUTPUT_TOKEN.with_suffix(".tmp")
        temporary.write_text(str(long_lived_token), encoding="utf-8")
        os.chmod(temporary, 0o600)
        temporary.replace(OUTPUT_TOKEN)
        STAGE = "remove_temporary_credential"
        await ws_command(
            admin_token,
            {"type": "config/auth_provider/homeassistant/delete", "username": username},
        )
        credential_created = False
        print(json.dumps({"status": "created", "identity": SERVICE_NAME, "local_only": True, "password_credential_removed": True}))
    except Exception:
        if credential_created:
            try:
                await ws_command(
                    admin_token,
                    {"type": "config/auth_provider/homeassistant/delete", "username": username},
                )
            except Exception:
                pass
        if user_id:
            try:
                await ws_command(admin_token, {"type": "config/auth/delete", "user_id": user_id})
            except Exception:
                pass
        raise


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as exc:
        status = getattr(exc, "code", None)
        print(json.dumps({"status": "error", "stage": STAGE, "error_type": type(exc).__name__, "http_status": status}), file=sys.stderr)
        raise SystemExit(1) from exc
