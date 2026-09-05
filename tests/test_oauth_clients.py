"""OAuth client admission: which redirect URIs and client identities the server accepts."""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlencode

_temporary_root = tempfile.TemporaryDirectory()
_root = Path(_temporary_root.name)
for _name, _value in {
    "ha_token": "test-home-assistant-token",
    "oauth_password_hash": "$argon2id$v=19$m=65536,t=3,p=4$dGVzdA$dGVzdA",
    "jwt_secret": "test-jwt-secret-that-is-long-enough-for-unit-tests",
    "origin_shared_secret": "test-origin-shared-secret",
}.items():
    (_root / _name).write_text(_value, encoding="utf-8")

for _key, _value in {
    "PUBLIC_BASE_URL": "https://example.invalid",
    "FRONTEND_PUBLIC_URL": "https://ha.example.invalid",
    "HA_BASE_URL": "http://127.0.0.1:8123",
    "HA_TOKEN_FILE": str(_root / "ha_token"),
    "OAUTH_PASSWORD_HASH_FILE": str(_root / "oauth_password_hash"),
    "JWT_SECRET_FILE": str(_root / "jwt_secret"),
    "ORIGIN_SHARED_SECRET_FILE": str(_root / "origin_shared_secret"),
    "DATABASE_PATH": str(_root / "oauth.sqlite3"),
    "AUDIT_LOG_PATH": str(_root / "audit.jsonl"),
    "HA_CONFIG_PATH": str(_root / "ha-config"),
    "BACKUP_PATH": str(_root / "backups"),
    "HOST_DIAGNOSTICS_PATH": str(_root / "host-diagnostics"),
}.items():
    os.environ.setdefault(_key, _value)

from starlette.requests import Request  # noqa: E402
from starlette.responses import Response  # noqa: E402

from app.oauth import (  # noqa: E402
    OAuthServer,
    OAuthStore,
    _official_cimd,
    _official_redirect,
)

CHALLENGE = "a" * 43


def _request(method: str, path: str, *, query: dict[str, str] | None = None, body: object = None) -> Request:
    payload = b"" if body is None else json.dumps(body).encode("utf-8")
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": method,
        "scheme": "https",
        "server": ("example.invalid", 443),
        "path": path,
        "raw_path": path.encode("ascii"),
        "root_path": "",
        "query_string": urlencode(query or {}).encode("ascii"),
        "headers": [(b"content-type", b"application/json"), (b"host", b"example.invalid")],
    }
    sent = False

    async def receive() -> dict[str, object]:
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": payload, "more_body": False}

    return Request(scope, receive)


def _json(response: Response) -> object:
    return json.loads(bytes(response.body).decode("utf-8"))


class RedirectPolicyTests(unittest.TestCase):
    def test_hosted_https_callbacks_are_accepted(self) -> None:
        for uri in (
            "https://chatgpt.com/connector_platform_oauth_redirect",
            "https://platform.openai.com/apps-sdk/oauth/callback",
            "https://claude.ai/api/mcp/auth_callback",
            "https://claude.com/api/mcp/auth_callback",
            "https://app.claude.ai/api/mcp/auth_callback",
        ):
            with self.subTest(uri=uri):
                self.assertTrue(_official_redirect(uri))

    def test_loopback_http_callbacks_accept_any_port(self) -> None:
        for uri in (
            "http://localhost:53210/callback",
            "http://localhost/callback",
            "http://127.0.0.1:8080/callback",
            "http://[::1]:9000/callback",
        ):
            with self.subTest(uri=uri):
                self.assertTrue(_official_redirect(uri))

    def test_other_redirects_stay_rejected(self) -> None:
        for uri in (
            "",
            "not a url",
            "https://evil.example/callback",
            "https://claude.ai.evil.example/api/mcp/auth_callback",
            "https://evilclaude.ai/api/mcp/auth_callback",
            "http://claude.ai/api/mcp/auth_callback",
            "http://localhost.evil.example/callback",
            "http://intranet.example/callback",
            "https://localhost/callback",
            "http://localhost:53210/callback#fragment",
            "customscheme://localhost/callback",
        ):
            with self.subTest(uri=uri):
                self.assertFalse(_official_redirect(uri))

    def test_client_id_metadata_documents(self) -> None:
        for client_id in (
            "https://chatgpt.com/oauth/client-metadata.json",
            "https://claude.ai/.well-known/oauth-client-metadata",
            "https://claude.com/oauth/client",
        ):
            with self.subTest(client_id=client_id):
                self.assertTrue(_official_cimd(client_id))
        for client_id in (
            "https://chatgpt.com/other/metadata.json",
            "http://claude.ai/.well-known/oauth-client-metadata",
            "https://claude.ai",
            "https://claude.ai/",
            "https://app.claude.ai/metadata",
            "https://evil.example/oauth/metadata",
            "",
        ):
            with self.subTest(client_id=client_id):
                self.assertFalse(_official_cimd(client_id))


class ClientAdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        store = OAuthStore(Path(self.temporary.name) / "oauth.sqlite3")
        self.server = OAuthServer(
            store,
            issuer="https://example.invalid",
            resource="https://example.invalid/mcp",
            jwt_secret="test-jwt-secret-that-is-long-enough-for-unit-tests",
            password_hash="$argon2id$v=19$m=65536,t=3,p=4$dGVzdA$dGVzdA",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _register(self, *redirect_uris: str, name: str = "Claude Code") -> Response:
        request = _request(
            "POST",
            "/oauth/register",
            body={
                "client_name": name,
                "redirect_uris": list(redirect_uris),
                "token_endpoint_auth_method": "none",
            },
        )
        return asyncio.run(self.server.register(request))

    def _authorize(self, client_id: str, redirect_uri: str) -> Response:
        request = _request(
            "GET",
            "/oauth/authorize",
            query={
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "response_type": "code",
                "code_challenge": CHALLENGE,
                "code_challenge_method": "S256",
                "state": "xyz",
            },
        )
        return asyncio.run(self.server.authorize(request))

    def test_claude_code_loopback_client_can_register_and_authorize(self) -> None:
        redirect = "http://localhost:53210/callback"
        registered = self._register(redirect)
        self.assertEqual(registered.status_code, 201)
        body = _json(registered)
        self.assertEqual(body["redirect_uris"], [redirect])
        self.assertEqual(body["client_name"], "Claude Code")
        page = self._authorize(body["client_id"], redirect)
        self.assertEqual(page.status_code, 200)
        html = bytes(page.body).decode("utf-8")
        self.assertIn("Authorize this client", html)
        self.assertNotIn("ChatGPT", html)

    def test_claude_ai_hosted_client_can_register(self) -> None:
        registered = self._register(
            "https://claude.ai/api/mcp/auth_callback",
            "https://claude.com/api/mcp/auth_callback",
            name="Claude",
        )
        self.assertEqual(registered.status_code, 201)

    def test_chatgpt_registration_still_works(self) -> None:
        registered = self._register(
            "https://chatgpt.com/connector_platform_oauth_redirect", name="ChatGPT"
        )
        self.assertEqual(registered.status_code, 201)

    def test_registration_rejects_any_foreign_redirect(self) -> None:
        response = self._register(
            "http://localhost:53210/callback", "https://evil.example/callback"
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(_json(response), {"error": "invalid_redirect_uri"})

    def test_authorize_requires_the_registered_loopback_port(self) -> None:
        registered = self._register("http://localhost:53210/callback")
        client_id = _json(registered)["client_id"]
        response = self._authorize(client_id, "http://localhost:53211/callback")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(_json(response), {"error": "invalid_redirect_uri"})

    def test_authorize_rejects_unknown_client(self) -> None:
        response = self._authorize("unknown-client", "http://localhost:53210/callback")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(_json(response), {"error": "invalid_redirect_uri"})

    def test_claude_metadata_document_client_may_use_loopback_redirect(self) -> None:
        response = self._authorize(
            "https://claude.ai/.well-known/oauth-client-metadata",
            "http://127.0.0.1:41000/callback",
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("Authorize this client", bytes(response.body).decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
