from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlparse

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import jwt
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from . import config


SUPPORTED_SCOPES = {"mcp:diagnostics", "mcp:read", "mcp:write"}
PASSWORD_HASHER = PasswordHasher()


class ClosingConnection(sqlite3.Connection):
    """Commit or roll back a context-managed connection, then release the file handle."""

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> bool:
        try:
            return bool(super().__exit__(exc_type, exc_value, traceback))
        finally:
            self.close()


def _now() -> int:
    return int(time.time())


def _token(length: int = 48) -> str:
    return secrets.token_urlsafe(length)


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


# Hosted MCP clients whose HTTPS callbacks may receive authorization codes: ChatGPT/Codex
# (chatgpt.com, openai.com) and Claude (claude.ai, claude.com). Subdomains are included.
OFFICIAL_REDIRECT_DOMAINS = ("chatgpt.com", "openai.com", "claude.ai", "claude.com")
# Native clients such as Claude Code register an RFC 8252 loopback redirect
# (http://localhost:<ephemeral port>/callback). Any port is accepted, as the RFC requires.
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
# Client ID metadata document hosts (exact match) that may skip dynamic registration.
OFFICIAL_CIMD_HOSTS = frozenset({"chatgpt.com", "claude.ai", "claude.com"})


def _host_in_domains(host: str, domains: tuple[str, ...]) -> bool:
    return any(host == domain or host.endswith("." + domain) for domain in domains)


def _official_redirect(uri: str) -> bool:
    try:
        parsed = urlparse(uri)
    except ValueError:
        return False
    host = (parsed.hostname or "").lower()
    if not host or parsed.fragment:
        return False
    if parsed.scheme == "https":
        return _host_in_domains(host, OFFICIAL_REDIRECT_DOMAINS)
    if parsed.scheme == "http":
        return host in LOOPBACK_HOSTS
    return False


def _official_cimd(client_id: str) -> bool:
    try:
        parsed = urlparse(client_id)
    except ValueError:
        return False
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or host not in OFFICIAL_CIMD_HOSTS:
        return False
    if host == "chatgpt.com":
        return parsed.path.startswith("/oauth/")
    return parsed.path.startswith("/") and len(parsed.path) > 1


class OAuthStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path, timeout=10, factory=ClosingConnection
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _initialize(self) -> None:
        with self.connect() as db:
            db.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS clients (
                    client_id TEXT PRIMARY KEY,
                    client_name TEXT NOT NULL,
                    redirect_uris TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS auth_requests (
                    transaction_id TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL,
                    redirect_uri TEXT NOT NULL,
                    state TEXT,
                    scope TEXT NOT NULL,
                    code_challenge TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    expires_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS auth_codes (
                    code_hash TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL,
                    redirect_uri TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    code_challenge TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    expires_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS refresh_tokens (
                    token_hash TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0
                );
                """
            )

    def cleanup(self) -> None:
        now = _now()
        with self.connect() as db:
            db.execute("DELETE FROM auth_requests WHERE expires_at < ?", (now,))
            db.execute("DELETE FROM auth_codes WHERE expires_at < ?", (now,))
            db.execute("DELETE FROM refresh_tokens WHERE expires_at < ? OR revoked = 1", (now,))


class OAuthServer:
    def __init__(
        self,
        store: OAuthStore,
        issuer: str,
        resource: str,
        jwt_secret: str,
        password_hash: str,
    ) -> None:
        self.store = store
        self.issuer = issuer.rstrip("/")
        self.resource = resource
        self.jwt_secret = jwt_secret
        self.password_hash = password_hash

    def authorization_metadata(self) -> dict[str, Any]:
        return {
            "issuer": self.issuer,
            "authorization_endpoint": f"{self.issuer}/oauth/authorize",
            "token_endpoint": f"{self.issuer}/oauth/token",
            "registration_endpoint": f"{self.issuer}/oauth/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": sorted(SUPPORTED_SCOPES),
            "client_id_metadata_document_supported": True,
        }

    def resource_metadata(self) -> dict[str, Any]:
        return {
            "resource": self.resource,
            "authorization_servers": [self.issuer],
            "bearer_methods_supported": ["header"],
            "scopes_supported": sorted(SUPPORTED_SCOPES),
            "resource_name": config.MCP_DISPLAY_NAME,
        }

    async def register(self, request: Request) -> Response:
        try:
            payload = await request.json()
        except Exception:
            return _oauth_error("invalid_client_metadata", status=400)
        redirect_uris = payload.get("redirect_uris")
        if (
            not isinstance(redirect_uris, list)
            or not redirect_uris
            or len(redirect_uris) > 10
            or not all(isinstance(uri, str) and _official_redirect(uri) for uri in redirect_uris)
        ):
            return _oauth_error("invalid_redirect_uri", status=400)
        auth_method = payload.get("token_endpoint_auth_method", "none")
        if auth_method != "none":
            return _oauth_error("invalid_client_metadata", status=400)
        client_id = _token(32)
        client_name = str(payload.get("client_name") or "MCP client")[:120]
        with self.store.connect() as db:
            db.execute(
                "INSERT INTO clients(client_id,client_name,redirect_uris,created_at) VALUES(?,?,?,?)",
                (client_id, client_name, json.dumps(redirect_uris), _now()),
            )
        return JSONResponse(
            {
                "client_id": client_id,
                "client_name": client_name,
                "redirect_uris": redirect_uris,
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
            },
            status_code=201,
            headers={"Cache-Control": "no-store"},
        )

    def _client_redirect_allowed(self, client_id: str, redirect_uri: str) -> bool:
        if _official_cimd(client_id):
            return _official_redirect(redirect_uri)
        with self.store.connect() as db:
            row = db.execute(
                "SELECT redirect_uris FROM clients WHERE client_id = ?", (client_id,)
            ).fetchone()
        return bool(row and redirect_uri in json.loads(row["redirect_uris"]))

    async def authorize(self, request: Request) -> Response:
        query = request.query_params
        client_id = query.get("client_id", "")
        redirect_uri = query.get("redirect_uri", "")
        response_type = query.get("response_type", "")
        code_challenge = query.get("code_challenge", "")
        method = query.get("code_challenge_method", "")
        resource = query.get("resource") or self.resource
        state = query.get("state")
        scope = self._normalize_scope(query.get("scope"))
        if response_type != "code" or method != "S256" or len(code_challenge) < 43:
            return _oauth_error("invalid_request", status=400)
        if resource != self.resource:
            return _oauth_error("invalid_target", status=400)
        if not self._client_redirect_allowed(client_id, redirect_uri):
            return _oauth_error("invalid_redirect_uri", status=400)
        if scope is None:
            return _oauth_error("invalid_scope", status=400)
        transaction_id = _token(32)
        with self.store.connect() as db:
            db.execute(
                """INSERT INTO auth_requests
                (transaction_id,client_id,redirect_uri,state,scope,code_challenge,resource,expires_at)
                VALUES(?,?,?,?,?,?,?,?)""",
                (
                    transaction_id,
                    client_id,
                    redirect_uri,
                    state,
                    scope,
                    code_challenge,
                    resource,
                    _now() + 300,
                ),
            )
        page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorize Home Assistant</title>
<style>body{{font-family:system-ui,sans-serif;max-width:34rem;margin:4rem auto;padding:0 1rem;color:#18202b}}form{{display:grid;gap:1rem}}input,button{{font:inherit;padding:.8rem;border-radius:.5rem;border:1px solid #b7c0cc}}button{{background:#1677ff;color:white;border:0;font-weight:650}}.note{{color:#536171}}</style></head>
<body><h1>Authorize Home Assistant</h1><p>Allow this client to use the configured private Home Assistant tools.</p>
<form method="post" action="/oauth/authorize/decision">
<input type="hidden" name="transaction_id" value="{html.escape(transaction_id)}">
<label>Connection password<input name="password" type="password" autocomplete="current-password" required autofocus></label>
<button type="submit">Authorize this client</button></form>
<p class="note">The password is verified here and is never sent to the client or to Home Assistant.</p></body></html>"""
        return HTMLResponse(page, headers={"Cache-Control": "no-store"})

    async def authorize_decision(self, request: Request) -> Response:
        form = await request.form()
        transaction_id = str(form.get("transaction_id") or "")
        password = str(form.get("password") or "")
        with self.store.connect() as db:
            row = db.execute(
                "SELECT * FROM auth_requests WHERE transaction_id = ? AND expires_at >= ?",
                (transaction_id, _now()),
            ).fetchone()
        if row is None:
            return HTMLResponse("Authorization request expired.", status_code=400)
        try:
            PASSWORD_HASHER.verify(self.password_hash, password)
        except VerifyMismatchError:
            return HTMLResponse("Invalid connection password.", status_code=403)
        code = _token(48)
        with self.store.connect() as db:
            db.execute("DELETE FROM auth_requests WHERE transaction_id = ?", (transaction_id,))
            db.execute(
                """INSERT INTO auth_codes
                (code_hash,client_id,redirect_uri,scope,code_challenge,resource,expires_at)
                VALUES(?,?,?,?,?,?,?)""",
                (
                    _hash(code),
                    row["client_id"],
                    row["redirect_uri"],
                    row["scope"],
                    row["code_challenge"],
                    row["resource"],
                    _now() + 180,
                ),
            )
        params = {"code": code}
        if row["state"]:
            params["state"] = row["state"]
        separator = "&" if "?" in row["redirect_uri"] else "?"
        return RedirectResponse(
            row["redirect_uri"] + separator + urlencode(params), status_code=303
        )

    async def token(self, request: Request) -> Response:
        form = await request.form()
        grant_type = str(form.get("grant_type") or "")
        client_id = str(form.get("client_id") or "")
        if grant_type == "authorization_code":
            code = str(form.get("code") or "")
            redirect_uri = str(form.get("redirect_uri") or "")
            verifier = str(form.get("code_verifier") or "")
            with self.store.connect() as db:
                row = db.execute(
                    "SELECT * FROM auth_codes WHERE code_hash = ? AND expires_at >= ?",
                    (_hash(code), _now()),
                ).fetchone()
                if row:
                    db.execute("DELETE FROM auth_codes WHERE code_hash = ?", (_hash(code),))
            if row is None or not client_id or client_id != row["client_id"]:
                return _oauth_error("invalid_grant", status=400)
            if redirect_uri != row["redirect_uri"]:
                return _oauth_error("invalid_grant", status=400)
            challenge = base64.urlsafe_b64encode(
                hashlib.sha256(verifier.encode("ascii", "strict")).digest()
            ).rstrip(b"=").decode("ascii")
            if not hmac.compare_digest(challenge, row["code_challenge"]):
                return _oauth_error("invalid_grant", status=400)
            return self._issue_tokens(client_id, row["scope"], row["resource"])
        if grant_type == "refresh_token":
            refresh_token = str(form.get("refresh_token") or "")
            with self.store.connect() as db:
                row = db.execute(
                    "SELECT * FROM refresh_tokens WHERE token_hash = ? AND revoked = 0 AND expires_at >= ?",
                    (_hash(refresh_token), _now()),
                ).fetchone()
                if row:
                    db.execute(
                        "UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?",
                        (_hash(refresh_token),),
                    )
            if row is None or not client_id or client_id != row["client_id"]:
                return _oauth_error("invalid_grant", status=400)
            return self._issue_tokens(client_id, row["scope"], row["resource"])
        return _oauth_error("unsupported_grant_type", status=400)

    def _issue_tokens(self, client_id: str, scope: str, resource: str) -> Response:
        now = _now()
        claims = {
            "iss": self.issuer,
            "sub": config.OAUTH_SUBJECT,
            "aud": resource,
            "iat": now,
            "nbf": now - 5,
            "exp": now + 600,
            "jti": _token(16),
            "client_id": client_id,
            "scope": scope,
        }
        access_token = jwt.encode(claims, self.jwt_secret, algorithm="HS256")
        refresh_token = _token(48)
        with self.store.connect() as db:
            db.execute(
                """INSERT INTO refresh_tokens
                (token_hash,client_id,scope,resource,expires_at,revoked)
                VALUES(?,?,?,?,?,0)""",
                (_hash(refresh_token), client_id, scope, resource, now + 30 * 86400),
            )
        return JSONResponse(
            {
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": 600,
                "refresh_token": refresh_token,
                "scope": scope,
            },
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )

    def verify_access_token(self, token: str) -> dict[str, Any] | None:
        try:
            return jwt.decode(
                token,
                self.jwt_secret,
                algorithms=["HS256"],
                audience=self.resource,
                issuer=self.issuer,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except jwt.PyJWTError:
            return None

    @staticmethod
    def _normalize_scope(scope: str | None) -> str | None:
        requested = set((scope or "mcp:read mcp:write").split())
        if not requested or not requested.issubset(SUPPORTED_SCOPES):
            return None
        return " ".join(sorted(requested))


def _oauth_error(error: str, *, status: int) -> JSONResponse:
    return JSONResponse(
        {"error": error}, status_code=status, headers={"Cache-Control": "no-store"}
    )
