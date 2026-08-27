"""HTTP client for the local SolarEdge Monitoring bridge endpoint."""

from __future__ import annotations

import ipaddress
from typing import Any
from urllib.parse import urlparse

import aiohttp

from .const import BRIDGE_SECRET_HEADER, DEFAULT_TIMEOUT_SECONDS
from .model import InvalidSnapshot, SolarEdgeSnapshot, parse_snapshot


class BridgeError(Exception):
    """Base error for bridge communication failures."""


class BridgeAuthenticationError(BridgeError):
    """Raised when the bridge rejects the shared secret."""


class BridgeConnectionError(BridgeError):
    """Raised when the bridge cannot be reached or returns an invalid response."""


def is_local_endpoint(endpoint: str) -> bool:
    """Return whether an endpoint is constrained to a local/private destination."""
    try:
        parsed = urlparse(endpoint)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return False
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            return False
        if parsed.hostname.casefold() == "localhost":
            return True
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        # Docker-internal DNS names cannot be resolved safely here. A simple
        # unqualified hostname remains confined to the local resolver/search domain.
        return "." not in (parsed.hostname or "")
    return address.is_private or address.is_loopback or address.is_link_local


class SolarEdgeBridgeClient:
    """Fetch sanitized snapshots from the local bridge."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        endpoint: str,
        shared_secret: str,
        *,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._session = session
        self._endpoint = endpoint
        self._shared_secret = shared_secret
        self._timeout = aiohttp.ClientTimeout(total=timeout_seconds)

    async def async_get_snapshot(self) -> SolarEdgeSnapshot:
        """Retrieve and validate one bridge snapshot."""
        try:
            async with self._session.get(
                self._endpoint,
                headers={BRIDGE_SECRET_HEADER: self._shared_secret},
                timeout=self._timeout,
            ) as response:
                if response.status in (401, 403):
                    raise BridgeAuthenticationError("bridge authentication failed")
                if response.status != 200:
                    raise BridgeConnectionError(
                        f"bridge returned HTTP {response.status}"
                    )
                try:
                    payload: Any = await response.json(content_type=None)
                except (aiohttp.ContentTypeError, ValueError) as err:
                    raise BridgeConnectionError("bridge returned invalid JSON") from err
        except BridgeError:
            raise
        except (TimeoutError, aiohttp.ClientError) as err:
            raise BridgeConnectionError("bridge request failed") from err

        try:
            return parse_snapshot(payload)
        except InvalidSnapshot as err:
            raise BridgeConnectionError("bridge returned an invalid snapshot") from err
