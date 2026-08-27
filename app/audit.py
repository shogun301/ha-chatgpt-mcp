from __future__ import annotations

import json
import logging
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .ha_client import redact_sensitive

LOGGER = logging.getLogger("ha_chatgpt_mcp.audit")
_lock = threading.Lock()


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, event: str, **fields: Any) -> None:
        safe = redact_sensitive(
            {
                "timestamp": datetime.now(UTC).isoformat(),
                "event": event,
                **{key: value for key, value in fields.items() if value is not None},
            }
        )
        line = json.dumps(safe, separators=(",", ":"), sort_keys=True)
        with _lock, self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        LOGGER.info("audit_event=%s", event)

    def latest_tool_call(
        self,
        tool_names: set[str],
        *,
        max_bytes: int = 1_048_576,
    ) -> dict[str, Any] | None:
        """Return the newest matching safe audit entry from a bounded log tail."""
        if not self.path.exists():
            return None
        with _lock, self.path.open("rb") as handle:
            handle.seek(0, 2)
            size = handle.tell()
            start = max(0, size - max_bytes)
            handle.seek(start)
            data = handle.read()
        if start:
            _, _, data = data.partition(b"\n")
        for raw_line in reversed(data.splitlines()):
            try:
                item = json.loads(raw_line)
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if item.get("event") == "tool_call" and item.get("tool") in tool_names:
                return item
        return None
