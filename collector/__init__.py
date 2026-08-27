"""Host-local, privilege-separated diagnostics collector."""

from .ha_host_diagnostics import Collector, CollectorConfig, sanitize_text

__all__ = ["Collector", "CollectorConfig", "sanitize_text"]
