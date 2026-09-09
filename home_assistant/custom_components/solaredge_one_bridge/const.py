"""Constants for the SolarEdge Monitoring Bridge integration."""

from datetime import timedelta

DOMAIN = "solaredge_one_bridge"
PLATFORMS = ["sensor", "binary_sensor"]

CONF_ENDPOINT = "endpoint"
CONF_SHARED_SECRET = "shared_secret"

DEFAULT_ENDPOINT = "http://127.0.0.1:8000/internal/solaredge/snapshot"
DEFAULT_TIMEOUT_SECONDS = 30
CONF_POLL_INTERVAL = "poll_interval"
DEFAULT_POLL_INTERVAL_SECONDS = 300
MIN_POLL_INTERVAL_SECONDS = 60
MAX_POLL_INTERVAL_SECONDS = 3600
DEFAULT_UPDATE_INTERVAL = timedelta(seconds=DEFAULT_POLL_INTERVAL_SECONDS)

BRIDGE_SECRET_HEADER = "X-SolarEdge-Bridge-Secret"
