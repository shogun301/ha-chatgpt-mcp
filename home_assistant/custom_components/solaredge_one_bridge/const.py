"""Constants for the SolarEdge Monitoring Bridge integration."""

from datetime import timedelta

DOMAIN = "solaredge_one_bridge"
PLATFORMS = ["sensor"]

CONF_ENDPOINT = "endpoint"
CONF_SHARED_SECRET = "shared_secret"

DEFAULT_ENDPOINT = "http://127.0.0.1:8000/internal/solaredge/snapshot"
DEFAULT_TIMEOUT_SECONDS = 10
DEFAULT_UPDATE_INTERVAL = timedelta(minutes=5)

BRIDGE_SECRET_HEADER = "X-SolarEdge-Bridge-Secret"
