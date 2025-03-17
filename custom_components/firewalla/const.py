"""Constants for the Firewalla integration."""
from typing import Final

DOMAIN: Final = "firewalla"
PLATFORMS: Final = ["binary_sensor", "sensor"]

# Configuration constants
CONF_API_TOKEN: Final = "api_token"
CONF_SUBDOMAIN: Final = "subdomain"
CONF_SCAN_INTERVAL: Final = "scan_interval"

# Default values
DEFAULT_SUBDOMAIN: Final = "api"
DEFAULT_API_URL: Final = "https://api.firewalla.net/v2"
DEFAULT_SCAN_INTERVAL: Final = 300  # 5 minutes

# Data storage keys
COORDINATOR: Final = "coordinator"
API_CLIENT: Final = "client"

# API constants
DEFAULT_TIMEOUT: Final = 30

# Entity attributes
ATTR_DEVICE_ID: Final = "device_id"
ATTR_DEVICE_NAME: Final = "device_name"
ATTR_NETWORK_ID: Final = "network_id"
ATTR_LAST_SEEN: Final = "last_seen"
ATTR_IP_ADDRESS: Final = "ip_address"
ATTR_MAC_ADDRESS: Final = "mac_address"
ATTR_ONLINE: Final = "online"
ATTR_BLOCKED: Final = "blocked"
ATTR_UPLOAD: Final = "upload"
ATTR_DOWNLOAD: Final = "download"
ATTR_BLOCKED_COUNT: Final = "blocked_count"
ATTR_ALARM_ID: Final = "alarm_id"
ATTR_RULE_ID: Final = "rule_id"

