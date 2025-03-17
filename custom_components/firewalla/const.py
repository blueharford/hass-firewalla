"""Constants for the Firewalla integration."""
from typing import Final

DOMAIN: Final = "firewalla"
PLATFORMS: Final = ["binary_sensor", "sensor", "switch"]

# Configuration constants
CONF_EMAIL: Final = "email"
CONF_PASSWORD: Final = "password"
CONF_API_KEY: Final = "api_key"
CONF_API_SECRET: Final = "api_secret"
CONF_API_TOKEN: Final = "api_token"
CONF_SUBDOMAIN: Final = "subdomain"
CONF_USE_MOCK_DATA: Final = "use_mock_data"
CONF_SCAN_INTERVAL: Final = "scan_interval"

# Default values
DEFAULT_SUBDOMAIN: Final = "api"
DEFAULT_SCAN_INTERVAL: Final = 300  # 5 minutes

# Data storage keys
COORDINATOR: Final = "coordinator"
API_CLIENT: Final = "client"

# API constants
DEFAULT_API_URL: Final = "https://api.firewalla.io/api/1.0"
DEFAULT_TIMEOUT: Final = 30
API_LOGIN_ENDPOINT: Final = "/users/login"
API_ORGS_ENDPOINT: Final = "/orgs"
API_NETWORKS_ENDPOINT: Final = "/networks"
API_DEVICES_ENDPOINT: Final = "/devices"

# Entity attributes
ATTR_DEVICE_ID: Final = "device_id"
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

