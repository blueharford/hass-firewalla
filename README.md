# Firewalla for Home Assistant

This integration allows you to monitor and control your Firewalla devices from Home Assistant.

## Features

- Monitor device status and connections
- View network flows and statistics
- Enable/disable firewall rules
- Get alerts for security events

## Installation

### HACS (Recommended)

1. Make sure you have [HACS](https://hacs.xyz/) installed
2. Go to HACS > Integrations
3. Click the three dots in the top right corner and select "Custom repositories"
4. Add this repository URL: `https://github.com/blueharford/hass-firewalla`
5. Select "Integration" as the category
6. Click "ADD"
7. Search for "Firewalla" and install it

### Manual Installation

1. Download the latest release from the [releases page](https://github.com/blueharford/hass-firewalla/releases)
2. Extract the `firewalla` folder from the zip file
3. Copy the `firewalla` folder to your Home Assistant's `custom_components` directory
4. Restart Home Assistant

## Configuration

1. Go to Home Assistant > Settings > Devices & Services
2. Click "Add Integration"
3. Search for "Firewalla" and select it
4. Enter your Firewalla subdomain (e.g., dn-jeyeek)
   - This is the unique subdomain for your MSP account (the part before .firewalla.net)
5. Enter your Firewalla API token
   - To get your API token, go to your Firewalla MSP account > Account Settings > Create New Token

## Available Entities

### Sensors

- Device Status: Shows the current status of each Firewalla device
- Device Connections: Shows the number of active connections for each device
- Flow Status: Shows the status of each network flow

### Switches

- Rule Switches: Enable or disable firewall rules

### Binary Sensors

- Alarm Sensors: Show active security alerts

## Support

If you have any issues or feature requests, please [open an issue](https://github.com/blueharford/hass-firewalla/issues) on GitHub.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

