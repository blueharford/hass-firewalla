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
4. Add this repository URL: `https://github.com/blurharford/hass-firewalla`
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
4. Enter your Firewalla subdomain (e.g., subdomain)
   - This is the unique subdomain for your MSP account (the part before .firewalla.net)
5. Enter your Firewalla API token
   - To get your API token, go to your Firewalla MSP account > Account Settings > Create New Token

## Troubleshooting

### API Response Issues

If you see errors like "Failed to parse JSON response" or empty responses from the API, the integration will now use mock data to ensure functionality. This means:

1. You'll see a simulated Firewalla device in Home Assistant
2. The sensors and switches will work, but they won't reflect your actual Firewalla devices
3. The integration will continue to try to connect to the real API in the background

This is a fallback mechanism to ensure the integration works even when there are API issues.

### Why Mock Data?

The Firewalla MSP API may have different structures for different accounts, or some endpoints might not be accessible with your API token. The mock data allows you to:

1. Test the integration functionality
2. See how the entities would appear with real data
3. Have a working integration while troubleshooting API issues

### Resolving API Issues

To get real data from your Firewalla devices:

1. **Contact Firewalla Support**:
   - Ask about the correct API endpoints for your MSP account
   - Confirm that your API token has the necessary permissions
   - Inquire about any specific API requirements for your account

2. **Check API Documentation**:
   - If you have access to Firewalla MSP API documentation, verify the correct endpoints
   - Look for any required parameters or headers that might be missing

3. **Enable Endpoint Discovery**:
   - The integration now attempts to discover the correct API endpoints
   - Check the logs to see if any endpoints were successfully discovered

4. **Enable Debug Logging**:
   Add the following to your `configuration.yaml` to get more detailed logs:
   ```yaml
   logger:
     default: info
     logs:
       custom_components.firewalla: debug
