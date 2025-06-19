# FMS Debug Tool v0.1

A Python-based desktop application for configuring and debugging Ultramarine FMS (Fuel Management System) devices.

## Features

- Serial port communication with FMS devices
- Real-time log monitoring with level filtering
- Device discovery via Zeroconf
- WiFi configuration management
- Protocol configuration for different pump types
- Command history tracking
- Log saving and filtering capabilities

## Requirements

- Python 3.6+
- PyQt5
- pyserial
- zeroconf
- requests

## Installation

1. Clone the repository or download the files
2. Install required packages:
```bash
pip install PyQt5 pyserial zeroconf requests
```

## Usage

Run the application:
```bash
python ultmSetupV0.1.py
```

### Main Functions

1. **Device Connection**
   - Select COM port and baud rate
   - Connect/disconnect to FMS device

2. **Log Monitoring**
   - Real-time log display with level coloring
   - Log filtering by level and text
   - Save logs to txt/csv

3. **Device Configuration**
   - WiFi setup
   - Protocol configuration (Tatsuno, Gilbarco, etc.)
   - Device UUID management

4. **Device Discovery**
   - Auto-detect FMS devices on network
   - Quick connect to discovered devices

## Commands

- `wifi <ssid> <password>` - Configure WiFi settings
- `wifi_connect <ssid> <password>` - Connect to WiFi network
- `restart` - Restart system
- `wifiscan_safe` - Scan for WiFi networks
- `wifiread` - Read current WiFi status
- `uuid_change <uuid>` - Change device ID
- `login <password>` - Login to CLI
- `help` - Show available commands

# FMS Debug Tool Documentation

## Quick Links

- [User Manual (PDF)](docs/Debug_Tool_User_Manual.pdf)
<!-- - [Protocol Documentation (PDF)](docs/FMS_Protocol_Documentation.pdf)
- [Developer Guide (PDF)](docs/FMS_Developer_Guide.pdf) -->

## Overview

The FMS Debug Tool is a diagnostic and configuration utility for FMS devices. This tool provides:

- Serial port monitoring and debugging
- WiFi configuration
- Protocol settings
- Device discovery
- Nozzle configuration
- Command line interface

## Documentation

For detailed information, please refer to the PDF documentation:

1. [User Manual](docs/FMS_Debug_Tool_User_Manual.pdf) - Complete guide for using the debug tool
<!-- 2. [Protocol Documentation](docs/FMS_Protocol_Documentation.pdf) - Details about supported protocols and their implementation
3. [Developer Guide](docs/FMS_Developer_Guide.pdf) - Technical documentation for developers -->

## Support

For technical support or questions, please contact support@iih

## License

Copyright © 2025 iih (Thailand)