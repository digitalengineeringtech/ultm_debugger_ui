# version 0.1
# author: @ultm
# date: 2025-06-05
# description: This is a simple CLI for the FMS device.
# it is a simple CLI for the FMS device.

#!/usr/bin/env python3
import sys
import time
import re
import json
import socket
import struct
import threading
import webbrowser
import requests
from datetime import datetime
from zeroconf import ServiceBrowser, Zeroconf
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QLabel, QPushButton, QComboBox, QCheckBox, QLineEdit, 
    QTextEdit, QTabWidget, QGroupBox, QFormLayout, QSpinBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QSplitter,
    QFileDialog, QMessageBox, QDialog, QGridLayout, QInputDialog,
    QDialogButtonBox, QFrame, QListWidget, QListWidgetItem, QMenu
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QSettings
from PyQt5.QtGui import QColor, QTextCharFormat, QFont, QIcon, QSyntaxHighlighter, QTextCursor
import serial
import serial.tools.list_ports

# Log level mapping
LOG_LEVELS = {
    "ERROR": 0,
    "WARN": 1, 
    "WARNING": 1,
    "INFO": 2,
    "DEBUG": 3,
    "VERB": 4,
    "VERBOSE": 4,
    "TASK": 5,
    "NONE": 6
}

# Colors for different log levels
LOG_COLORS = {
    "ERROR": QColor(255, 80, 80),
    "WARN": QColor(255, 180, 0),
    "WARNING": QColor(255, 180, 0),
    "INFO": QColor(0, 120, 215),
    "DEBUG": QColor(128, 0, 128),
    "VERB": QColor(0, 160, 0),
    "VERBOSE": QColor(0, 160, 0),
    "TASK": QColor(0, 160, 160),
    "NONE": QColor(128, 128, 128)
}

# CLI Commands
CLI_COMMANDS = {
    "wifi": {
        "description": "Configure WiFi settings",
        "usage": "wifi <ssid> <password>",
        "min_args": 2,
        "max_args": 2
    },
    "wifi_connect": {
        "description": "Connect to WiFi network",
        "usage": "wifi_connect <ssid> <password>",
        "min_args": 2,
        "max_args": 2
    },
    "restart": {
        "description": "Restart the system",
        "usage": "restart",
        "min_args": 0,
        "max_args": 0
    },
    "wifiscan_safe": {
        "description": "Scan for WiFi networks (safe mode)",
        "usage": "wifiscan_safe",
        "min_args": 0,
        "max_args": 0
    },
    "wifiread": {
        "description": "Read current WiFi status",
        "usage": "wifiread",
        "min_args": 0,
        "max_args": 0
    },
    "wifi_test": {
        "description": "Test WiFi connection",
        "usage": "wifi_test",
        "min_args": 0,
        "max_args": 0
    },
    "uuid_change": {
        "description": "Change Your Device Id unique address",
        "usage": "uuid_change <uuid>",
        "min_args": 1,
        "max_args": 1
    },
    "help": {
        "description": "Help command",
        "usage": "help",
        "min_args": 0,
        "max_args": 0
    },
    "login": {
        "description": "Login to CLI with password",
        "usage": "login <password>",
        "min_args": 1,
        "max_args": 1
    },
    "echo": {
        "description": "Toggle command echo",
        "usage": "echo [on|off]",
        "min_args": 0,
        "max_args": 1
    },
    "logout": {
        "description": "Logout from CLI",
        "usage": "logout",
        "min_args": 0,
        "max_args": 0
    }
}

class OTADiscoveryListener:
    def __init__(self, callback):
        self.callback = callback

    def remove_service(self, zeroconf, type, name):
        pass

    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        if info:
            try:
                ip = socket.inet_ntoa(info.addresses[0])
                device_name = info.name.split('.')[0]
                url = f"http://{ip}/api/info"
                response = requests.get(url, timeout=2)
                if response.ok:
                    data = response.json()
                    if "deviceName" in data and "firmwareVersion" in data:
                        self.callback({
                            "name": data["deviceName"],
                            "ip": ip,
                            "version": data["firmwareVersion"],
                            "rssi": data["rssi"],
                            "uptime": data["uptime"],
                            "mac": data["macAddress"]
                        })
            except Exception as e:
                print(f"Failed to get info for {name}: {e}")

class JsonSyntaxHighlighter(QSyntaxHighlighter):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.highlighting_rules = []

        # Define formats for different parts of JSON
        key_format = QTextCharFormat()
        key_format.setForeground(QColor(0, 120, 215))  # Blue for keys
        key_format.setFontWeight(QFont.Bold)

        string_format = QTextCharFormat()
        string_format.setForeground(QColor(0, 160, 0))  # Green for strings

        number_format = QTextCharFormat()
        number_format.setForeground(QColor(128, 0, 128))  # Purple for numbers

        boolean_format = QTextCharFormat()
        boolean_format.setForeground(QColor(255, 140, 0))  # Orange for booleans

        # Add rules for highlighting
        self.highlighting_rules.append((re.compile(r'"([^"]+)"\s*:'), key_format))
        self.highlighting_rules.append((re.compile(r':\s*"([^"]+)"'), string_format))
        self.highlighting_rules.append((re.compile(r':\s*(-?\d+(\.\d+)?)'), number_format))
        self.highlighting_rules.append((re.compile(r':\s*(true|false|null)'), boolean_format))

    def highlightBlock(self, text):
        for pattern, format in self.highlighting_rules:
            for match in pattern.finditer(text):
                self.setFormat(match.start(), match.end() - match.start(), format)

class LogEntry:
    def __init__(self, timestamp, level, message, raw=None):
        self.timestamp = timestamp
        self.level = level
        self.message = message
        self.raw = raw or f"[{timestamp}] [{level}] {message}"
       
    
    def __str__(self):
        return self.raw

class SerialReaderThread(QThread):
    log_received = pyqtSignal(str)
    connection_error = pyqtSignal(str)
    
    def __init__(self, port, baud_rate):
        super().__init__()
        self.port = port
        self.baud_rate = baud_rate
        self.running = False
        self.serial_port = None
    
    def run(self):
        try:
            self.serial_port = serial.Serial(
                port=self.port,
                baudrate=self.baud_rate,
                timeout=0.1
            )
            self.running = True
            
            buffer = ""
            while self.running:
                if self.serial_port.in_waiting:
                    data = self.serial_port.read(self.serial_port.in_waiting).decode('utf-8', errors='replace')
                    buffer += data
                    
                    lines = re.split(r'\r?\n', buffer)
                    buffer = lines.pop()
                    
                    for line in lines:
                        if line.strip():
                            self.log_received.emit(line.strip())
                
                time.sleep(0.01)
                
        except serial.SerialException as e:
            self.connection_error.emit(f"Serial connection error: {str(e)}")
        finally:
            if self.serial_port and self.serial_port.is_open:
                self.serial_port.close()
    
    def stop(self):
        self.running = False
        self.wait()
        if self.serial_port and self.serial_port.is_open:
            self.serial_port.close()
    
    def send_command(self, command):
        if not self.running or not self.serial_port or not self.serial_port.is_open:
            raise Exception("Serial port not connected")
        
        if not command.endswith('\r\n'):
            if command.endswith('\n'):
                command = command[:-1] + '\r\n'
            elif command.endswith('\r'):
                command = command + '\n'
            else:
                command += '\r\n'
        
        self.serial_port.write(command.encode('utf-8'))
        self.serial_port.flush()
        time.sleep(0.05)

class LogParser:
    @staticmethod
    def parse_log_line(line):
        pattern = r'\[(.*?)\]\s*\[(.*?)\]\s*(.*)'
        match = re.match(pattern, line)
        
        if match:
            timestamp = match.group(1)
            level = match.group(2).upper()
            message = match.group(3)
            
            if level not in LOG_LEVELS:
                if "WARN" in level:
                    level = "WARN"
                elif "ERR" in level:
                    level = "ERROR"
                elif "INFO" in level:
                    level = "INFO"
                elif "DEBUG" in level:
                    level = "DEBUG"
                elif "VERB" in level:
                    level = "VERB"
                elif "TASK" in level:
                    level = "TASK"
                else:
                    level = "NONE"
            
            return LogEntry(timestamp, level, message, line)
        
        try:
            if line.strip().startswith('{') and line.strip().endswith('}'):
                data = json.loads(line)
                if isinstance(data, dict):
                    now = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                    command = data.get("command", "unknown")
                    success = data.get("success", True)
                    result = data.get("result", "")
                    message = f"Command '{command}': {result}"
                    level = "INFO" if success else "ERROR"
                    
                    # Show dialog box for successful login
                    if command == "login" and success and result == "Login successful":
                        QMessageBox.information(None, "Login Status", "Login successful")
                    
                    return LogEntry(now, level, message, line)
        except json.JSONDecodeError:
            pass
        except Exception:
            pass
        
        if "interruptSection" in line:
            now = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            return LogEntry(now, "DEBUG", f"Interrupt: {line}", line)
        
        now = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        return LogEntry(now, "NONE", line, line)

class WiFiConfigDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("WiFi Configuration")
        self.resize(400, 150)
        
        layout = QFormLayout()
        
        self.ssid_input = QLineEdit()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        
        layout.addRow("SSID:", self.ssid_input)
        layout.addRow("Password:", self.password_input)
        
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        
        layout.addRow(buttons)
        layout.addRow(QLabel("Save to ultmFlashStorage Needed to Restart"))
        self.setLayout(layout)
    
    def get_values(self):
        return self.ssid_input.text(), self.password_input.text()

class UUIDChangeDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Change Device UUID")
        self.resize(400, 100)
        
        layout = QFormLayout()
        
        self.uuid_input = QLineEdit()
        
        layout.addRow("New UUID:", self.uuid_input)
        
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        
        layout.addRow(buttons)
        self.setLayout(layout)
    
    def get_value(self):
        return self.uuid_input.text()

class LoginDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Login to FMS CLI")
        self.resize(400, 100)
        
        layout = QFormLayout()
        
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        
        layout.addRow("Password:", self.password_input)
        
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        
        layout.addRow(buttons)
        self.setLayout(layout)
    
    def get_password(self):
        return self.password_input.text()

class CommandDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Send Command")
        self.resize(500, 400)
        
        layout = QVBoxLayout()
        
        input_layout = QHBoxLayout()
        self.command_input = QLineEdit()
        command_group = QGroupBox("Available Commands")
        command_layout = QVBoxLayout()
        
        self.command_table = QTableWidget(len(CLI_COMMANDS), 2)
        self.command_table.setHorizontalHeaderLabels(["Command", "Description"])
        self.command_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.command_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.command_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.command_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.command_table.itemDoubleClicked.connect(self.command_selected)
        
        row = 0
        for cmd, info in CLI_COMMANDS.items():
            self.command_table.setItem(row, 0, QTableWidgetItem(cmd))
            self.command_table.setItem(row, 1, QTableWidgetItem(info["description"]))
            row += 1
        
        command_layout.addWidget(self.command_table)
        command_group.setLayout(command_layout)
        
        details_group = QGroupBox("Command Details")
        details_layout = QVBoxLayout()
        self.command_details = QTextEdit()
        self.command_details.setReadOnly(True)
        details_layout.addWidget(self.command_details)
        details_group.setLayout(details_layout)
        
        layout.addLayout(input_layout)
        layout.addWidget(command_group)
        layout.addWidget(details_group)
        
        self.setLayout(layout)
        
        self.command_table.itemSelectionChanged.connect(self.update_command_details)
        self.command_input.returnPressed.connect(self.accept)
    
    def update_command_details(self):
        selected_items = self.command_table.selectedItems()
        if not selected_items:
            return
        
        row = selected_items[0].row()
        command = self.command_table.item(row, 0).text()
        
        if command in CLI_COMMANDS:
            info = CLI_COMMANDS[command]
            details = f"Command: {command}\n"
            details += f"Description: {info['description']}\n"
            details += f"Usage: {info['usage']}\n"
            details += f"Arguments: {info['min_args']} to {info['max_args']}"
            self.command_details.setText(details)
    
    def command_selected(self, item):
        row = item.row()
        command = self.command_table.item(row, 0).text()
        self.command_input.setText(command)
    
    def get_command(self):
        return self.command_input.text()

class MQTTConfigDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("MQTT Configuration")
        self.resize(400, 200)
        
        layout = QFormLayout()
        
        self.broker_input = QLineEdit()
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(1883)
        
        layout.addRow("Broker Address:", self.broker_input)
        layout.addRow("Port:", self.port_input)
        
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        
        layout.addRow(buttons)
        self.setLayout(layout)
    
    def get_values(self):
        return self.broker_input.text(), self.port_input.value()

class DeviceSetupDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Device Protocol Configuration")
        self.resize(600, 400)
        
        # Main layout
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        
        # Protocol Selection
        protocol_group = QGroupBox("Protocol Selection")
        protocol_layout = QHBoxLayout()
        protocol_layout.setAlignment(Qt.AlignLeft)
        
        protocol_label = QLabel("Select Protocol:")
        protocol_label.setMinimumWidth(120)
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["tatsuno", "gilbarco", "redstar", "haungyang"])
        
        protocol_layout.addWidget(protocol_label)
        protocol_layout.addWidget(self.protocol_combo)
        protocol_layout.addStretch()
        protocol_group.setLayout(protocol_layout)
        
        # Device Configuration
        config_group = QGroupBox("Device Configuration")
        config_layout = QGridLayout()
        config_layout.setColumnStretch(1, 1)
        config_layout.setHorizontalSpacing(15)
        config_layout.setVerticalSpacing(10)
        
        # Device and Nozzle configuration
        self.devSpin = QSpinBox()
        self.devSpin.setRange(0, 255)
        self.nozSpin = QSpinBox()
        self.nozSpin.setRange(0, 255)
        
        config_layout.addWidget(QLabel("Device Number:"), 0, 0)
        config_layout.addWidget(self.devSpin, 0, 1)
        config_layout.addWidget(QLabel("Nozzle Number:"), 1, 0)
        config_layout.addWidget(self.nozSpin, 1, 1)
        
        # Pump IDs
        pump_group = QGroupBox("Pump ID Configuration")
        pump_layout = QGridLayout()
        pump_layout.setHorizontalSpacing(15)
        pump_layout.setVerticalSpacing(10)
        
        self.pumpSpins = []
        for i in range(8):
            label = QLabel(f"Pump ID {i+1}:")
            spin = QSpinBox()
            spin.setRange(0, 255)
            self.pumpSpins.append(spin)
            
            # Create a 2-column layout (4 rows x 2 columns)
            row = i // 2
            col = (i % 2) * 2
            pump_layout.addWidget(label, row, col)
            pump_layout.addWidget(spin, row, col + 1)
        
        pump_group.setLayout(pump_layout)
        
        # Add all groups to the main layout
        layout.addWidget(protocol_group)
        layout.addWidget(config_group)
        config_group.setLayout(config_layout)
        layout.addWidget(pump_group)
        
        # Add a spacer before the buttons
        layout.addSpacing(10)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.sendBtn = QPushButton("Send Configuration")
        self.sendBtn.setMinimumWidth(200)
        self.sendBtn.clicked.connect(self.accept)
        
        cancelBtn = QPushButton("Cancel")
        cancelBtn.clicked.connect(self.reject)
        
        button_layout.addStretch()
        button_layout.addWidget(self.sendBtn)
        button_layout.addWidget(cancelBtn)
        button_layout.addStretch()
        
        layout.addLayout(button_layout)
    
    def get_configuration(self):
        return {
            'protocol': self.protocol_combo.currentText(),
            'device': self.devSpin.value(),
            'nozzle': self.nozSpin.value(),
            'pumps': [spin.value() for spin in self.pumpSpins]
        }

class FMSDebugUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("FMS Debug Logger")
        self.resize(1000, 700)
        
        # Initialize variables
        self.serial_thread = None
        self.logs = []
        self.current_filter_level = "INFO"
        self.filter_text = ""
        self.auto_scroll = True
        self.max_logs = 10000
        self.command_history = []
        self.command_history_index = -1
        self.is_authenticated = False
        self.all_logs_auto_scroll = True
        self.discovered_devices = {}
        self.protocols = ["tatsuno", "gilbarco", "redstar", "haungyang"]
        # Load settings
        self.settings = QSettings("FMSDebug", "LoggerUI")
        
        # Setup UI
        self.setup_ui()
        self.setup_toolbar()
        self.load_settings()
        self.refresh_ports()
        
        # Setup auto-refresh for ports
        self.port_refresh_timer = QTimer(self)
        self.port_refresh_timer.timeout.connect(self.refresh_ports)
        self.port_refresh_timer.start(5000)
    
    def setup_ui(self):
        main_widget = QWidget()
        main_layout = QVBoxLayout(main_widget)
       
        self.tabs = QTabWidget()
        
        # Create tabs
        self.tabs.addTab(self.create_log_tab(), "Logs & Commands")
        self.tabs.addTab(self.create_device_discovery_tab(), "Find Device")
        self.tabs.addTab(self.create_noz_setting_tab(),"NOZZLE SETTING")
        main_layout.addWidget(self.tabs)
        self.setCentralWidget(main_widget)
        
        # Status bar
        self.statusBar().showMessage("Ready")
    
    def setup_toolbar(self):
        toolbar = self.addToolBar("Main Toolbar")
        toolbar.setMovable(False)
    
        # Help action
        help_action = toolbar.addAction("Help")
        help_action.setStatusTip("Show command help")
        help_action.triggered.connect(self.show_command_dialog)
        toolbar.addSeparator()
        
        # Device Setup action
        setup_action = toolbar.addAction("Device Setup")
        setup_action.setStatusTip("Configure device protocol settings")
        setup_action.triggered.connect(self.show_device_setup_dialog)
        toolbar.addSeparator()
        
        # About
        about_action = toolbar.addAction("About")
        about_action.setStatusTip("About FMS Debug Logger")
        about_action.triggered.connect(self.show_about_dialog)

    def create_log_tab(self):
        log_tab = QWidget()
        layout = QVBoxLayout(log_tab)
       
        # Top controls
        top_layout = QHBoxLayout()
        
        # Cli Login Layout
        login_layout = QHBoxLayout()
        self.login_button = QPushButton("Login to CLI")
        self.login_button.setStyleSheet("""
                QPushButton {
                    background-color: #6200EE;
                    color: white;
                    font-size: 14px;
                    font-weight: bold;
                    border-radius: 4px;
                    padding: 8px 16px;
                    border: none;
                }
                QPushButton:hover {
                    background-color: #3700B3;
                }
                QPushButton:pressed {
                    background-color: #6200EE;
                    
                }
                QPushButton:disabled {
                    background-color: #CCCCCC;
                    color: #666666;
                }
            """)

        self.login_button.setToolTip("Login to the CLI command terminal")
        self.login_button.setStatusTip("Login to the CLI command terminal")

        self.login_button.clicked.connect(self.show_login_dialog)
        login_layout.addWidget(self.login_button)

        # Connection group
        connection_group = QGroupBox("Connection")
        connection_layout = QFormLayout()
        
        self.port_combo = QComboBox()
        self.baud_combo = QComboBox()
        for rate in ["9600", "19200", "38400", "57600", "115200"]:
            self.baud_combo.addItem(rate)
        self.baud_combo.setCurrentText("115200")
        
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.refresh_ports)
        
        self.connect_button = QPushButton("Connect")
        self.connect_button.clicked.connect(self.toggle_connection)
        
        port_layout = QHBoxLayout()
        port_layout.addWidget(self.port_combo)
        port_layout.addWidget(self.refresh_button)
        
        connection_layout.addRow("Port:", port_layout)
        connection_layout.addRow("Baud Rate:", self.baud_combo)
        connection_layout.addRow("", self.connect_button)
        connection_layout.addRow(login_layout)
        connection_layout.addRow(QLabel("Before Send Command to ultramarine board , plese login CLI  terminal"))
       
  
        connection_group.setLayout(connection_layout)
        top_layout.addWidget(connection_group)

        # Quick commands group
        quick_commands_group = QGroupBox("Quick Commands")
        quick_layout = QGridLayout()
        
        # WiFi commands
        wifi_config_button = QPushButton("WiFi Config")
        wifi_config_button.clicked.connect(self.show_wifi_config_dialog)
        
        wifi_connect_button = QPushButton("WiFi Connect")
        wifi_connect_button.clicked.connect(self.show_wifi_connect_dialog)
        
        wifi_status_button = QPushButton("WiFi Status")
        wifi_status_button.clicked.connect(lambda: self.send_cli_command("wifiread"))
        
        # System commands
        restart_button = QPushButton("Restart System")
        restart_button.clicked.connect(self.confirm_restart)
        
        uuid_button = QPushButton("Change UUID")
        uuid_button.clicked.connect(self.show_uuid_dialog)
        
        help_button = QPushButton("Help")
        help_button.clicked.connect(self.show_command_dialog)
        
        # Add buttons to grid
        quick_layout.addWidget(QLabel("<b>WiFi Commands</b>"), 0, 0, 1, 2)
        quick_layout.addWidget(wifi_config_button, 1, 0)
        quick_layout.addWidget(wifi_connect_button, 1, 1)
        quick_layout.addWidget(wifi_status_button, 2, 1)
        
        quick_layout.addWidget(QLabel("<b>System Commands</b>"), 4, 0, 1, 2)
        quick_layout.addWidget(restart_button, 5, 0)
        quick_layout.addWidget(uuid_button, 5, 1)
        quick_layout.addWidget(help_button, 6, 0)
        
        # Add Mqtt Commands 
        quick_layout.addWidget(QLabel("<b>MQTT Commands</b>"), 7, 0, 1, 2)
        mqtt_connect_button = QPushButton("MQTT Connect")
        mqtt_connect_button.clicked.connect(self.show_mqtt_dialog)
        quick_layout.addWidget(mqtt_connect_button, 8, 0)


        quick_commands_group.setLayout(quick_layout)
        top_layout.addWidget(quick_commands_group)

        # Custom command
        custom_command_group = QGroupBox("Custom Command")
        custom_layout = QHBoxLayout()
        
        self.custom_command_input = QLineEdit()
        self.custom_command_input.setPlaceholderText("Enter command...")
        self.custom_command_input.returnPressed.connect(self.send_custom_command)
        self.custom_command_input.installEventFilter(self)
        
        send_button = QPushButton("Send")
        send_button.clicked.connect(self.send_custom_command)
        
        custom_layout.addWidget(self.custom_command_input)
        custom_layout.addWidget(send_button)
        custom_command_group.setLayout(custom_layout)
        
        layout.addLayout(top_layout)
        layout.addWidget(custom_command_group)

        # Create a splitter for logs, command response and history
        main_splitter = QSplitter(Qt.Vertical)
        
        # Log section
        log_group = QGroupBox("Log Output")
        log_layout = QVBoxLayout()
        
        # Controls
        controls_layout = QHBoxLayout()
        self.all_logs_auto_scroll_check = QCheckBox("Auto-scroll")
        self.all_logs_auto_scroll_check.setChecked(True)
        self.all_logs_auto_scroll_check.stateChanged.connect(self.toggle_all_logs_auto_scroll)
        
        self.all_logs_clear_button = QPushButton("Clear Logs")
        self.all_logs_clear_button.clicked.connect(self.clear_all_logs)
        
        self.all_logs_save_button = QPushButton("Save Logs")
        self.all_logs_save_button.clicked.connect(self.save_all_logs)
        
        controls_layout.addWidget(self.all_logs_auto_scroll_check)
        controls_layout.addStretch()
        controls_layout.addWidget(self.all_logs_clear_button)
        controls_layout.addWidget(self.all_logs_save_button)
        
        log_layout.addLayout(controls_layout)
        
        # Log table and details
        log_splitter = QSplitter(Qt.Vertical)
        self.all_logs_table = QTableWidget(0, 3)
        self.all_logs_table.setHorizontalHeaderLabels(["Timestamp", "Level", "Message"])
        self.all_logs_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.all_logs_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.all_logs_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.all_logs_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.all_logs_table.setEditTriggers(QTableWidget.NoEditTriggers)
        
        self.all_logs_details = QTextEdit()
        self.all_logs_details.setReadOnly(True)
        self.all_logs_details.setFont(QFont("Monospace", 9))
        
        log_splitter.addWidget(self.all_logs_table)
        log_splitter.addWidget(self.all_logs_details)
        log_layout.addWidget(log_splitter)
        log_group.setLayout(log_layout)
        
        # Command history section
        history_group = QGroupBox("Command History")
        history_layout = QVBoxLayout()
        
        self.history_list = QTableWidget(0, 2)
        self.history_list.setHorizontalHeaderLabels(["Command", "Time"])
        self.history_list.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.history_list.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.history_list.setSelectionBehavior(QTableWidget.SelectRows)
        self.history_list.setEditTriggers(QTableWidget.NoEditTriggers)
        self.history_list.itemDoubleClicked.connect(self.use_history_command)
        
        clear_history_button = QPushButton("Clear History")
        clear_history_button.clicked.connect(self.clear_command_history)
        
        history_layout.addWidget(self.history_list)
        history_layout.addWidget(clear_history_button)
        history_group.setLayout(history_layout)
        
        # Add groups to main splitter
        main_splitter.addWidget(log_group)
        main_splitter.addWidget(history_group)
        main_splitter.setSizes([300, 200, 200])
        layout.addWidget(main_splitter)
        
        # Connect signals
        self.all_logs_table.itemSelectionChanged.connect(self.show_all_logs_details)
        
        return log_tab
    
    def create_device_discovery_tab(self):
        device_tab = QWidget()
        layout = QVBoxLayout(device_tab)
        
        header = QLabel("Ultm FMS Devices Discovery")
        header.setAlignment(Qt.AlignCenter)
        header.setStyleSheet("font-size: 16px; font-weight: bold;")
        
        # Replace list with table
        self.device_table = QTableWidget()
        self.device_table.setColumnCount(6)
        self.device_table.setHorizontalHeaderLabels(["Signal", "Device Name", "IP Address", "MAC", "Version", "Uptime"])
        
        # Set column resize modes
        self.device_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)  # Signal
        self.device_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)          # Device Name
        self.device_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents) # IP
        self.device_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents) # MAC
        self.device_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents) # Version
        self.device_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents) # Uptime
        
        self.device_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.device_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.device_table.verticalHeader().setVisible(False)
        
        self.refresh_button = QPushButton("Refresh Devices")
        self.refresh_button.clicked.connect(self.start_discovery)
        
        # Action buttons
        button_layout = QHBoxLayout()
        self.open_dashboard_button = QPushButton("Open Dashboard")
        self.open_dashboard_button.clicked.connect(self.open_selected_device_dashboard)
        self.open_dashboard_button.setEnabled(False)
        
        button_layout.addWidget(self.open_dashboard_button)
        
        layout.addWidget(header)
        layout.addWidget(self.device_table)
        layout.addWidget(self.refresh_button)
        layout.addLayout(button_layout)
        
        # Connect signals
        self.device_table.itemSelectionChanged.connect(self.update_device_buttons)
        
        return device_tab
    
    def create_noz_setting_tab(self):
        # Nozzle Configuration Tab
        nozzle_tab = QWidget()
        nozzle_layout = QVBoxLayout(nozzle_tab)
        nozzle_layout.setSpacing(15)
        
        # Default values
        default_names = [
            "001-Octane Ron(92)",
            "001-Octane Ron(92)",
            "004-Diesel",
            "005-Premium Diesel",
            "004-Diesel",
            "002-Octane Ron(95)",
            "",
            ""
        ]
        default_prices = [3000, 3200, 0, 0, 0, 0, 0, 0]
        
        # Create a grid for nozzle groups (2 columns)
        nozzle_grid = QGridLayout()
        nozzle_grid.setSpacing(10)
        self.nozzle_names = []
        self.nozzle_prices = []
        
        for i in range(8):
            nozzle_group = QGroupBox(f"Nozzle {i+1}")
            nozzle_group_layout = QGridLayout()
            nozzle_group_layout.setSpacing(8)
            
            name = QLineEdit()
            name.setPlaceholderText(f"Nozzle {i+1} Name")
            name.setText(default_names[i])
            
            price = QSpinBox()
            price.setRange(0, 99999)
            price.setSingleStep(100)
            price.setValue(default_prices[i])
            
            self.nozzle_names.append(name)
            self.nozzle_prices.append(price)
            
            nozzle_group_layout.addWidget(QLabel("Name:"), 0, 0)
            nozzle_group_layout.addWidget(name, 0, 1)
            nozzle_group_layout.addWidget(QLabel("Price:"), 1, 0)
            nozzle_group_layout.addWidget(price, 1, 1)
            
            nozzle_group.setLayout(nozzle_group_layout)
            nozzle_grid.addWidget(nozzle_group, i//2, i%2)
        
        nozzle_layout.addLayout(nozzle_grid)
        return nozzle_tab
        # tab_widget.addTab(nozzle_tab, "Nozzle Settings")
        
        # # Control Buttons
        # button_layout = QHBoxLayout()
        # button_layout.setSpacing(10)
        # save_btn = QPushButton("Save Configuration")
        # save_btn.clicked.connect(self.save_config)
        # load_btn = QPushButton("Load Configuration")
        # load_btn.clicked.connect(self.load_config)
        # button_layout.addStretch()
        # button_layout.addWidget(load_btn)
        # button_layout.addWidget(save_btn)
        # main_layout.addLayout(button_layout)



    def show_device_setup_dialog(self):
        dialog = DeviceSetupDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            config = dialog.get_configuration()
            proto = config['protocol']
            dev = config['device']
            noz = config['nozzle']
            pumps = config['pumps']
            
            command = f"protocol_config {proto} {dev} {noz} " + ' '.join(map(str, pumps)) + "\n"
            try:
                if self.serial_thread and self.serial_thread.running:
                    self.serial_thread.send_command(command)
                    QMessageBox.information(self, "Success", f"Configuration sent for {proto} protocol")
                else:
                    QMessageBox.warning(self, "Error", "Serial connection not established")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to send configuration: {str(e)}")
            self.add_to_command_history(command.strip())
            self.update_command_history_display()
    
    def sendConfig(self):
        proto = self.protocol_combo.currentText()
        if proto not in ["tatsuno", "gilbarco", "redstar", "haungyang"]:
            QMessageBox.warning(self, "Error", "Unsupported protocol selected")
            return
        
        dev = self.devSpin.value()
        noz = self.nozSpin.value()
        pumps = [spin.value() for spin in self.pumpSpins]
        command = f"protocol_config {proto} {dev} {noz} " + ' '.join(map(str, pumps)) + "\n"
        try:
            if self.serial_thread and self.serial_thread.running:
                self.serial_thread.send_command(command)
                QMessageBox.information(self, "Success", f"Configuration sent for {proto} protocol")
            else:
                QMessageBox.warning(self, "Error", "Serial connection not established")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to send configuration: {str(e)}")
        self.add_to_command_history(command.strip())
        self.update_command_history_display()
    
    def update_device_buttons(self):
        has_selection = len(self.device_table.selectedItems()) > 0
        self.open_dashboard_button.setEnabled(has_selection)
    
    def start_discovery(self):
        self.device_table.setRowCount(0)
        self.discovered_devices = {}
        
        # Add "Searching..." row
        row = self.device_table.rowCount()
        self.device_table.insertRow(row)
        searching_item = QTableWidgetItem("Searching for devices...")
        self.device_table.setSpan(row, 0, 1, 6)  # Span across all columns
        self.device_table.setItem(row, 0, searching_item)
        
        threading.Thread(target=self._discover_devices, daemon=True).start()
    
    def _discover_devices(self):
        zeroconf = Zeroconf()
        listener = OTADiscoveryListener(self.add_discovered_device)
        ServiceBrowser(zeroconf, "_http._tcp.local.", listener)
        
        threading.Event().wait(5)
        zeroconf.close()
        
        if self.device_table.rowCount() == 1 and self.device_table.item(0, 0).text() == "Searching for devices...":
            self.device_table.setRowCount(0)
            row = self.device_table.rowCount()
            self.device_table.insertRow(row)
            no_devices_item = QTableWidgetItem("No devices found")
            self.device_table.setSpan(row, 0, 1, 6)  # Span across all columns
            self.device_table.setItem(row, 0, no_devices_item)

    def add_discovered_device(self, device):
        ip = device["ip"]
        if ip in self.discovered_devices:
            return
        
        self.discovered_devices[ip] = device
        
        # Clear "Searching..." message if it exists
        if self.device_table.rowCount() == 1 and self.device_table.item(0, 0).text() in ["Searching for devices...", "No devices found"]:
            self.device_table.setRowCount(0)
        
        row = self.device_table.rowCount()
        self.device_table.insertRow(row)
        
        # Signal strength with icon
        signal_icon = self.get_signal_icon(device['rssi'])
        signal_item = QTableWidgetItem(signal_icon)
        signal_item.setToolTip(f"Signal Strength: {device['rssi']} dBm")
        
        # Create items for each column
        name_item = QTableWidgetItem(device['name'])
        ip_item = QTableWidgetItem(ip)
        mac_item = QTableWidgetItem(device.get('mac', 'N/A'))  # Add MAC if available
        version_item = QTableWidgetItem(device['version'])
        uptime_item = QTableWidgetItem(str(device['uptime']))
        
        # Store IP in the first column's item for reference
        signal_item.setData(Qt.UserRole, ip)
        
        # Add items to table
        self.device_table.setItem(row, 0, signal_item)
        self.device_table.setItem(row, 1, name_item)
        self.device_table.setItem(row, 2, ip_item)
        self.device_table.setItem(row, 3, mac_item)
        self.device_table.setItem(row, 4, version_item)
        self.device_table.setItem(row, 5, uptime_item)

    def open_selected_device_dashboard(self):
        selected_rows = self.device_table.selectedItems()
        if not selected_rows:
            return
        
        # Get IP from the first column's UserRole data
        ip = self.device_table.item(selected_rows[0].row(), 0).data(Qt.UserRole)
        if ip:
            webbrowser.open(f"http://{ip}/dashboard")
    
    def connect_to_selected_device(self):
        selected_items = self.device_table.selectedItems()
        if not selected_items:
            return
        
        ip = selected_items[0].data(Qt.UserRole)
        if not ip:
            return
        
        device_name = selected_items[0].text().split(' (')[0]
        ports = [port.device for port in serial.tools.list_ports.comports()]
        matching_ports = [p for p in ports if device_name.lower() in p.lower()]
        
        if matching_ports:
            self.port_combo.setCurrentText(matching_ports[0])
            self.connect_serial()
        else:
            QMessageBox.information(self, "No Serial Port Found", 
                                  f"Could not automatically find a serial port for {device_name}. "
                                  "Please select the correct port manually.")
    
    def eventFilter(self, obj, event):
        if obj is self.custom_command_input and event.type() == event.KeyPress:
            if event.key() == Qt.Key_Up:
                self.navigate_command_history(-1)
                return True
            elif event.key() == Qt.Key_Down:
                self.navigate_command_history(1)
                return True
        return super().eventFilter(obj, event)
    
    def navigate_command_history(self, direction):
        if not self.command_history:
            return
        
        self.command_history_index += direction
        
        if self.command_history_index < 0:
            self.command_history_index = 0
        elif self.command_history_index >= len(self.command_history):
            self.command_history_index = len(self.command_history) - 1
        
        self.custom_command_input.setText(self.command_history[self.command_history_index])
        self.custom_command_input.setCursorPosition(len(self.custom_command_input.text()))
    
    def add_to_command_history(self, command):
        if not command or (self.command_history and self.command_history[0] == command):
            return
        
        self.command_history.insert(0, command)
        
        if len(self.command_history) > 50:
            self.command_history = self.command_history[:50]
        
        self.command_history_index = -1
        self.update_command_history_display()
    
    def update_command_history_display(self):
        self.history_list.setRowCount(0)
        
        for i, command in enumerate(self.command_history):
            row = self.history_list.rowCount()
            self.history_list.insertRow(row)
            
            command_item = QTableWidgetItem(command)
            time_item = QTableWidgetItem(datetime.now().strftime("%H:%M:%S"))
            
            self.history_list.setItem(row, 0, command_item)
            self.history_list.setItem(row, 1, time_item)
    
    def use_history_command(self, item):
        row = item.row()
        if 0 <= row < len(self.command_history):
            command = self.command_history[row]
            self.custom_command_input.setText(command)
            self.custom_command_input.setFocus()
    
    def clear_command_history(self):
        self.command_history = []
        self.command_history_index = -1
        self.history_list.setRowCount(0)
    
    def load_settings(self):
        last_port = self.settings.value("last_port", "")
        last_baud = self.settings.value("last_baud", "115200")
        
        if last_baud:
            index = self.baud_combo.findText(last_baud)
            if index >= 0:
                self.baud_combo.setCurrentIndex(index)
    
    def save_settings(self):
        self.settings.setValue("last_port", self.port_combo.currentText())
        self.settings.setValue("last_baud", self.baud_combo.currentText())
    
    def refresh_ports(self):
        current_port = self.port_combo.currentText()
        self.port_combo.clear()
        
        ports = [port.device for port in serial.tools.list_ports.comports()]
        for port in ports:
            self.port_combo.addItem(port)
        
        if current_port:
            index = self.port_combo.findText(current_port)
            if index >= 0:
                self.port_combo.setCurrentIndex(index)
        
        if self.port_combo.currentText() == "" and ports:
            last_port = self.settings.value("last_port", "")
            index = self.port_combo.findText(last_port)
            if index >= 0:
                self.port_combo.setCurrentIndex(index)
            else:
                self.port_combo.setCurrentIndex(0)
    
    def toggle_connection(self):
        if self.serial_thread and self.serial_thread.running:
            self.disconnect_serial()
        else:
            self.connect_serial()
    
    def connect_serial(self):
        port = self.port_combo.currentText()
        baud_rate = int(self.baud_combo.currentText())
        
        if not port:
            QMessageBox.warning(self, "Connection Error", "No serial port selected")
            return
        
        self.serial_thread = SerialReaderThread(port, baud_rate)
        self.serial_thread.log_received.connect(self.process_log)
        self.serial_thread.connection_error.connect(self.handle_connection_error)
        self.serial_thread.start()
        
        self.connect_button.setText("Disconnect")
        self.statusBar().showMessage(f"Connected to {port} at {baud_rate} baud")
        self.save_settings()
    
    def disconnect_serial(self):
        if self.serial_thread:
            self.serial_thread.stop()
            self.serial_thread = None
        
        self.connect_button.setText("Connect")
        self.statusBar().showMessage("Disconnected")
    
    def handle_connection_error(self, error_message):
        self.disconnect_serial()
        QMessageBox.critical(self, "Connection Error", error_message)
    
    def process_log(self, log_line):
        log_entry = LogParser.parse_log_line(log_line)
        self.logs.append(log_entry)
        
        if "Login successful" in log_line:
            self.is_authenticated = True
            self.statusBar().showMessage("Authenticated")
        elif "Invalid password" in log_line:
            self.is_authenticated = False
            self.statusBar().showMessage("Authentication failed")
        
        # Check for WiFi status response
        try:
            data = json.loads(log_line)
            if "ssid" in data and "ip" in data:
                self.show_wifi_status_dialog(data)
        except json.JSONDecodeError:
            pass
        
        if len(self.logs) > self.max_logs:
            self.logs = self.logs[-self.max_logs:]
        
        self.add_log_to_all_logs_table(log_entry)
        
        # Update command response
        # self.command_response.append(log_line)
        
        # Scroll to the bottom of the command response
        # self.command_response.verticalScrollBar().setValue(self.command_response.verticalScrollBar().maximum())
        
    def should_display_log(self, log_entry):
        if LOG_LEVELS.get(log_entry.level, 6) > LOG_LEVELS.get(self.current_filter_level, 2):
            return False
        
        if self.filter_text and self.filter_text.lower() not in log_entry.raw.lower():
            return False
        
        return True
    
    def show_log_details(self):
        selected_rows = self.log_table.selectedItems()
        if not selected_rows:
            return
        
        row = selected_rows[0].row()
        if 0 <= row < len(self.logs):
            log_entry = self.logs[row]
            self.log_details.setText(log_entry.raw)
    
    def set_log_level(self, level):
        self.current_filter_level = level
        # self.refresh_log_display()
    
    def set_filter_text(self, text):
        self.filter_text = text
        self.refresh_log_display()
    
    def toggle_auto_scroll(self, state):
        self.auto_scroll = state == Qt.Checked
    
    def refresh_log_display(self):
        # self.log_table.setRowCount(0)
        for log_entry in self.logs:
            if self.should_display_log(log_entry):
                self.add_log_to_table(log_entry)
    
    def clear_logs(self):
        self.logs = []
        # self.log_table.setRowCount(0)
        self.all_logs_table.setRowCount(0)
        self.log_details.clear()
        self.all_logs_details.clear()
    
    def save_logs(self):
        if not self.logs:
            QMessageBox.information(self, "Save Logs", "No logs to save")
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save Logs", "", "Text Files (*.txt);;CSV Files (*.csv);;All Files (*)"
        )
        
        if not filename:
            return
        
        try:
            with open(filename, 'w') as f:
                if filename.endswith('.csv'):
                    f.write("Timestamp,Level,Message\n")
                    for log in self.logs:
                        f.write(f'"{log.timestamp}","{log.level}","{log.message}"\n')
                else:
                    for log in self.logs:
                        f.write(f"{log.raw}\n")
            
            QMessageBox.information(self, "Save Logs", f"Logs saved to {filename}")
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save logs: {str(e)}")    
    
    def show_command_dialog(self):
        dialog = CommandDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            command = dialog.get_command()
            if command:
                self.send_cli_command(command)
    
    def show_mqtt_dialog(self):
        dialog = MQTTConfigDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            host, port= dialog.get_values()
            if host and port:
                command = f'mqtt_config "{host}" "{port}" '
                self.send_cli_command(command)

    def show_about_dialog(self):
        about_text = (
            "<h2>Ultm FMS Setup Tool</h2>"
            "<p>Version 0.1</p>"
            "<p>This tool allows you to configure and manage Ultm FMS devices.</p>"
            "<p>Developed by: iih</p>"
        )
        QMessageBox.about(self, "About Ultm FMS Setup Tool", about_text)

    def send_custom_command(self):
        command = self.custom_command_input.text()
        if command:
            self.send_cli_command(command)
            self.add_to_command_history(command)
            self.custom_command_input.clear()
    
    def send_cli_command(self, command):
        if not self.serial_thread or not self.serial_thread.running:
            QMessageBox.warning(self, "Send Command", "Not connected to a serial port")
            return
        
        try:
           # self.command_response.append(f"> {command}\n")
            self.serial_thread.send_command(command)
            self.statusBar().showMessage(f"Command sent: {command}")
            # self.tabs.setCurrentIndex(1)
            self.add_to_command_history(command)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to send command: {str(e)}")
    
    def show_wifi_config_dialog(self):
        dialog = WiFiConfigDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            ssid, password = dialog.get_values()
            if ssid and password:
                self.send_cli_command(f'wifi "{ssid}" "{password}"')
    
    def show_wifi_connect_dialog(self):
        dialog = WiFiConfigDialog(self)
        dialog.setWindowTitle("WiFi Connect")
        if dialog.exec_() == QDialog.Accepted:
            ssid, password = dialog.get_values()
            if ssid and password:
                self.send_cli_command(f'wifi_connect "{ssid}" "{password}"')
    
    def show_uuid_dialog(self):
        dialog = UUIDChangeDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            uuid = dialog.get_value()
            if uuid:
                self.send_cli_command(f'uuid_change "{uuid}"')
    
    def show_login_dialog(self):
        dialog = LoginDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            password = dialog.get_password()
            if password:
                self.send_cli_command(f'login {password}')

    def confirm_restart(self):
        reply = QMessageBox.question(
            self, "Confirm Restart", 
            "Are you sure you want to restart the system?",
            QMessageBox.Yes | QMessageBox.No, 
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.send_cli_command("restart")
    
    def toggle_all_logs_auto_scroll(self, state):
        self.all_logs_auto_scroll = state == Qt.Checked
    
    def show_all_logs_details(self):
        selected_rows = self.all_logs_table.selectedItems()
      

        if not selected_rows:
            return
      
        row = selected_rows[0].row()
        if 0 <= row < len(self.logs):
            log_entry = self.logs[row]
            self.all_logs_details.setText(log_entry.raw)

    def clear_all_logs(self):
        self.logs = []
        self.all_logs_table.setRowCount(0)
    
    def save_all_logs(self):
        if not self.logs:
            QMessageBox.information(self, "Save Logs", "No logs to save")
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save All Logs", "", "Text Files (*.txt);;CSV Files (*.csv);;All Files (*)"
        )
        
        if not filename:
            return
        
        try:
            with open(filename, 'w') as f:
                if filename.endswith('.csv'):
                    f.write("Timestamp,Level,Message\n")
                    for log in self.logs:
                        f.write(f'"{log.timestamp}","{log.level}","{log.message}"\n')
                else:
                    for log in self.logs:
                        f.write(f"{log.raw}\n")
            
            QMessageBox.information(self, "Save Logs", f"All logs saved to {filename}")
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save logs: {str(e)}")

    def add_log_to_all_logs_table(self, log_entry):
        row = self.all_logs_table.rowCount()
        self.all_logs_table.insertRow(row)
        
        timestamp_item = QTableWidgetItem(log_entry.timestamp)
        level_item = QTableWidgetItem(log_entry.level)
        level_item.setForeground(LOG_COLORS.get(log_entry.level, QColor(0, 0, 0)))
        message_item = QTableWidgetItem(log_entry.message)
        
        self.all_logs_table.setItem(row, 0, timestamp_item)
        self.all_logs_table.setItem(row, 1, level_item)
        self.all_logs_table.setItem(row, 2, message_item)
        
        if self.all_logs_auto_scroll:
            self.all_logs_table.scrollToBottom()

    def show_wifi_status_dialog(self, wifi_data):
        msg = QMessageBox(self)
        msg.setWindowTitle("WiFi Status")
        msg.setIcon(QMessageBox.Information)
        
        # Create rich text with highlighted IP
        text = f"SSID: {wifi_data['ssid']}\n"
        text += f"Signal Strength (RSSI): {wifi_data['rssi']} dBm\n"
        text += "IP Address: <span style='background-color: yellow; font-weight: bold;'>"
        text += f"{wifi_data['ip']}</span>"
        
        msg.setText(text)
        msg.setTextFormat(Qt.RichText)
        msg.exec_()

    def get_signal_icon(self, rssi):
        """Convert RSSI value to a signal strength icon string"""
        if rssi >= -50:
            return "▂▄▆█"  # Excellent (4 bars)
        elif rssi >= -60:
            return "▂▄▆ "  # Good (3 bars)
        elif rssi >= -70:
            return "▂▄  "  # Fair (2 bars)
        elif rssi >= -80:
            return "▂   "  # Poor (1 bar)
        else:
            return "□   "  # Very poor/No signal (empty bars)

    def closeEvent(self, event):
        self.disconnect_serial()
        self.save_settings()
        event.accept()
    
   
def main():
    app = QApplication(sys.argv)
    window = FMSDebugUI()
    window.setStatusTip("copyright (c) 2023 Ultm FMS @2025 iih")
    window.setWindowTitle("Ultm FMS Debug Tool v0.1")
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
