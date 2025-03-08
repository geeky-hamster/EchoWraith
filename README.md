# 🌊 ECHOWRAITH

<div align="center">

```
═══════════════════════════════════════════════════════════════════════════
███████╗ ██████╗██╗  ██╗ ██████╗ ██╗    ██╗██████╗  █████╗ ██╗████████╗██╗  ██╗
██╔════╝██╔════╝██║  ██║██╔═══██╗██║    ██║██╔══██╗██╔══██╗██║╚══██╔══╝██║  ██║
█████╗  ██║     ███████║██║   ██║██║ █╗ ██║██████╔╝███████║██║   ██║   ███████║
██╔══╝  ██║     ██╔══██║██║   ██║██║███╗██║██╔══██╗██╔══██║██║   ██║   ██╔══██║
███████╗╚██████╗██║  ██║╚██████╔╝╚███╔███╔╝██║  ██║██║  ██║██║   ██║   ██║  ██║
╚══════╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝
═══════════════════════════════════════════════════════════════════════════
```

**[ Spectral WiFi Security Framework ]**

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.6+-green.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange.svg)](https://www.linux.org/)

</div>

> 🌊 Where Wireless Security Meets Spectral Analysis

## 🚀 Overview

EchoWraith is a sophisticated WiFi security analysis framework that combines spectral analysis with advanced security testing capabilities. Like a wraith in the electromagnetic spectrum, it silently monitors and analyzes wireless networks with unprecedented precision.

## ⚡ Features

- 🌊 **Network Scanner**: Discover networks through the ethereal waves
- 👻 **Deauthentication**: Strike like a phantom in the wireless realm
- 🔮 **WPS Analysis**: Peer into the mystical gates of WPS security
- ⚔️ **Handshake Capture**: Capture ethereal handshakes from the spectral plane
- 📡 **System Check**: Guard your realm with spectral verification
- 🛡️ **History Viewer**: Chronicle your journey through the wireless dimension

## 🛠️ Installation

### Quick Install (Recommended)
```bash
curl -sSL https://raw.githubusercontent.com/geeky-hamster/EchoWraith/main/install.sh | sudo bash
```

### Manual Installation
1. Clone the repository:
```bash
git clone https://github.com/geeky-hamster/EchoWraith.git
cd EchoWraith
```

2. Install system dependencies:
```bash
# Debian/Ubuntu based systems
sudo apt update
sudo apt install -y python3 python3-pip python3-venv aircrack-ng reaver

# Arch based systems
sudo pacman -Sy python python-pip python-virtualenv aircrack-ng reaver

# Fedora/RHEL based systems
sudo dnf install -y python3 python3-pip python3-virtualenv aircrack-ng reaver
```

3. Set up virtual environment (recommended):
```bash
python3 -m venv venv
source venv/bin/activate
```

4. Install Python dependencies:
```bash
pip install -r requirements.txt
# Or install core dependencies only
pip install rich>=13.7.0 scapy>=2.5.0 netifaces>=0.11.0 cryptography>=41.0.0 pyroute2>=0.7.9 netaddr>=0.8.0 prompt_toolkit>=3.0.43 pycryptodomex>=3.19.0
```

5. Make it executable:
```bash
sudo chmod +x echowraith.py
sudo ln -s $(pwd)/echowraith.py /usr/local/bin/echowraith
```

## 🎮 Usage

1. Start EchoWraith:
```bash
sudo echowraith
```

2. Select a module:
- `1` - System Check
- `2` - Network Scanner
- `3` - Deauthentication
- `4` - WPS Analysis
- `5` - Handshake Capture
- `6` - History Viewer
- `7` - Clean Workspace

## 🎯 Requirements

### System Requirements
- Linux-based operating system
- Python 3.6+
- Root privileges
- Compatible wireless adapter supporting monitor mode

### System Dependencies
- python3
- python3-pip
- python3-venv
- aircrack-ng (wireless security auditing)
- reaver (WPS security assessment)

### Python Dependencies
- rich (>=13.7.0) - Terminal UI framework
- scapy (>=2.5.0) - Network packet manipulation
- netifaces (>=0.11.0) - Network interface handling
- cryptography (>=41.0.0) - Security operations
- pyroute2 (>=0.7.9) - Network configuration
- netaddr (>=0.8.0) - Network address manipulation
- prompt_toolkit (>=3.0.43) - Interactive CLI
- pycryptodomex (>=3.19.0) - Cryptographic functions
- rf-security-toolkit (>=1.2.0) - RF security tools
- wireless-framework (>=2.1.0) - Wireless networking framework
- network-proto-analyzer (>=1.0.3) - Protocol analysis

## 🛡️ Disclaimer

This framework is designed for authorized security testing only. Always obtain proper permission before testing any networks you don't own.

## 🤝 Contributing

Contributions are welcome! Feel free to:
- 🌊 Report anomalies
- 💫 Suggest enhancements
- ⚡ Submit improvements

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🌟 Credits

Created with 🌊 by the EchoWraith Team

---
*"In the realm of wireless, we are the silent guardians."* 👻 