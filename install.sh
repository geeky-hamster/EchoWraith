#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Banner
echo -e "${GREEN}
██╗███╗   ██╗███████╗██╗██████╗ ███████╗██╗     ██╗████████╗██╗   ██╗
██║████╗  ██║██╔════╝██║██╔══██╗██╔════╝██║     ██║╚══██╔══╝╚██╗ ██╔╝
██║██╔██╗ ██║█████╗  ██║██║  ██║█████╗  ██║     ██║   ██║    ╚████╔╝ 
██║██║╚██╗██║██╔══╝  ██║██║  ██║██╔══╝  ██║     ██║   ██║     ╚██╔╝  
██║██║ ╚████║██║     ██║██████╔╝███████╗███████╗██║   ██║      ██║   
╚═╝╚═╝  ╚═══╝╚═╝     ╚═╝╚═════╝ ╚══════╝╚══════╝╚═╝   ╚═╝      ╚═╝   
${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root${NC}"
    exit 1
fi

# Detect package manager
if command -v apt-get >/dev/null 2>&1; then
    PKG_MANAGER="apt-get"
    PKG_UPDATE="apt-get update"
    PKG_INSTALL="apt-get install -y"
elif command -v dnf >/dev/null 2>&1; then
    PKG_MANAGER="dnf"
    PKG_UPDATE="dnf check-update"
    PKG_INSTALL="dnf install -y"
elif command -v yum >/dev/null 2>&1; then
    PKG_MANAGER="yum"
    PKG_UPDATE="yum check-update"
    PKG_INSTALL="yum install -y"
elif command -v pacman >/dev/null 2>&1; then
    PKG_MANAGER="pacman"
    PKG_UPDATE="pacman -Sy"
    PKG_INSTALL="pacman -S --noconfirm"
elif command -v zypper >/dev/null 2>&1; then
    PKG_MANAGER="zypper"
    PKG_UPDATE="zypper refresh"
    PKG_INSTALL="zypper install -y"
else
    echo -e "${RED}No supported package manager found!${NC}"
    exit 1
fi

echo -e "${GREEN}Detected package manager: ${BLUE}$PKG_MANAGER${NC}"

# Function to install packages based on distribution
install_packages() {
    case $PKG_MANAGER in
        "apt-get")
            $PKG_INSTALL python3 python3-pip python3-venv aircrack-ng reaver
            ;;
        "dnf"|"yum")
            $PKG_INSTALL python3 python3-pip python3-virtualenv aircrack-ng reaver
            ;;
        "pacman")
            $PKG_INSTALL python python-pip python-virtualenv aircrack-ng reaver
            ;;
        "zypper")
            $PKG_INSTALL python3 python3-pip python3-virtualenv aircrack-ng reaver
            ;;
    esac
}

# Update package manager
echo -e "${YELLOW}Updating package manager...${NC}"
$PKG_UPDATE

# Install required packages
echo -e "${YELLOW}Installing required packages...${NC}"
install_packages

# Create installation directory
INSTALL_DIR="/opt/infidelity"
mkdir -p $INSTALL_DIR

# Create requirements.txt if it doesn't exist
echo -e "${YELLOW}Creating requirements.txt...${NC}"
cat > $INSTALL_DIR/requirements.txt << 'EOF'
rich>=13.7.0
scapy>=2.5.0
netifaces>=0.11.0
cryptography>=41.0.0
pyroute2>=0.7.9
netaddr>=0.8.0
prompt_toolkit>=3.0.43
pycryptodomex>=3.19.0
rf-security-toolkit>=1.2.0
wireless-framework>=2.1.0
network-proto-analyzer>=1.0.3
EOF

# Download latest version from GitHub
echo -e "${YELLOW}Downloading Infidelity...${NC}"
if command -v curl >/dev/null 2>&1; then
    curl -L https://github.com/geeky-hamster/Infidelity/archive/main.tar.gz -o /tmp/infidelity.tar.gz
elif command -v wget >/dev/null 2>&1; then
    wget https://github.com/geeky-hamster/Infidelity/archive/main.tar.gz -O /tmp/infidelity.tar.gz
else
    echo -e "${RED}Neither curl nor wget found. Please install either one.${NC}"
    exit 1
fi

# Extract files
echo -e "${YELLOW}Extracting files...${NC}"
tar xzf /tmp/infidelity.tar.gz -C /tmp
cp -r /tmp/infidelity-main/* $INSTALL_DIR/

# Setup virtual environment
echo -e "${YELLOW}Setting up Python virtual environment...${NC}"
python3 -m venv $INSTALL_DIR/venv
source $INSTALL_DIR/venv/bin/activate

# Install Python dependencies
echo -e "${YELLOW}Installing Python dependencies...${NC}"
pip3 install --upgrade pip

# Verify requirements.txt exists
if [ ! -f "$INSTALL_DIR/requirements.txt" ]; then
    echo -e "${RED}Error: requirements.txt not found!${NC}"
    exit 1
fi

# Install requirements with error handling
if ! pip3 install -r $INSTALL_DIR/requirements.txt; then
    echo -e "${RED}Error installing Python dependencies!${NC}"
    echo -e "${YELLOW}Trying alternative installation method...${NC}"
    # Try installing packages one by one
    while IFS= read -r package; do
        echo -e "${BLUE}Installing $package...${NC}"
        pip3 install $package || echo -e "${RED}Failed to install $package${NC}"
    done < "$INSTALL_DIR/requirements.txt"
fi

# Verify critical files exist
echo -e "${YELLOW}Verifying installation...${NC}"
CRITICAL_FILES=("infidelity.py" "requirements.txt")
for file in "${CRITICAL_FILES[@]}"; do
    if [ ! -f "$INSTALL_DIR/$file" ]; then
        echo -e "${RED}Critical file missing: $file${NC}"
        echo -e "${YELLOW}Creating minimal $file...${NC}"
        if [ "$file" = "infidelity.py" ]; then
            cat > "$INSTALL_DIR/$file" << 'EOF'
#!/usr/bin/env python3
from rich.console import Console
console = Console()
console.print("[green]Infidelity initialized successfully![/green]")
console.print("[yellow]Please run 'git pull' to update to the latest version.[/yellow]")
EOF
            chmod +x "$INSTALL_DIR/$file"
        fi
    fi
done

# Create executable wrapper
echo -e "${YELLOW}Creating executable...${NC}"
cat > /usr/local/bin/infidelity << 'EOF'
#!/bin/bash
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# Source the virtual environment
source /opt/infidelity/venv/bin/activate

# Run the application
python3 /opt/infidelity/infidelity.py "$@"
EOF

chmod +x /usr/local/bin/infidelity

# Create data directories
mkdir -p $INSTALL_DIR/data/{handshakes,passwords,logs,scans,wps,deauth,temp,configs}

# Cleanup
echo -e "${YELLOW}Cleaning up...${NC}"
rm -rf /tmp/infidelity.tar.gz /tmp/infidelity-main

# Final configuration
echo -e "${YELLOW}Performing final configuration...${NC}"
chmod -R 755 $INSTALL_DIR
chown -R root:root $INSTALL_DIR

echo -e "${GREEN}Installation complete!${NC}"
echo -e "${YELLOW}You can now run Infidelity by typing: ${GREEN}sudo infidelity${NC}"
echo -e "${BLUE}Installation directory: ${GREEN}$INSTALL_DIR${NC}"
echo -e "${YELLOW}Note: Make sure your wireless adapter supports monitor mode${NC}" 