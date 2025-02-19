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
pip3 install -r $INSTALL_DIR/requirements.txt

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