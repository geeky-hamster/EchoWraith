#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Installation directory
INSTALL_DIR="/opt/echowraith"
VENV_DIR="$INSTALL_DIR/venv"

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
if command -v apt-get &> /dev/null; then
    PKG_MANAGER="apt-get"
elif command -v pacman &> /dev/null; then
    PKG_MANAGER="pacman"
elif command -v dnf &> /dev/null; then
    PKG_MANAGER="dnf"
else
    echo -e "${RED}Unsupported package manager${NC}"
    exit 1
fi

echo -e "${GREEN}Detected package manager: ${BLUE}$PKG_MANAGER${NC}"

# Update package manager
echo -e "${YELLOW}Updating package manager...${NC}"
if [ "$PKG_MANAGER" = "apt-get" ]; then
    apt-get update
elif [ "$PKG_MANAGER" = "pacman" ]; then
    pacman -Sy
elif [ "$PKG_MANAGER" = "dnf" ]; then
    dnf check-update
fi

# Install required packages
echo -e "${YELLOW}Installing required packages...${NC}"
if [ "$PKG_MANAGER" = "apt-get" ]; then
    apt-get install -y python3 python3-pip python3-venv aircrack-ng reaver
elif [ "$PKG_MANAGER" = "pacman" ]; then
    pacman -S --noconfirm python python-pip python-virtualenv aircrack-ng reaver
elif [ "$PKG_MANAGER" = "dnf" ]; then
    dnf install -y python3 python3-pip python3-virtualenv aircrack-ng reaver
fi

# Create installation directory
mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/modules"
mkdir -p "$INSTALL_DIR/data"

# Download and extract files
echo -e "${YELLOW}Downloading EchoWraith...${NC}"
curl -L https://github.com/geeky-hamster/EchoWraith/archive/main.tar.gz -o /tmp/echowraith.tar.gz
tar xzf /tmp/echowraith.tar.gz -C /tmp/

# Copy files to installation directory
echo -e "${YELLOW}Installing files...${NC}"
cp -r /tmp/EchoWraith-main/* "$INSTALL_DIR/"
cp -r /tmp/EchoWraith-main/modules/* "$INSTALL_DIR/modules/"

# Create Python virtual environment
echo -e "${YELLOW}Setting up Python virtual environment...${NC}"
python3 -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"

# Install Python dependencies
echo -e "${YELLOW}Installing Python dependencies...${NC}"
"$VENV_DIR/bin/pip" install --upgrade pip
"$VENV_DIR/bin/pip" install -r "$INSTALL_DIR/requirements.txt"

# Create executable
echo -e "${YELLOW}Creating executable...${NC}"
cat > /usr/local/bin/echowraith << 'EOF'
#!/bin/bash
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi
source /opt/echowraith/venv/bin/activate
python3 /opt/echowraith/echowraith.py "$@"
EOF

chmod +x /usr/local/bin/echowraith

# Clean up
echo -e "${YELLOW}Cleaning up...${NC}"
rm -rf /tmp/echowraith.tar.gz /tmp/EchoWraith-main

# Create data directories
echo -e "${YELLOW}Creating data directories...${NC}"
mkdir -p "$INSTALL_DIR/data/"{handshakes,passwords,logs,scans,wps,deauth,temp,configs}
chmod -R 755 "$INSTALL_DIR"

echo -e "${GREEN}Installation complete!${NC}"
echo -e "${YELLOW}You can now run EchoWraith by typing: ${GREEN}sudo echowraith${NC}"
echo -e "${BLUE}Installation directory: ${GREEN}$INSTALL_DIR${NC}"
echo -e "${YELLOW}Note: Make sure your wireless adapter supports monitor mode${NC}" 