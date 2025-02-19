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
mkdir -p $INSTALL_DIR/modules

# Create main application file
echo -e "${YELLOW}Creating main application file...${NC}"
cat > $INSTALL_DIR/infidelity.py << 'EOF'
#!/usr/bin/env python3

from rich.console import Console
from rich.table import Table
import os
import sys
from modules.network_scanner import NetworkScanner
from modules.handshake_capture import HandshakeCapture
from modules.wps_attack import WPSAttacker
from modules.deauth_attack import DeauthAttacker
from modules.utils import setup_workspace, cleanup_workspace, log_activity

class Infidelity:
    def __init__(self):
        self.console = Console()
        self.setup_workspace()

    def setup_workspace(self):
        """Initialize workspace directories"""
        if not setup_workspace():
            self.console.print("[red]Failed to setup workspace. Please check permissions.[/red]")
            sys.exit(1)

    def display_banner(self):
        """Display the application banner"""
        banner = """
██╗███╗   ██╗███████╗██╗██████╗ ███████╗██╗     ██╗████████╗██╗   ██╗
██║████╗  ██║██╔════╝██║██╔══██╗██╔════╝██║     ██║╚══██╔══╝╚██╗ ██╔╝
██║██╔██╗ ██║█████╗  ██║██║  ██║█████╗  ██║     ██║   ██║    ╚████╔╝ 
██║██║╚██╗██║██╔══╝  ██║██║  ██║██╔══╝  ██║     ██║   ██║     ╚██╔╝  
██║██║ ╚████║██║     ██║██████╔╝███████╗███████╗██║   ██║      ██║   
╚═╝╚═╝  ╚═══╝╚═╝     ╚═╝╚═════╝ ╚══════╝╚══════╝╚═╝   ╚═╝      ╚═╝   
        """
        self.console.print(f"[green]{banner}[/green]")
        self.console.print("\n[cyan]Advanced WiFi Security Analysis Platform[/cyan]")
        self.console.print("[yellow]Version 2.1.0[/yellow]\n")

    def display_menu(self):
        """Display the main menu"""
        table = Table(title="Available Modules")
        table.add_column("Option", style="cyan", justify="right")
        table.add_column("Module", style="green")
        table.add_column("Description", style="yellow")

        table.add_row("1", "Network Scanner", "Discover and analyze nearby networks")
        table.add_row("2", "Deauthentication", "Advanced client management")
        table.add_row("3", "WPS Analysis", "Test WPS security implementations")
        table.add_row("4", "Handshake Capture", "Capture and analyze handshakes")
        table.add_row("5", "View History", "View previous session data")
        table.add_row("6", "Clean Workspace", "Remove temporary files")
        table.add_row("7", "Exit", "Exit Infidelity")

        self.console.print(table)

    def run(self):
        """Main application loop"""
        if os.geteuid() != 0:
            self.console.print("[red]Please run Infidelity with root privileges[/red]")
            sys.exit(1)

        self.display_banner()
        
        while True:
            try:
                self.display_menu()
                choice = input("\nSelect an option: ")

                if choice == "1":
                    scanner = NetworkScanner()
                    scanner.start_scan()
                elif choice == "2":
                    deauth = DeauthAttacker()
                    deauth.start_attack()
                elif choice == "3":
                    wps = WPSAttacker()
                    wps.start_attack()
                elif choice == "4":
                    handshake = HandshakeCapture()
                    handshake.start_capture()
                elif choice == "5":
                    self.view_history()
                elif choice == "6":
                    cleanup_workspace()
                    self.console.print("[green]Workspace cleaned successfully![/green]")
                elif choice == "7":
                    self.console.print("[yellow]Exiting Infidelity...[/yellow]")
                    break
                else:
                    self.console.print("[red]Invalid option. Please try again.[/red]")

            except KeyboardInterrupt:
                self.console.print("\n[yellow]Operation cancelled by user[/yellow]")
            except Exception as e:
                self.console.print(f"[red]Error: {str(e)}[/red]")

    def view_history(self):
        """View session history and captured data"""
        # Implementation for viewing history
        pass

if __name__ == "__main__":
    app = Infidelity()
    app.run()
EOF

# Create modules directory and files
echo -e "${YELLOW}Creating module files...${NC}"

# Create __init__.py for modules directory
touch $INSTALL_DIR/modules/__init__.py

# Create network_scanner.py
cat > $INSTALL_DIR/modules/network_scanner.py << 'EOF'
#!/usr/bin/env python3

from rich.console import Console
from rich.table import Table
import subprocess
import os

class NetworkScanner:
    def __init__(self):
        self.console = Console()

    def start_scan(self):
        self.console.print("[cyan]Starting network scan...[/cyan]")
        self.console.print("[yellow]This feature will be implemented in the next update.[/yellow]")
EOF

# Create handshake_capture.py
cat > $INSTALL_DIR/modules/handshake_capture.py << 'EOF'
#!/usr/bin/env python3

from rich.console import Console

class HandshakeCapture:
    def __init__(self):
        self.console = Console()

    def start_capture(self):
        self.console.print("[cyan]Starting handshake capture...[/cyan]")
        self.console.print("[yellow]This feature will be implemented in the next update.[/yellow]")
EOF

# Create wps_attack.py
cat > $INSTALL_DIR/modules/wps_attack.py << 'EOF'
#!/usr/bin/env python3

from rich.console import Console

class WPSAttacker:
    def __init__(self):
        self.console = Console()

    def start_attack(self):
        self.console.print("[cyan]Starting WPS analysis...[/cyan]")
        self.console.print("[yellow]This feature will be implemented in the next update.[/yellow]")
EOF

# Create deauth_attack.py
cat > $INSTALL_DIR/modules/deauth_attack.py << 'EOF'
#!/usr/bin/env python3

from rich.console import Console

class DeauthAttacker:
    def __init__(self):
        self.console = Console()

    def start_attack(self):
        self.console.print("[cyan]Starting deauthentication...[/cyan]")
        self.console.print("[yellow]This feature will be implemented in the next update.[/yellow]")
EOF

# Make all module files executable
chmod +x $INSTALL_DIR/modules/*.py

# Create utils.py
cat > $INSTALL_DIR/modules/utils.py << 'EOF'
#!/usr/bin/env python3

from rich.console import Console
import os
import shutil
from datetime import datetime

console = Console()

def setup_workspace():
    """Setup workspace directories"""
    try:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        data_dir = os.path.join(base_dir, 'data')
        
        directories = {
            'handshakes': os.path.join(data_dir, 'handshakes'),
            'passwords': os.path.join(data_dir, 'passwords'),
            'logs': os.path.join(data_dir, 'logs'),
            'scans': os.path.join(data_dir, 'scans'),
            'wps': os.path.join(data_dir, 'wps'),
            'deauth': os.path.join(data_dir, 'deauth'),
            'temp': os.path.join(data_dir, 'temp'),
            'configs': os.path.join(data_dir, 'configs')
        }
        
        for dir_path in directories.values():
            os.makedirs(dir_path, exist_ok=True)
            
        return directories
    except Exception as e:
        console.print(f"[red]Error setting up workspace: {str(e)}[/red]")
        return None

def cleanup_workspace(keep_logs=False):
    """Clean up workspace files"""
    try:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        data_dir = os.path.join(base_dir, 'data')
        
        if os.path.exists(data_dir):
            for subdir in ['handshakes', 'passwords', 'scans', 'wps', 'temp']:
                dir_path = os.path.join(data_dir, subdir)
                if os.path.exists(dir_path):
                    shutil.rmtree(dir_path)
                    os.makedirs(dir_path)
            
        console.print("[green]Workspace cleaned successfully![/green]")
    except Exception as e:
        console.print(f"[red]Error cleaning workspace: {str(e)}[/red]")

def log_activity(message):
    """Log activity with timestamp"""
    try:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        log_file = os.path.join(base_dir, 'data', 'logs', 'activity.log')
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(log_file, 'a') as f:
            f.write(f"[{timestamp}] {message}\n")
    except Exception as e:
        console.print(f"[red]Error logging activity: {str(e)}[/red]")
EOF

chmod +x $INSTALL_DIR/infidelity.py
chmod +x $INSTALL_DIR/modules/utils.py

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