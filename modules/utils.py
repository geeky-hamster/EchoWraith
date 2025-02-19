#!/usr/bin/env python3

from rich.console import Console
from rich.table import Table
from rich.progress import Progress
import subprocess
import time
import os
import shutil
from datetime import datetime

console = Console()

def setup_workspace():
    """Setup workspace directories"""
    try:
        # Get the program's directory
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        data_dir = os.path.join(base_dir, 'data')
        
        # Create main data directory and subdirectories
        directories = {
            'handshakes': os.path.join(data_dir, 'handshakes'),
            'passwords': os.path.join(data_dir, 'passwords'),
            'logs': os.path.join(data_dir, 'logs'),
            'scans': os.path.join(data_dir, 'scans'),
            'wps': os.path.join(data_dir, 'wps'),
            'deauth': os.path.join(data_dir, 'deauth'),
            'temp': os.path.join(data_dir, 'temp'),  # For temporary files
            'configs': os.path.join(data_dir, 'configs')    # For configuration files
        }
        
        for dir_name, dir_path in directories.items():
            os.makedirs(dir_path, exist_ok=True)
            
        return directories
    except Exception as e:
        console.print(f"[red]Error setting up workspace: {str(e)}[/red]")
        return None

def cleanup_workspace(keep_logs=False):
    """Clean up all created files and directories"""
    try:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        data_dir = os.path.join(base_dir, 'data')
        
        if os.path.exists(data_dir):
            if keep_logs:
                # If keeping logs, only remove contents of other directories
                for subdir in ['handshakes', 'passwords', 'scans', 'wps']:
                    dir_path = os.path.join(data_dir, subdir)
                    if os.path.exists(dir_path):
                        shutil.rmtree(dir_path)
                        os.makedirs(dir_path)
            else:
                # Remove entire data directory
                shutil.rmtree(data_dir)
            
            console.print("[green]Workspace cleaned successfully![/green]")
        else:
            console.print("[yellow]No data directory found to clean.[/yellow]")
            
    except Exception as e:
        console.print(f"[red]Error cleaning workspace: {str(e)}[/red]")

def get_data_path(module_name, filename):
    """Get the full path for a file in the data directory"""
    try:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        data_dir = os.path.join(base_dir, 'data', module_name)
        return os.path.join(data_dir, filename)
    except Exception as e:
        console.print(f"[red]Error getting data path: {str(e)}[/red]")
        return None

def log_activity(message):
    """Log activity with timestamp"""
    try:
        log_file = get_data_path('logs', 'activity.log')
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(log_file, 'a') as f:
            f.write(f"[{timestamp}] {message}\n")
    except Exception as e:
        console.print(f"[red]Error logging activity: {str(e)}[/red]")

def scan_networks(interface):
    """Common network scanning functionality for all modules"""
    try:
        networks = []
        scan_file = get_data_path('scans', f'scan_{int(time.time())}')
        
        # Start airodump-ng scan
        scan_process = subprocess.Popen(
            ['airodump-ng', '--output-format', 'csv', '-w', scan_file, interface],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        
        # Show progress while scanning
        with Progress() as progress:
            task = progress.add_task("[cyan]Scanning for networks...", total=100)
            
            for i in range(10):  # Scan for 10 seconds
                progress.update(task, advance=10)
                time.sleep(1)
            
            scan_process.terminate()
            time.sleep(1)
        
        # Parse scan results
        try:
            with open(f"{scan_file}-01.csv", 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            for line in lines[2:]:  # Skip headers
                if line.strip() and ',' in line:
                    parts = line.strip().split(',')
                    if len(parts) >= 14:  # Valid network line
                        bssid = parts[0].strip()
                        if bssid and ':' in bssid:  # Valid BSSID
                            networks.append({
                                'BSSID': bssid,
                                'Channel': parts[3].strip(),
                                'ESSID': parts[13].strip().rstrip('\x00'),
                                'Encryption': parts[5].strip(),
                                'Clients': []
                            })
            
            # Get connected clients
            client_section = False
            for line in lines:
                if 'Station MAC' in line:
                    client_section = True
                    continue
                if client_section and line.strip() and ',' in line:
                    parts = line.strip().split(',')
                    if len(parts) >= 6:
                        client_mac = parts[0].strip()
                        ap_mac = parts[5].strip()
                        for network in networks:
                            if network['BSSID'] == ap_mac:
                                network['Clients'].append(client_mac)
            
        except FileNotFoundError:
            console.print("[red]Error: Scan output file not found.[/red]")
        finally:
            # Cleanup temporary files
            os.system(f"rm -f {scan_file}*")
        
        return networks
        
    except Exception as e:
        console.print(f"[red]Error during scan: {str(e)}[/red]")
        return []

def display_networks(networks):
    """Display networks in a standardized format"""
    if not networks:
        console.print("[red]No networks found![/red]")
        return False

    # Display networks
    table = Table(title="Discovered Networks")
    table.add_column("Index", style="cyan", justify="center")
    table.add_column("BSSID", style="green")
    table.add_column("Channel", justify="center")
    table.add_column("ESSID", style="yellow")
    table.add_column("Encryption", style="red")
    table.add_column("Clients", justify="center")

    for idx, network in enumerate(networks, 1):
        table.add_row(
            str(idx),
            network['BSSID'],
            network['Channel'],
            network['ESSID'] or "Hidden Network",
            network['Encryption'],
            str(len(network['Clients']))
        )

    console.print(table)
    return True

def select_target(networks):
    """Common target selection functionality"""
    if not display_networks(networks):
        return None, None, None, []

    while True:
        try:
            choice = int(input("\nSelect target network number: ")) - 1
            if 0 <= choice < len(networks):
                target = networks[choice]
                return (
                    target['BSSID'],
                    target['Channel'],
                    target['ESSID'],
                    target['Clients']
                )
        except ValueError:
            pass
        console.print("[red]Invalid choice. Please try again.[/red]")

    return None, None, None, []

def setup_monitor_mode(interface):
    """Setup monitor mode with improved reliability"""
    try:
        # Kill interfering processes
        subprocess.run(['airmon-ng', 'check', 'kill'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)

        # Check if already in monitor mode
        if 'mon' in interface:
            return interface

        # Try multiple methods to enable monitor mode
        methods = [
            ['airmon-ng', 'start', interface],
            ['iw', 'dev', interface, 'set', 'monitor', 'none'],
            ['iwconfig', interface, 'mode', 'monitor']
        ]

        for method in methods:
            try:
                subprocess.run(method, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                time.sleep(2)
                
                # Verify monitor mode
                result = subprocess.run(['iwconfig', interface], capture_output=True, text=True)
                if 'Mode:Monitor' in result.stdout:
                    return interface
            except:
                continue

        # If all methods failed, try with mon suffix
        mon_interface = interface + 'mon'
        if os.path.exists(f'/sys/class/net/{mon_interface}'):
            return mon_interface

        console.print("[red]Failed to enable monitor mode.[/red]")
        return None

    except Exception as e:
        console.print(f"[red]Error setting up monitor mode: {str(e)}[/red]")
        return None

def get_interface():
    """Get available wireless interfaces with improved detection"""
    try:
        interfaces = []
        
        # Method 1: Using iwconfig
        result = subprocess.run(['iwconfig'], capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if 'IEEE 802.11' in line:
                interface = line.split()[0]
                interfaces.append(interface)
        
        # Method 2: Check /sys/class/net for wireless devices
        if not interfaces:
            for iface in os.listdir('/sys/class/net'):
                if os.path.exists(f'/sys/class/net/{iface}/wireless'):
                    interfaces.append(iface)
        
        if not interfaces:
            console.print("[red]No wireless interfaces found![/red]")
            return None
        
        # Create selection table
        table = Table(title="Available Wireless Interfaces")
        table.add_column("Option", style="cyan", justify="right")
        table.add_column("Interface", style="green")
        
        for i, interface in enumerate(interfaces, 1):
            table.add_row(str(i), interface)
        
        console.print(table)
        
        while True:
            try:
                choice = int(input("\nSelect interface: "))
                if 1 <= choice <= len(interfaces):
                    return interfaces[choice-1]
                else:
                    console.print("[red]Invalid choice. Please try again.[/red]")
            except ValueError:
                console.print("[red]Invalid input. Please enter a number.[/red]")
        
    except Exception as e:
        console.print(f"[red]Error getting wireless interfaces: {str(e)}[/red]")
        return None

def check_wireless_tools():
    """Check if required wireless tools are available"""
    required_tools = ['iwconfig', 'airmon-ng', 'airodump-ng', 'aireplay-ng']
    missing_tools = []
    
    for tool in required_tools:
        try:
            subprocess.run([tool, '--help'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            missing_tools.append(tool)
    
    if missing_tools:
        console.print(f"[red]Missing required tools: {', '.join(missing_tools)}[/red]")
        console.print("[yellow]Please install aircrack-ng and wireless-tools packages.[/yellow]")
        return False
    
    return True

def get_temp_path(filename):
    """Get path for temporary files in the data directory"""
    return get_data_path('temp', filename)

def get_config_path(filename):
    """Get path for configuration files in the data directory"""
    return get_data_path('configs', filename)

def get_web_path(filename):
    """Get path for web server files in the data directory"""
    return get_data_path('web', filename)

def get_capture_path(filename):
    """Get path for packet capture files in the data directory"""
    return get_data_path('captures', filename)

def cleanup_temp_files():
    """Clean up temporary files in the data directory"""
    try:
        temp_dir = get_data_path('temp', '')
        for file in os.listdir(temp_dir):
            file_path = os.path.join(temp_dir, file)
            try:
                if os.path.isfile(file_path):
                    os.unlink(file_path)
            except Exception as e:
                console.print(f"[red]Error removing file {file_path}: {str(e)}[/red]")
    except Exception as e:
        console.print(f"[red]Error cleaning temporary files: {str(e)}[/red]") 