#!/usr/bin/env python3

from rich.console import Console
from rich.table import Table
from rich.progress import Progress
import subprocess
import time
import os
import shutil
from datetime import datetime
from .interface_manager import InterfaceManager

console = Console()

def setup_workspace():
    """Create necessary directories for the toolkit"""
    try:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        directories = {
            'data': ['handshakes', 'passwords', 'logs', 'scans', 'wps', 'deauth', 'temp', 'configs', 'wordlists']
        }
        
        for parent, subdirs in directories.items():
            parent_dir = os.path.join(base_dir, parent)
            if not os.path.exists(parent_dir):
                os.makedirs(parent_dir)
            
            for subdir in subdirs:
                dir_path = os.path.join(parent_dir, subdir)
                if not os.path.exists(dir_path):
                    os.makedirs(dir_path)
        
        return True
    except Exception as e:
        console.print(f"[red]Error setting up workspace: {str(e)}[/red]")
        return False

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
    """Log toolkit activity"""
    try:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        log_dir = os.path.join(base_dir, 'data', 'logs')
        log_file = os.path.join(log_dir, 'activity.log')
        
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        timestamp = datetime.now().strftime('[%Y-%m-%d %H:%M:%S]')
        with open(log_file, 'a') as f:
            f.write(f"{timestamp} {message}\n")
    except Exception as e:
        console.print(f"[red]Error logging activity: {str(e)}[/red]")

def scan_networks(interface=None):
    """Common network scanning functionality for all modules"""
    try:
        # Get interface if not provided
        if not interface:
            interface = InterfaceManager.get_current_interface()
            if not interface:
                console.print("[red]No wireless interface available![/red]")
                return []

        # Ensure monitor mode is enabled
        if not InterfaceManager.ensure_monitor_mode():
            console.print("[red]Failed to enable monitor mode for scanning![/red]")
            return []

        # Get the current interface again as it might have changed (e.g., wlan0 -> wlan0mon)
        interface = InterfaceManager.get_current_interface()
        networks = []
        scan_file = get_data_path('scans', f'scan_{int(time.time())}')
        
        # Start airodump-ng scan with better parameters
        scan_process = subprocess.Popen(
            [
                'airodump-ng',
                '--output-format', 'csv',
                '--write', scan_file,
                '--write-interval', '1',
                interface
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        
        # Show progress while scanning
        with Progress() as progress:
            task = progress.add_task("[cyan]Scanning for networks...", total=100)
            
            # Scan for exactly 10 seconds
            for i in range(10):
                progress.update(task, advance=10)
                time.sleep(1)
                
                # Check if we have results already
                csv_file = f"{scan_file}-01.csv"
                if os.path.exists(csv_file):
                    try:
                        with open(csv_file, 'r', encoding='utf-8') as f:
                            if len(f.readlines()) > 3:  # If we have more than header lines
                                continue  # Keep scanning for full 10 seconds
                    except:
                        pass
            
            scan_process.terminate()
            time.sleep(1)

        # Process scan results
        csv_file = f"{scan_file}-01.csv"
        if os.path.exists(csv_file):
            try:
                with open(csv_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    
                    # Process APs
                    ap_section = True
                    for line in lines[2:]:  # Skip headers
                        if not line.strip():  # Empty line indicates end of AP section
                            ap_section = False
                            continue
                            
                        if ap_section and ',' in line:
                            parts = line.strip().split(',')
                            if len(parts) >= 14:  # Valid network line
                                bssid = parts[0].strip()
                                if bssid and ':' in bssid:  # Valid BSSID
                                    networks.append({
                                        'BSSID': bssid,
                                        'Channel': parts[3].strip(),
                                        'ESSID': parts[13].strip(),
                                        'Encryption': parts[5].strip(),
                                        'Clients': []
                                    })
                    
                    # Process clients
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
                                if client_mac and ':' in client_mac and ap_mac and ':' in ap_mac:
                                    for network in networks:
                                        if network['BSSID'] == ap_mac:
                                            network['Clients'].append(client_mac)

                if not networks:
                    console.print("[yellow]No networks found during scan.[/yellow]")
            except Exception as e:
                console.print(f"[yellow]Error parsing scan results: {str(e)}[/yellow]")

        # Cleanup temporary files
        cleanup_temp_files()
        return networks

    except Exception as e:
        console.print(f"[red]Error scanning networks: {str(e)}[/red]")
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

def get_interface():
    """Get wireless interface from user"""
    try:
        # Get available interfaces
        interfaces = []
        result = subprocess.run(['iwconfig'], capture_output=True, text=True)
        
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'IEEE 802.11' in line:
                    interface = line.split()[0]
                    interfaces.append(interface)
        
        if not interfaces:
            # Try alternative method
            for iface in os.listdir('/sys/class/net'):
                if os.path.exists(f'/sys/class/net/{iface}/wireless'):
                    interfaces.append(iface)
        
        if not interfaces:
            console.print("[red]No wireless interfaces found![/red]")
            return None
        
        # If only one interface, use it
        if len(interfaces) == 1:
            console.print(f"[green]Using wireless interface: {interfaces[0]}[/green]")
            return interfaces[0]
        
        # Let user select interface
        console.print("\n[cyan]Available wireless interfaces:[/cyan]")
        for i, iface in enumerate(interfaces, 1):
            console.print(f"{i}. {iface}")
        
        while True:
            try:
                choice = int(input("\nSelect interface number: "))
                if 1 <= choice <= len(interfaces):
                    return interfaces[choice - 1]
            except ValueError:
                pass
            console.print("[red]Invalid choice![/red]")
        
    except Exception as e:
        console.print(f"[red]Error getting wireless interface: {str(e)}[/red]")
        return None

def setup_monitor_mode(interface):
    """Enable monitor mode on interface"""
    try:
        # Kill interfering processes
        subprocess.run(['airmon-ng', 'check', 'kill'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)
        
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
                
                # Check if interface name changed (e.g., wlan0mon)
                mon_interface = interface + 'mon'
                if os.path.exists(f'/sys/class/net/{mon_interface}'):
                    return mon_interface
            except:
                continue
        
        console.print("[red]Failed to enable monitor mode![/red]")
        return None
        
    except Exception as e:
        console.print(f"[red]Error setting up monitor mode: {str(e)}[/red]")
        return None 