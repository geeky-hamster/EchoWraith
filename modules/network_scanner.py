#!/usr/bin/env python3

from rich.console import Console
from rich.table import Table
from rich.progress import Progress
import subprocess
import threading
import time
import os
from datetime import datetime
from modules.utils import (
    check_wireless_tools,
    get_interface,
    setup_monitor_mode,
    get_data_path,
    log_activity,
    get_temp_path,
    cleanup_temp_files
)

class NetworkScanner:
    def __init__(self):
        self.console = Console()
        self.interface = None
        self.networks = []
        self.running = False
        self.scan_time = 30  # Default scan time in seconds

    def scan_networks(self):
        """Scan for networks using airodump-ng"""
        try:
            networks = []
            temp_file = get_temp_path(f'scan_{int(time.time())}')
            
            # Start airodump-ng scan
            scan_process = subprocess.Popen(
                ['airodump-ng', '--output-format', 'csv', '-w', temp_file, self.interface],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            # Show progress while scanning
            with Progress() as progress:
                task = progress.add_task("[cyan]Scanning for networks...", total=self.scan_time)
                
                for i in range(self.scan_time):
                    progress.update(task, advance=1)
                    
                    # Parse current results
                    csv_file = f"{temp_file}-01.csv"
                    if os.path.exists(csv_file):
                        try:
                            with open(csv_file, 'r', encoding='utf-8') as f:
                                lines = f.readlines()
                                
                            # Process networks section
                            networks.clear()  # Clear previous results
                            for line in lines[2:]:  # Skip headers
                                if line.strip() and ',' in line:
                                    parts = line.strip().split(',')
                                    if len(parts) >= 14:  # Valid network line
                                        bssid = parts[0].strip()
                                        if bssid and ':' in bssid:  # Valid BSSID
                                            networks.append({
                                                'bssid': bssid,
                                                'channel': parts[3].strip(),
                                                'encryption': parts[5].strip(),
                                                'essid': parts[13].strip().rstrip('\x00'),
                                                'signal': parts[8].strip(),
                                                'clients': set()
                                            })
                            
                            # Process clients section
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
                                            if network['bssid'] == ap_mac:
                                                network['clients'].add(client_mac)
                                                
                            # Display current results
                            if networks:
                                self.display_networks(networks)
                                
                        except Exception as e:
                            self.console.print(f"[yellow]Error parsing results: {str(e)}[/yellow]")
                    
                    time.sleep(1)
                
            # Cleanup
            scan_process.terminate()
            cleanup_temp_files()
            return networks
            
        except Exception as e:
            self.console.print(f"[red]Error during scan: {str(e)}[/red]")
            return []

    def display_networks(self, networks):
        """Display networks in a formatted table"""
        table = Table(title="Discovered Networks")
        table.add_column("BSSID", style="cyan")
        table.add_column("Channel", justify="center")
        table.add_column("ESSID", style="green")
        table.add_column("Encryption", style="yellow")
        table.add_column("Signal", justify="right")
        table.add_column("Clients", justify="center")

        for network in sorted(networks, key=lambda x: x.get('signal', '0'), reverse=True):
            table.add_row(
                network['bssid'],
                network['channel'],
                network['essid'] or "<hidden>",
                network['encryption'],
                network['signal'],
                str(len(network['clients']))
            )

        os.system('cls' if os.name == 'nt' else 'clear')
        self.console.print(table)

    def start_scan(self):
        """Start network scanning"""
        try:
            # Check requirements
            if not check_wireless_tools():
                return

            # Get wireless interface
            self.interface = get_interface()
            if not self.interface:
                return

            # Enable monitor mode
            self.console.print("\n[yellow]Enabling monitor mode...[/yellow]")
            self.interface = setup_monitor_mode(self.interface)
            if not self.interface:
                self.console.print("[red]Failed to enable monitor mode![/red]")
                return

            self.console.print("[green]Monitor mode enabled successfully![/green]")
            self.console.print(f"[cyan]Using interface: {self.interface}[/cyan]")

            # Start scanning
            self.console.print("\n[yellow]Starting network scan...[/yellow]")
            networks = self.scan_networks()

            if not networks:
                self.console.print("[yellow]No networks found in range.[/yellow]")
                return

            # Display final results
            self.display_networks(networks)

            # Save results
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            save_path = get_data_path('scans', f'scan_{timestamp}.txt')

            with open(save_path, 'w') as f:
                f.write("Network Scan Results\n")
                f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Interface: {self.interface}\n")
                f.write(f"Duration: {self.scan_time} seconds\n\n")
                f.write("BSSID,Channel,ESSID,Encryption,Signal,Clients\n")
                for network in sorted(networks, key=lambda x: x.get('signal', '0'), reverse=True):
                    f.write(f"{network['bssid']},{network['channel']},{network['essid']},"
                           f"{network['encryption']},{network['signal']},{len(network['clients'])}\n")
                    if network['clients']:
                        f.write("Connected clients:\n")
                        for client in network['clients']:
                            f.write(f"  {client}\n")
                        f.write("\n")

            self.console.print(f"\n[green]Scan results saved to: {save_path}[/green]")
            log_activity(f"Network scan completed - Found {len(networks)} networks")

        except Exception as e:
            self.console.print(f"[red]Error during scan: {str(e)}[/red]")

        finally:
            # Cleanup
            try:
                subprocess.run(['airmon-ng', 'stop', self.interface],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
            except:
                pass

            input("\nPress Enter to continue...") 