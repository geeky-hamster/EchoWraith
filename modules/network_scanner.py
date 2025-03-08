#!/usr/bin/env python3

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
import subprocess
import threading
import time
import os
import json
from datetime import datetime
from modules.utils import (
    get_data_path,
    log_activity,
    get_temp_path,
    cleanup_temp_files
)
from modules import InterfaceManager

console = Console()

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
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeElapsedColumn(),
            ) as progress:
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
                                                'first_seen': parts[1].strip(),
                                                'last_seen': parts[2].strip(),
                                                'channel': parts[3].strip(),
                                                'speed': parts[4].strip(),
                                                'privacy': parts[5].strip(),
                                                'cipher': parts[6].strip(),
                                                'authentication': parts[7].strip(),
                                                'power': parts[8].strip(),
                                                'beacons': parts[9].strip(),
                                                'iv': parts[10].strip(),
                                                'lan_ip': parts[11].strip(),
                                                'id_length': parts[12].strip(),
                                                'essid': parts[13].strip().rstrip('\x00'),
                                                'key': parts[14].strip() if len(parts) > 14 else '',
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
                                        client_info = {
                                            'mac': client_mac,
                                            'first_seen': parts[1].strip(),
                                            'last_seen': parts[2].strip(),
                                            'power': parts[3].strip(),
                                            'packets': parts[4].strip(),
                                            'probed_essids': [essid.strip() for essid in parts[6:] if essid.strip()]
                                        }
                                        for network in networks:
                                            if network['bssid'] == ap_mac:
                                                network['clients'].add(json.dumps(client_info))
                                                
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
        table.add_column("Privacy", style="yellow")
        table.add_column("Power (dBm)", justify="right")
        table.add_column("Speed", justify="center")
        table.add_column("Clients", justify="center")

        for network in sorted(networks, key=lambda x: int(x.get('power', '0') or '0'), reverse=True):
            power = network['power']
            if power.isdigit() or (power.startswith('-') and power[1:].isdigit()):
                power = f"{int(power)} dBm"
            else:
                power = "N/A"

            table.add_row(
                network['bssid'],
                network['channel'],
                network['essid'] or "<hidden>",
                f"{network['privacy']}/{network['cipher']}/{network['authentication']}",
                power,
                f"{network['speed']} MB/s",
                str(len(network['clients']))
            )

        os.system('cls' if os.name == 'nt' else 'clear')
        self.console.print(table)

    def start_scan(self):
        """Start network scanning"""
        try:
            # Get interface and ensure monitor mode
            if not InterfaceManager.ensure_monitor_mode():
                self.console.print("[red]Failed to set monitor mode. Aborting scan.[/red]")
                return

            self.interface = InterfaceManager.get_current_interface()
            if not self.interface:
                self.console.print("[red]No wireless interface available.[/red]")
                return

            # Create scan output file
            timestamp = time.strftime("%Y%m%d-%H%M%S")
            output_file = get_data_path('scans', f'scan_{timestamp}')

            # Start airodump-ng scan
            self.console.print(f"\n[cyan]Starting network scan with {self.interface}...[/cyan]")
            self.console.print(f"[yellow]Scan will run for {self.scan_time} seconds[/yellow]\n")

            with Progress() as progress:
                scan_task = progress.add_task("[cyan]Scanning...", total=self.scan_time)

                # Start airodump-ng in background
                scan_proc = subprocess.Popen(
                    [
                        'airodump-ng',
                        '--write', output_file,
                        '--output-format', 'csv',
                        self.interface
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )

                # Show progress bar during scan
                while not progress.finished:
                    time.sleep(1)
                    progress.update(scan_task, advance=1)

                # Stop airodump-ng
                scan_proc.terminate()

            # Parse and display results
            csv_file = f"{output_file}-01.csv"
            if os.path.exists(csv_file):
                self.parse_results(csv_file)
                self.display_results()
            else:
                self.console.print("[red]No scan results found![/red]")

        except Exception as e:
            self.console.print(f"[red]Error during network scan: {str(e)}[/red]")
        finally:
            # Clean up temporary files
            for ext in ['-01.csv', '-01.kismet.csv', '-01.kismet.netxml', '-01.log.csv']:
                temp_file = f"{output_file}{ext}"
                if os.path.exists(temp_file):
                    os.remove(temp_file)

    def parse_results(self, csv_file):
        """Parse airodump-ng CSV output"""
        try:
            networks = []
            with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            # Find the split between networks and clients
            split_index = 0
            for i, line in enumerate(lines):
                if line.strip() == '':
                    split_index = i
                    break

            # Parse networks
            if split_index > 0:
                headers = [h.strip() for h in lines[0].split(',')]
                for line in lines[1:split_index]:
                    if line.strip():
                        data = [d.strip() for d in line.split(',')]
                        if len(data) >= 13:  # Ensure we have enough fields
                            network = {
                                'bssid': data[0],
                                'essid': data[13].strip() or '<hidden>',
                                'channel': data[3],
                                'power': data[8],
                                'encryption': data[5],
                                'clients': 0
                            }
                            networks.append(network)

            # Count clients for each network
            if len(lines) > split_index + 2:
                for line in lines[split_index + 2:]:
                    if line.strip():
                        data = [d.strip() for d in line.split(',')]
                        if len(data) >= 6:  # Ensure we have enough fields
                            bssid = data[5]
                            for network in networks:
                                if network['bssid'] == bssid:
                                    network['clients'] += 1

            self.networks = networks

        except Exception as e:
            self.console.print(f"[red]Error parsing scan results: {str(e)}[/red]")

    def display_results(self):
        """Display scan results in a table"""
        if not self.networks:
            self.console.print("[yellow]No networks found.[/yellow]")
            return

        # Create results table
        table = Table(
            title="Discovered Networks",
            show_header=True,
            header_style="bold magenta",
            border_style="cyan"
        )

        # Add columns
        table.add_column("BSSID", style="cyan")
        table.add_column("ESSID", style="green")
        table.add_column("Channel", justify="center")
        table.add_column("Power", justify="right")
        table.add_column("Encryption", style="yellow")
        table.add_column("Clients", justify="center")

        # Add network data
        for network in sorted(self.networks, key=lambda x: int(x['power'] or 0), reverse=True):
            table.add_row(
                network['bssid'],
                network['essid'],
                network['channel'],
                network['power'],
                network['encryption'],
                str(network['clients'])
            )

        self.console.print(table)
        self.console.print(f"\n[green]Found {len(self.networks)} networks[/green]")

        # Save detailed results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        save_path = get_data_path('scans', f'scan_{timestamp}')
        
        # Save JSON format for machine processing
        with open(f"{save_path}.json", 'w') as f:
            # Convert sets to lists for JSON serialization
            networks_json = []
            for network in self.networks:
                network_copy = network.copy()
                network_copy['clients'] = [json.loads(client) for client in network['clients']]
                networks_json.append(network_copy)
            json.dump(networks_json, f, indent=4)

        # Save human-readable format
        with open(f"{save_path}.txt", 'w') as f:
            f.write("Network Scan Results\n")
            f.write("===================\n\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Interface: {self.interface}\n")
            f.write(f"Duration: {self.scan_time} seconds\n")
            f.write(f"Networks Found: {len(self.networks)}\n\n")

            for i, network in enumerate(sorted(self.networks, key=lambda x: int(x.get('power', '0') or '0'), reverse=True), 1):
                f.write(f"Network {i}\n")
                f.write("-" * 50 + "\n")
                f.write(f"ESSID: {network['essid'] or '<hidden>'}\n")
                f.write(f"BSSID: {network['bssid']}\n")
                f.write(f"Channel: {network['channel']}\n")
                f.write(f"Signal Strength: {network['power']} dBm\n")
                if 'speed' in network:
                    f.write(f"Speed: {network['speed']} MB/s\n")
                if 'privacy' in network:
                    f.write(f"Privacy: {network['privacy']}\n")
                if 'cipher' in network:
                    f.write(f"Cipher: {network['cipher']}\n")
                if 'authentication' in network:
                    f.write(f"Authentication: {network['authentication']}\n")
                if 'first_seen' in network:
                    f.write(f"First Seen: {network['first_seen']}\n")
                if 'last_seen' in network:
                    f.write(f"Last Seen: {network['last_seen']}\n")
                if 'beacons' in network:
                    f.write(f"Beacons: {network['beacons']}\n")
                if 'iv' in network:
                    f.write(f"Data Packets: {network['iv']}\n")
                if 'lan_ip' in network and network['lan_ip']:
                    f.write(f"LAN IP: {network['lan_ip']}\n")
                
                if network['clients']:
                    f.write("\nConnected Clients:\n")
                    for client_json in network['clients']:
                        client = json.loads(client_json)
                        f.write(f"\n  Client MAC: {client['mac']}\n")
                        f.write(f"  First Seen: {client['first_seen']}\n")
                        f.write(f"  Last Seen: {client['last_seen']}\n")
                        f.write(f"  Signal Strength: {client['power']} dBm\n")
                        f.write(f"  Packets: {client['packets']}\n")
                        if client['probed_essids']:
                            f.write("  Probed Networks:\n")
                            for essid in client['probed_essids']:
                                f.write(f"    - {essid}\n")
                f.write("\n")

        self.console.print(f"\n[green]Detailed scan results saved to:[/green]")
        self.console.print(f"[cyan]- {save_path}.txt[/cyan] (Human readable)")
        self.console.print(f"[cyan]- {save_path}.json[/cyan] (Machine readable)")
        log_activity(f"Network scan completed - Found {len(self.networks)} networks") 