#!/usr/bin/env python3

from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11WEP
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
import threading
import time
import os
import subprocess
from datetime import datetime
from threading import Thread
from modules.utils import (
    check_wireless_tools,
    get_interface,
    setup_monitor_mode,
    get_data_path,
    log_activity
)

class NetworkScanner:
    def __init__(self):
        self.console = Console()
        self.interface = None
        self.networks = []
        self.channel = 1
        self.running = False
        self.lock = threading.Lock()
        self.display_thread = None
        self.scan_time = 30  # Default scan time in seconds

    def _channel_hopper(self):
        """Hop through channels 1-14"""
        while self.running:
            try:
                subprocess.run(['iwconfig', self.interface, 'channel', str(self.channel)],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
                self.channel = self.channel % 14 + 1
                time.sleep(0.5)
            except:
                continue

    def _packet_handler(self, pkt):
        """Handle captured packets"""
        if pkt.haslayer(Dot11Beacon):
            try:
                # Extract basic information
                bssid = pkt[Dot11].addr2
                essid = pkt[Dot11Elt].info.decode()
                channel = int(ord(pkt[Dot11Elt:3].info))
                signal = -(256-ord(pkt.notdecoded[-4:-3]))
                
                # Get encryption type
                capability = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
                encryption = "Open"
                
                if 'privacy' in capability:
                    # Check for WEP
                    if pkt.haslayer(Dot11WEP):
                        encryption = "WEP"
                    else:
                        # Check for WPA/WPA2
                        for n in range(pkt[Dot11Elt].payload.iterpayloads()):
                            if n.ID == 48:  # RSN (WPA2) element ID
                                encryption = "WPA2"
                                break
                            elif n.ID == 221 and n.info.startswith(b'\x00P\xf2\x01\x01\x00'):  # WPA element ID
                                encryption = "WPA"
                                break
                
                # Check if network already found
                with self.lock:
                    for network in self.networks:
                        if network['bssid'] == bssid:
                            network.update({
                                'signal': signal,
                                'last_seen': time.time()
                            })
                            return
                    
                    # Add new network
                    self.networks.append({
                        'essid': essid,
                        'bssid': bssid,
                        'channel': channel,
                        'signal': signal,
                        'encryption': encryption,
                        'first_seen': time.time(),
                        'last_seen': time.time(),
                        'beacons': 1,
                        'clients': set()
                    })
                
            except:
                pass
        
        # Track client connections
        elif pkt.haslayer(Dot11) and pkt.type == 2:  # Data frames
            try:
                ds = pkt.FCfield & 0x3
                if ds == 1:  # Station to AP
                    client = pkt.addr2
                    bssid = pkt.addr1
                elif ds == 2:  # AP to Station
                    client = pkt.addr1
                    bssid = pkt.addr2
                else:
                    return
                
                # Update network client list
                with self.lock:
                    for network in self.networks:
                        if network['bssid'] == bssid:
                            network['clients'].add(client)
                            break
            except:
                pass

    def display_networks(self):
        """Display networks with improved formatting"""
        table = Table(title="Discovered Networks")
        table.add_column("BSSID", style="cyan")
        table.add_column("ESSID", style="green")
        table.add_column("Channel", justify="right")
        table.add_column("Signal", justify="right")
        table.add_column("Encryption", style="yellow")
        table.add_column("Clients", justify="right")

        with self.lock:
            networks = sorted(self.networks, key=lambda x: x['signal'], reverse=True)
            
            for network in networks:
                table.add_row(
                    network['bssid'],
                    network['essid'] or "<hidden>",
                    str(network['channel']),
                    f"{network['signal']} dBm",
                    network['encryption'],
                    str(len(network['clients']))
                )

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

            # Start channel hopping
            self.running = True
            channel_thread = Thread(target=self._channel_hopper)
            channel_thread.daemon = True
            channel_thread.start()

            # Start scanning
            self.console.print("\n[yellow]Starting network scan...[/yellow]")
            self.console.print(f"[cyan]Scanning for {self.scan_time} seconds...[/cyan]")

            with Progress() as progress:
                task = progress.add_task("[cyan]Scanning...", total=self.scan_time)

                # Start packet capture
                sniff_thread = Thread(target=lambda: sniff(
                    iface=self.interface,
                    prn=self._packet_handler,
                    timeout=self.scan_time
                ))
                sniff_thread.daemon = True
                sniff_thread.start()

                # Show progress and update network display
                start_time = time.time()
                while time.time() - start_time < self.scan_time:
                    progress.update(task, completed=int(time.time() - start_time))
                    self.display_networks()
                    time.sleep(1)
                    os.system('cls' if os.name == 'nt' else 'clear')

            self.running = False
            time.sleep(1)  # Wait for threads to clean up

            # Final network display
            if not self.networks:
                self.console.print("[yellow]No networks found![/yellow]")
                return

            self.display_networks()

            # Save results
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            save_path = get_data_path('scans', f'scan_{timestamp}.txt')

            with open(save_path, 'w') as f:
                f.write("Network Scan Results\n")
                f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Interface: {self.interface}\n")
                f.write(f"Duration: {self.scan_time} seconds\n\n")
                f.write("BSSID,ESSID,Channel,Signal,Encryption,Clients\n")
                for network in sorted(self.networks, key=lambda x: x['signal'], reverse=True):
                    f.write(f"{network['bssid']},{network['essid']},{network['channel']},"
                           f"{network['signal']},{network['encryption']},{len(network['clients'])}\n")
                    if network['clients']:
                        f.write("Connected clients:\n")
                        for client in network['clients']:
                            f.write(f"  {client}\n")
                        f.write("\n")

            self.console.print(f"\n[green]Scan results saved to: {save_path}[/green]")
            log_activity(f"Network scan completed - Found {len(self.networks)} networks")

        except Exception as e:
            self.console.print(f"[red]Error during scan: {str(e)}[/red]")

        finally:
            # Cleanup
            self.running = False
            try:
                subprocess.run(['airmon-ng', 'stop', self.interface],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
            except:
                pass

            input("\nPress Enter to continue...") 