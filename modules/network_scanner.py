#!/usr/bin/env python3

from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11WEP
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
import threading
import time
import netifaces
import subprocess
import signal
import os

class NetworkScanner:
    def __init__(self):
        self.console = Console()
        self.networks = {}
        self.lock = threading.Lock()
        self.interface = None
        self.running = False
        self.channel_hopper = None
        self.display_thread = None

    def cleanup(self):
        """Clean up resources and restore interface state"""
        try:
            self.running = False
            if self.channel_hopper and self.channel_hopper.is_alive():
                self.channel_hopper.join(timeout=1)
            if self.display_thread and self.display_thread.is_alive():
                self.display_thread.join(timeout=1)
            if self.interface:
                subprocess.run(['airmon-ng', 'stop', self.interface], 
                             stdout=subprocess.DEVNULL, 
                             stderr=subprocess.DEVNULL)
        except Exception as e:
            self.console.print(f"[red]Error during cleanup: {str(e)}[/red]")

    def get_interface(self):
        """Get available wireless interfaces with improved detection"""
        try:
            interfaces = []
            
            # Method 1: iwconfig
            result = subprocess.run(['iwconfig'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'IEEE 802.11' in line:
                    iface = line.split()[0]
                    interfaces.append(iface)

            # Method 2: iw dev
            if not interfaces:
                result = subprocess.run(['iw', 'dev'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if 'Interface' in line:
                        iface = line.split('Interface')[1].strip()
                        interfaces.append(iface)

            # Method 3: Check /sys/class/net for wireless devices
            if not interfaces:
                for iface in os.listdir('/sys/class/net'):
                    if os.path.exists(f'/sys/class/net/{iface}/wireless'):
                        interfaces.append(iface)

            if not interfaces:
                self.console.print("[red]No wireless interfaces found![/red]")
                self.console.print("[yellow]Please ensure your wireless adapter is connected and recognized.[/yellow]")
                return None

            # Display available interfaces in a table
            table = Table(title="Available Wireless Interfaces")
            table.add_column("Index", style="cyan")
            table.add_column("Interface", style="green")
            table.add_column("Status", style="yellow")

            for idx, iface in enumerate(interfaces, 1):
                # Get interface status
                status = "Unknown"
                try:
                    result = subprocess.run(['iwconfig', iface], capture_output=True, text=True)
                    if 'Mode:Monitor' in result.stdout:
                        status = "Monitor Mode"
                    elif 'Mode:Managed' in result.stdout:
                        status = "Managed Mode"
                except:
                    pass
                table.add_row(str(idx), iface, status)

            self.console.print(table)

            while True:
                try:
                    choice = int(input("\nSelect interface number: ")) - 1
                    if 0 <= choice < len(interfaces):
                        return interfaces[choice]
                except ValueError:
                    pass
                self.console.print("[red]Invalid choice. Please try again.[/red]")

        except Exception as e:
            self.console.print(f"[red]Error detecting wireless interfaces: {str(e)}[/red]")
            return None

    def setup_monitor_mode(self):
        """Setup monitor mode with improved reliability"""
        try:
            if not self.interface:
                self.interface = self.get_interface()
                if not self.interface:
                    return None

            # Kill interfering processes more thoroughly
            subprocess.run(['airmon-ng', 'check', 'kill'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1)  # Give system time to clean up

            # Check if already in monitor mode
            if 'mon' in self.interface:
                return self.interface

            # Try multiple methods to enable monitor mode
            methods = [
                ['airmon-ng', 'start', self.interface],
                ['iw', 'dev', self.interface, 'set', 'monitor', 'none'],
                ['iwconfig', self.interface, 'mode', 'monitor']
            ]

            for method in methods:
                try:
                    subprocess.run(method, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    time.sleep(2)
                    
                    # Verify monitor mode
                    result = subprocess.run(['iwconfig', self.interface], capture_output=True, text=True)
                    if 'Mode:Monitor' in result.stdout:
                        return self.interface
                except:
                    continue

            # If all methods failed, try with mon suffix
            mon_interface = self.interface + 'mon'
            if os.path.exists(f'/sys/class/net/{mon_interface}'):
                self.interface = mon_interface
                return mon_interface

            self.console.print("[red]Failed to enable monitor mode.[/red]")
            return None

        except Exception as e:
            self.console.print(f"[red]Error setting up monitor mode: {str(e)}[/red]")
            return None

    def packet_handler(self, pkt):
        """Handle captured packets with improved data extraction"""
        try:
            if pkt.haslayer(Dot11Beacon):
                bssid = pkt[Dot11].addr2
                essid = pkt[Dot11Elt].info.decode() if pkt[Dot11Elt].info else "Hidden SSID"
                
                # Get channel with fallback methods
                channel = 0
                try:
                    channel = int(ord(pkt[Dot11Elt:3].info))
                except:
                    for element in pkt[Dot11Elt:]:
                        if element.ID == 3:
                            channel = ord(element.info)
                            break
                
                # Get signal strength with improved accuracy
                signal_strength = -100
                try:
                    signal_strength = -(256-ord(pkt.notdecoded[-4:-3]))
                except:
                    try:
                        signal_strength = -(256-ord(pkt.notdecoded[-2:-1]))
                    except:
                        pass
                
                # Get additional network information
                stats = {
                    'Privacy': set(),
                    'Cipher': set(),
                    'Authentication': set()
                }
                
                current = pkt
                while Dot11Elt in current:
                    if current[Dot11Elt].ID == 48:  # RSN
                        stats['Privacy'].add("WPA2")
                    elif current[Dot11Elt].ID == 221 and current[Dot11Elt].info.startswith(b'\x00P\xf2\x01\x01\x00'):
                        stats['Privacy'].add("WPA")
                    current = current[Dot11Elt].payload
                
                if not stats['Privacy']:
                    if Dot11WEP in pkt:
                        stats['Privacy'].add("WEP")
                    else:
                        stats['Privacy'].add("Open")

                # Only add networks with valid ESSID
                if essid and essid != "Hidden SSID":
                    with self.lock:
                        if bssid not in self.networks:
                            self.networks[bssid] = {
                                'ESSID': essid,
                                'Channel': channel,
                                'Signal': signal_strength,
                                'Privacy': '/'.join(stats['Privacy']),
                                'First Seen': time.strftime("%Y-%m-%d %H:%M:%S"),
                                'Last Seen': time.strftime("%Y-%m-%d %H:%M:%S"),
                                'Beacons': 1,
                                'Data Packets': 0
                            }
                        else:
                            self.networks[bssid]['Last Seen'] = time.strftime("%Y-%m-%d %H:%M:%S")
                            self.networks[bssid]['Beacons'] += 1
                            self.networks[bssid]['Signal'] = max(signal_strength, self.networks[bssid]['Signal'])
        except Exception as e:
            pass  # Silently skip malformed packets

    def display_networks(self):
        """Display networks with improved formatting"""
        table = Table(title="Discovered Networks")
        table.add_column("BSSID", style="cyan")
        table.add_column("ESSID", style="green")
        table.add_column("Channel", justify="right")
        table.add_column("Signal", justify="right")
        table.add_column("Privacy", style="yellow")
        table.add_column("Last Seen", style="magenta")
        table.add_column("Beacons", justify="right")

        with self.lock:
            networks = sorted(self.networks.items(), 
                            key=lambda x: x[1]['Signal'], 
                            reverse=True)
            
            for bssid, data in networks:
                table.add_row(
                    bssid,
                    data['ESSID'],
                    str(data['Channel']),
                    f"{data['Signal']} dBm",
                    data['Privacy'],
                    data['Last Seen'].split()[1],  # Show only time
                    str(data['Beacons'])
                )
        
        self.console.clear()
        self.console.print(table)
        self.console.print("\n[cyan]Press Ctrl+C to stop scanning[/cyan]")

    def channel_hopper(self, interface):
        """Hop through channels with improved timing"""
        while self.running:
            for channel in range(1, 15):
                if not self.running:
                    break
                try:
                    subprocess.run(['iw', 'dev', interface, 'set', 'channel', str(channel)],
                                 stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
                    # Adaptive channel hopping delay based on network density
                    with self.lock:
                        networks_on_channel = sum(1 for net in self.networks.values() 
                                                if net['Channel'] == channel)
                        delay = 0.5 if networks_on_channel > 0 else 0.3
                    time.sleep(delay)
                except:
                    break

    def start_scan(self):
        """Start scanning with improved control flow"""
        try:
            # Setup monitor mode
            mon_interface = self.setup_monitor_mode()
            if not mon_interface:
                self.console.print("[red]Failed to setup monitor mode. Make sure your wireless adapter supports monitor mode.[/red]")
                return

            self.console.print(f"[green]Starting scan on interface {mon_interface}...[/green]")
            self.console.print("[cyan]Press Ctrl+C to stop scanning[/cyan]\n")

            # Clear any previous networks
            self.networks = {}
            self.running = True

            # Start display thread
            self.display_thread = threading.Thread(target=self.periodic_display)
            self.display_thread.daemon = True
            self.display_thread.start()

            # Start channel hopping
            self.channel_hopper = threading.Thread(target=self.channel_hopper, args=(mon_interface,))
            self.channel_hopper.daemon = True
            self.channel_hopper.start()

            # Setup signal handler for graceful exit
            def signal_handler(signum, frame):
                self.running = False
                raise KeyboardInterrupt

            signal.signal(signal.SIGINT, signal_handler)

            # Start sniffing with timeout
            while self.running:
                try:
                    sniff(iface=mon_interface, 
                          prn=self.packet_handler, 
                          store=0,
                          timeout=2)
                except Exception as e:
                    if not self.running:
                        break
                    self.console.print(f"[red]Error during scan: {str(e)}[/red]")

        except KeyboardInterrupt:
            self.console.print("\n[yellow]Scan stopped by user[/yellow]")
        except Exception as e:
            self.console.print(f"[red]Error during scan: {str(e)}[/red]")
        finally:
            self.cleanup()

    def periodic_display(self):
        """Periodically update the display with adaptive refresh rate"""
        last_count = 0
        refresh_rate = 2.0  # Start with 2 second refresh

        while self.running:
            try:
                with self.lock:
                    current_count = len(self.networks)
                
                # Adjust refresh rate based on network discovery rate
                if current_count > last_count:
                    refresh_rate = max(0.5, refresh_rate * 0.8)  # Speed up
                else:
                    refresh_rate = min(2.0, refresh_rate * 1.2)  # Slow down
                
                self.display_networks()
                last_count = current_count
                time.sleep(refresh_rate)
            except:
                break 