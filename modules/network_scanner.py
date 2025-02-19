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
from datetime import datetime
from threading import Thread

class NetworkScanner:
    def __init__(self):
        self.console = Console()
        self.networks = []
        self.interface = None
        self.channel = 1
        self.running = False
        self.lock = threading.Lock()
        self.display_thread = None

    def cleanup(self):
        """Clean up resources and restore interface state"""
        try:
            self.running = False
            if self.display_thread and self.display_thread.is_alive():
                self.display_thread.join(timeout=1)
            if self.interface:
                subprocess.run(['airmon-ng', 'stop', self.interface], 
                             stdout=subprocess.DEVNULL, 
                             stderr=subprocess.DEVNULL)
        except Exception as e:
            self.console.print(f"[red]Error during cleanup: {str(e)}[/red]")

    def _check_wireless_tools(self):
        """Check if required wireless tools are available"""
        try:
            subprocess.run(['iwconfig'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return True
        except FileNotFoundError:
            self.console.print("[red]Error: wireless-tools not found. Please install wireless-tools package.[/red]")
            return False
            
    def _get_interface(self):
        """Get wireless interface from user"""
        try:
            # Get list of wireless interfaces
            result = subprocess.run(['iwconfig'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            interfaces = []
            
            for line in result.stdout.decode().split('\n'):
                if 'IEEE 802.11' in line:
                    interface = line.split()[0]
                    interfaces.append(interface)
                    
            if not interfaces:
                self.console.print("[red]No wireless interfaces found![/red]")
                return None
                
            # Create selection table
            table = Table(title="Available Wireless Interfaces")
            table.add_column("Option", style="cyan", justify="right")
            table.add_column("Interface", style="green")
            
            for i, interface in enumerate(interfaces, 1):
                table.add_row(str(i), interface)
                
            self.console.print(table)
            
            while True:
                try:
                    choice = int(input("\nSelect interface: "))
                    if 1 <= choice <= len(interfaces):
                        return interfaces[choice-1]
                    else:
                        self.console.print("[red]Invalid choice. Please try again.[/red]")
                except ValueError:
                    self.console.print("[red]Invalid input. Please enter a number.[/red]")
                    
        except Exception as e:
            self.console.print(f"[red]Error getting wireless interfaces: {str(e)}[/red]")
            return None
            
    def _enable_monitor_mode(self):
        """Enable monitor mode on selected interface"""
        try:
            # Kill interfering processes
            subprocess.run(['airmon-ng', 'check', 'kill'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Start monitor mode
            result = subprocess.run(['airmon-ng', 'start', self.interface], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Check if monitor mode is enabled
            check = subprocess.run(['iwconfig', self.interface], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if 'Mode:Monitor' in check.stdout.decode():
                return True
                
            # If interface name changed, update it
            for line in result.stdout.decode().split('\n'):
                if '(monitor mode enabled on' in line:
                    self.interface = line.split('on')[1].strip().strip(')')
                    return True
                    
            return False
            
        except Exception as e:
            self.console.print(f"[red]Error enabling monitor mode: {str(e)}[/red]")
            return False
            
    def _channel_hopper(self):
        """Hop through channels 1-14"""
        while self.running:
            try:
                subprocess.run(['iwconfig', self.interface, 'channel', str(self.channel)], 
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.channel = self.channel % 14 + 1
                time.sleep(0.5)
            except:
                continue
                
    def _packet_handler(self, pkt):
        """Handle captured packets"""
        if pkt.haslayer(Dot11Beacon):
            try:
                bssid = pkt[Dot11].addr2
                ssid = pkt[Dot11Elt].info.decode()
                channel = int(ord(pkt[Dot11Elt:3].info))
                signal = -(256-ord(pkt.notdecoded[-4:-3]))
                
                # Check if network already found
                for network in self.networks:
                    if network['bssid'] == bssid:
                        network['signal'] = signal
                        return
                        
                # Add new network
                self.networks.append({
                    'ssid': ssid,
                    'bssid': bssid,
                    'channel': channel,
                    'signal': signal
                })
                
            except:
                pass
                
    def start_scan(self):
        """Start network scanning"""
        try:
            # Check requirements
            if not self._check_wireless_tools():
                return
                
            # Get wireless interface
            self.interface = self._get_interface()
            if not self.interface:
                return
                
            # Enable monitor mode
            self.console.print("\n[yellow]Enabling monitor mode...[/yellow]")
            if not self._enable_monitor_mode():
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
            
            with Progress() as progress:
                scan_task = progress.add_task("[cyan]Scanning...", total=None)
                
                # Sniff packets
                sniff(iface=self.interface, prn=self._packet_handler, timeout=20)
                
            self.running = False
            
            # Display results
            if not self.networks:
                self.console.print("[yellow]No networks found![/yellow]")
                return
                
            table = Table(title="Discovered Networks")
            table.add_column("SSID", style="cyan")
            table.add_column("BSSID", style="green")
            table.add_column("Channel", justify="right", style="yellow")
            table.add_column("Signal", justify="right", style="red")
            
            for network in sorted(self.networks, key=lambda x: x['signal'], reverse=True):
                table.add_row(
                    network['ssid'],
                    network['bssid'],
                    str(network['channel']),
                    str(network['signal']) + " dBm"
                )
                
            self.console.print(table)
            
            # Save results
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            save_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                                   'data', 'scans', f'scan_{timestamp}.txt')
                                   
            with open(save_path, 'w') as f:
                f.write("SSID,BSSID,Channel,Signal\n")
                for network in self.networks:
                    f.write(f"{network['ssid']},{network['bssid']},{network['channel']},{network['signal']}\n")
                    
            self.console.print(f"\n[green]Scan results saved to: {save_path}[/green]")
            
        except Exception as e:
            self.console.print(f"[red]Error during scan: {str(e)}[/red]")
            
        finally:
            # Cleanup
            self.running = False
            try:
                subprocess.run(['airmon-ng', 'stop', self.interface], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except:
                pass
            
            input("\nPress Enter to continue...")

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
            networks = sorted(self.networks, key=lambda x: x['signal'], reverse=True)
            
            for network in networks:
                table.add_row(
                    network['bssid'],
                    network['ssid'],
                    str(network['channel']),
                    str(network['signal']) + " dBm"
                )
        
        self.console.clear()
        self.console.print(table)
        self.console.print("\n[cyan]Press Ctrl+C to stop scanning[/cyan]")

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