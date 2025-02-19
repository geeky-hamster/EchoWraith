#!/usr/bin/env python3

import sys
import os
import subprocess
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.progress import Progress
from datetime import datetime
from modules.network_scanner import NetworkScanner
from modules.deauth_attack import DeauthAttacker
from modules.wps_attack import WPSAttacker
from modules.handshake_capture import HandshakeCapture
from modules.utils import setup_workspace, cleanup_workspace, log_activity, check_wireless_tools

console = Console()

class EchoWraith:
    def __init__(self):
        self.console = Console()
        self.modules = {
            '1': ('System Check', self.system_check, 'Check system requirements and wireless capabilities'),
            '2': ('Network Scanner', self.network_scan, 'Discover and analyze nearby WiFi networks'),
            '3': ('Deauthentication', self.deauth_attack, 'Disconnect clients from target networks'),
            '4': ('WPS Analysis', self.wps_attack, 'Test WPS security'),
            '5': ('Handshake Capture', self.capture_handshake, 'Capture and analyze WPA/WPA2 handshakes'),
            '6': ('View History', self.view_history, 'View previous session results'),
            '7': ('Clean Workspace', self.clean_workspace, 'Delete all created files and directories'),
            '8': ('Exit', self.exit_program, 'Exit EchoWraith')
        }
        self.directories = setup_workspace()
        if not self.directories:
            console.print("[red]Failed to setup workspace. Some features may not work correctly.[/red]")

    def perform_system_check(self):
        """Perform comprehensive system check"""
        try:
            self.console.print("\n[cyan]Performing system check...[/cyan]")
            checks_passed = True
            
            # Check Python version
            python_version = sys.version_info
            if python_version.major < 3 or (python_version.major == 3 and python_version.minor < 6):
                self.console.print("[red]❌ Error: Python 3.6 or higher is required[/red]")
                checks_passed = False
            else:
                self.console.print("[green]✓ Python version: OK[/green]")
            
            # Check root privileges
            if os.geteuid() != 0:
                self.console.print("[red]❌ Error: Root privileges required[/red]")
                checks_passed = False
            else:
                self.console.print("[green]✓ Root privileges: OK[/green]")
            
            # Check required tools
            tools = {
                'aircrack-ng': 'Aircrack-ng suite',
                'iwconfig': 'Wireless tools',
                'reaver': 'Reaver WPS tool',
                'wash': 'WPS scanning tool'
            }
            
            for tool, description in tools.items():
                if subprocess.run(['which', tool], stdout=subprocess.DEVNULL).returncode == 0:
                    self.console.print(f"[green]✓ {description} ({tool}): OK[/green]")
                else:
                    self.console.print(f"[red]❌ {description} ({tool}): Not found[/red]")
                    checks_passed = False
            
            # Check wireless interfaces
            interfaces = []
            result = subprocess.run(['iwconfig'], capture_output=True, text=True)
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'IEEE 802.11' in line:
                        iface = line.split()[0]
                        interfaces.append(iface)
                        
                        # Check interface capabilities
                        self.console.print(f"\n[cyan]Checking capabilities for {iface}:[/cyan]")
                        
                        # Check monitor mode support
                        monitor_support = False
                        iw_info = subprocess.run(['iwconfig', iface], capture_output=True, text=True)
                        if 'Mode:Monitor' in iw_info.stdout or 'Mode:Auto' in iw_info.stdout:
                            monitor_support = True
                        
                        if monitor_support:
                            self.console.print(f"[green]✓ {iface} supports monitor mode[/green]")
                        else:
                            self.console.print(f"[yellow]⚠ {iface} monitor mode support unclear[/yellow]")
                        
                        # Check supported bands and channels
                        try:
                            iw_info = subprocess.run(['iwlist', iface, 'frequency'], capture_output=True, text=True)
                            if '2.4 GHz' in iw_info.stdout:
                                self.console.print(f"[green]✓ {iface} supports 2.4 GHz band[/green]")
                            if '5.0 GHz' in iw_info.stdout:
                                self.console.print(f"[green]✓ {iface} supports 5 GHz band[/green]")
                        except:
                            self.console.print(f"[yellow]⚠ Could not determine frequency bands for {iface}[/yellow]")
                        
                        # Check TX power capabilities
                        try:
                            iw_info = subprocess.run(['iwlist', iface, 'txpower'], capture_output=True, text=True)
                            if 'Current Tx-Power' in iw_info.stdout:
                                self.console.print(f"[green]✓ {iface} supports TX power adjustment[/green]")
                        except:
                            self.console.print(f"[yellow]⚠ Could not determine TX power capabilities for {iface}[/yellow]")
                
                if interfaces:
                    self.console.print(f"\n[green]✓ Found {len(interfaces)} wireless interface(s)[/green]")
                else:
                    self.console.print("[red]❌ No wireless interfaces found![/red]")
                    self.console.print("[yellow]Please connect a compatible wireless adapter[/yellow]")
                    checks_passed = False
            else:
                self.console.print("[red]❌ Error checking wireless interfaces[/red]")
                checks_passed = False
            
            # Check workspace directories
            if self.directories:
                self.console.print("[green]✓ Workspace directories: OK[/green]")
            else:
                self.console.print("[red]❌ Error with workspace directories[/red]")
                checks_passed = False
            
            # Final verdict
            if checks_passed:
                self.console.print("\n[green]✓ All system checks passed! System is ready.[/green]")
                log_activity("System check completed - All checks passed")
                return True
            else:
                self.console.print("\n[red]❌ Some system checks failed. Please address the issues above.[/red]")
                log_activity("System check completed - Some checks failed")
                return False
                
        except Exception as e:
            self.console.print(f"[red]Error during system check: {str(e)}[/red]")
            return False

    def system_check(self):
        """Menu option for system check"""
        self.perform_system_check()
        input("\nPress Enter to continue...")

    def clean_workspace(self):
        """Clean up all created files"""
        try:
            keep_logs = Prompt.ask(
                "\n[yellow]Do you want to keep the log files?[/yellow]",
                choices=["y", "n"],
                default="y"
            ) == "y"
            
            cleanup_workspace(keep_logs)
            log_activity("Workspace cleaned" + (" (kept logs)" if keep_logs else ""))
            
        except Exception as e:
            self.console.print(f"[red]Error during cleanup: {str(e)}[/red]")
        
        input("\nPress Enter to continue...")

    def network_scan(self):
        """Start network scanning"""
        try:
            # Check wireless tools first
            if not check_wireless_tools():
                return

            scanner = NetworkScanner()
            scanner.start_scan()
            log_activity("Network scan completed")
        except Exception as e:
            self.console.print(f"[red]Error in network scanner: {str(e)}[/red]")

    def deauth_attack(self):
        """Start deauthentication attack"""
        try:
            # Check wireless tools first
            if not check_wireless_tools():
                return

            deauther = DeauthAttacker()
            deauther.start_attack()
            log_activity(f"Deauth attack completed - Target: {deauther.target_bssid if deauther.target_bssid else 'Unknown'}")
        except Exception as e:
            self.console.print(f"[red]Error in deauth attack: {str(e)}[/red]")

    def wps_attack(self):
        """Start WPS security analysis"""
        try:
            # Check wireless tools first
            if not check_wireless_tools():
                return

            wps = WPSAttacker()
            wps.start_attack()
            log_activity(f"WPS attack completed - Target: {wps.target_bssid if wps.target_bssid else 'Unknown'}")
        except Exception as e:
            self.console.print(f"[red]Error in WPS attack: {str(e)}[/red]")

    def capture_handshake(self):
        """Start handshake capture"""
        try:
            # Check wireless tools first
            if not check_wireless_tools():
                return

            handshake = HandshakeCapture()
            handshake.start_capture()
            log_activity(f"Handshake capture completed - Target: {handshake.target_essid if handshake.target_essid else 'Unknown'}")
        except Exception as e:
            self.console.print(f"[red]Error in handshake capture: {str(e)}[/red]")

    def view_history(self):
        """View session history and captured data"""
        try:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            data_dir = os.path.join(base_dir, 'data')
            
            # Create a table for history display
            table = Table(title="Session History")
            table.add_column("Date/Time", style="cyan")
            table.add_column("Module", style="green")
            table.add_column("Activity", style="yellow")
            
            # Read from activity log
            log_file = os.path.join(data_dir, 'logs', 'activity.log')
            if os.path.exists(log_file):
                with open(log_file, 'r') as f:
                    for line in f:
                        if line.strip():
                            try:
                                # Parse log line
                                timestamp = line[1:20]  # Extract timestamp
                                message = line[22:].strip()  # Extract message
                                
                                # Determine module from message
                                module = "Unknown"
                                if "network scan" in message.lower():
                                    module = "Network Scanner"
                                elif "deauth" in message.lower():
                                    module = "Deauthentication"
                                elif "wps" in message.lower():
                                    module = "WPS Analysis"
                                elif "handshake" in message.lower():
                                    module = "Handshake Capture"
                                
                                table.add_row(timestamp, module, message)
                            except:
                                continue
                
                self.console.print(table)
            else:
                self.console.print("[yellow]No history found.[/yellow]")
                
            # Display captured data summary
            self.console.print("\n[cyan]Captured Data Summary:[/cyan]")
            
            # Check handshakes
            handshake_dir = os.path.join(data_dir, 'handshakes')
            if os.path.exists(handshake_dir):
                handshakes = len([f for f in os.listdir(handshake_dir) if f.endswith('.cap')])
                self.console.print(f"[green]Handshakes captured:[/green] {handshakes}")
            
            # Check WPS results
            wps_dir = os.path.join(data_dir, 'wps')
            if os.path.exists(wps_dir):
                wps_results = len([f for f in os.listdir(wps_dir) if f.endswith('.txt')])
                self.console.print(f"[green]WPS analysis results:[/green] {wps_results}")
            
            # Check network scans
            scans_dir = os.path.join(data_dir, 'scans')
            if os.path.exists(scans_dir):
                scans = len([f for f in os.listdir(scans_dir) if f.endswith('.txt')])
                self.console.print(f"[green]Network scans:[/green] {scans}")
            
            input("\nPress Enter to continue...")
            
        except Exception as e:
            self.console.print(f"[red]Error viewing history: {str(e)}[/red]")

    def exit_program(self):
        self.console.print("[yellow]Cleaning up and exiting...[/yellow]")
        # Cleanup any leftover processes
        os.system('pkill aircrack-ng 2>/dev/null')
        os.system('pkill airodump-ng 2>/dev/null')
        os.system('pkill aireplay-ng 2>/dev/null')
        log_activity("Toolkit session ended")
        sys.exit(0)

    def display_banner(self):
        """Display the toolkit banner"""
        banner = """
═══════════════════════════════════════════════════════════════════════════
███████╗ ██████╗██╗  ██╗ ██████╗ ██╗    ██╗██████╗  █████╗ ██╗████████╗██╗  ██╗
██╔════╝██╔════╝██║  ██║██╔═══██╗██║    ██║██╔══██╗██╔══██╗██║╚══██╔══╝██║  ██║
█████╗  ██║     ███████║██║   ██║██║ █╗ ██║██████╔╝███████║██║   ██║   ███████║
██╔══╝  ██║     ██╔══██║██║   ██║██║███╗██║██╔══██╗██╔══██║██║   ██║   ██╔══██║
███████╗╚██████╗██║  ██║╚██████╔╝╚███╔███╔╝██║  ██║██║  ██║██║   ██║   ██║  ██║
╚══════╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝
═══════════════════════════════════════════════════════════════════════════
        """
        self.console.print(Panel(banner, style="cyan"))
        self.console.print("[cyan][ Spectral WiFi Security Framework ][/cyan]")
        self.console.print("[red]For educational purposes and authorized testing only[/red]\n")

    def display_menu(self):
        """Display the main menu"""
        table = Table(title="Available Modules")
        table.add_column("Option", style="cyan", justify="center")
        table.add_column("Module", style="green")
        table.add_column("Description", style="yellow")

        for key, (name, _, description) in self.modules.items():
            table.add_row(key, name, description)

        self.console.print(table)

    def run(self):
        """Main program loop"""
        if os.geteuid() != 0:
            self.console.print("[red]Please run EchoWraith with root privileges[/red]")
            sys.exit(1)

        self.display_banner()
        
        # Perform mandatory system check at startup
        if not self.perform_system_check():
            self.console.print("\n[red]Critical system requirements not met. Please fix the issues and try again.[/red]")
            sys.exit(1)
        
        while True:
            try:
                self.display_menu()
                choice = Prompt.ask(
                    "\n[bold cyan]Select a module[/bold cyan]",
                    choices=list(self.modules.keys()),
                    show_choices=False
                )
                
                module_name, module_func, _ = self.modules[choice]
                self.console.print(f"\n[bold green]Running {module_name}...[/bold green]")
                
                module_func()
                
                if choice != '8':  # If not exit
                    input("\nPress Enter to continue...")
                
            except KeyboardInterrupt:
                self.console.print("\n[yellow]Operation cancelled by user[/yellow]")
                log_activity("Operation cancelled by user")
                continue
            except Exception as e:
                self.console.print(f"[red]Error: {str(e)}[/red]")
                log_activity(f"Error occurred: {str(e)}")
                continue

if __name__ == "__main__":
    try:
        toolkit = EchoWraith()
        toolkit.run()
    except KeyboardInterrupt:
        console.print("\n[yellow]Exiting WiFi Toolkit...[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]Fatal error: {str(e)}[/red]")
        sys.exit(1) 