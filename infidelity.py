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
from modules.utils import setup_workspace, cleanup_workspace, log_activity

console = Console()

class Infidelity:
    def __init__(self):
        self.console = Console()
        self.modules = {
            '1': ('Network Scanner', self.network_scan, 'Discover and analyze nearby WiFi networks'),
            '2': ('Deauthentication', self.deauth_attack, 'Disconnect clients from target networks'),
            '3': ('WPS Analysis', self.wps_attack, 'Test WPS security'),
            '4': ('Handshake Capture', self.capture_handshake, 'Capture and analyze WPA/WPA2 handshakes'),
            '5': ('View History', self.view_history, 'View previous session results'),
            '6': ('System Check', self.system_check, 'Check system requirements'),
            '7': ('Clean Workspace', self.clean_workspace, 'Delete all created files and directories'),
            '8': ('Exit', self.exit_program, 'Exit Infidelity')
        }
        self.directories = setup_workspace()
        if not self.directories:
            console.print("[red]Failed to setup workspace. Some features may not work correctly.[/red]")

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
        try:
            scanner = NetworkScanner()
            scanner.start_scan()
            log_activity("Completed network scan")
        except Exception as e:
            self.console.print(f"[red]Error in network scanner: {str(e)}[/red]")

    def deauth_attack(self):
        try:
            deauther = DeauthAttacker()
            deauther.start_attack()
            log_activity(f"Deauth attack completed - Target: {deauther.target_bssid if deauther.target_bssid else 'Unknown'}")
        except Exception as e:
            self.console.print(f"[red]Error in deauth attack: {str(e)}[/red]")

    def wps_attack(self):
        try:
            wps = WPSAttacker()
            wps.start_attack()
            log_activity(f"WPS attack completed - Target: {wps.target_bssid if wps.target_bssid else 'Unknown'}")
        except Exception as e:
            self.console.print(f"[red]Error in WPS attack: {str(e)}[/red]")

    def capture_handshake(self):
        try:
            handshake = HandshakeCapture()
            handshake.start_capture()
            log_activity(f"Handshake capture completed - Target: {handshake.target_essid if handshake.target_essid else 'Unknown'}")
        except Exception as e:
            self.console.print(f"[red]Error in handshake capture: {str(e)}[/red]")

    def view_history(self):
        """View session history from log file"""
        try:
            log_file = os.path.join(self.directories['logs'], 'activity.log')
            
            if not os.path.exists(log_file):
                self.console.print("[yellow]No history found.[/yellow]")
                return

            with open(log_file, 'r') as f:
                history = f.readlines()

            if not history:
                self.console.print("[yellow]History is empty.[/yellow]")
                return

            table = Table(title="Session History")
            table.add_column("Timestamp", style="cyan")
            table.add_column("Activity", style="yellow")

            for entry in history[-20:]:  # Show last 20 entries
                try:
                    timestamp = entry[1:20]
                    activity = entry[22:].strip()
                    table.add_row(timestamp, activity)
                except:
                    continue

            self.console.print(table)
            
        except Exception as e:
            self.console.print(f"[red]Error viewing history: {str(e)}[/red]")
        
        input("\nPress Enter to continue...")

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
██╗███╗   ██╗███████╗██╗██████╗ ███████╗██╗     ██╗████████╗██╗   ██╗
██║████╗  ██║██╔════╝██║██╔══██╗██╔════╝██║     ██║╚══██╔══╝╚██╗ ██╔╝
██║██╔██╗ ██║█████╗  ██║██║  ██║█████╗  ██║     ██║   ██║    ╚████╔╝ 
██║██║╚██╗██║██╔══╝  ██║██║  ██║██╔══╝  ██║     ██║   ██║     ╚██╔╝  
██║██║ ╚████║██║     ██║██████╔╝███████╗███████╗██║   ██║      ██║   
╚═╝╚═╝  ╚═══╝╚═╝     ╚═╝╚═════╝ ╚══════╝╚══════╝╚═╝   ╚═╝      ╚═╝   
        """
        self.console.print(Panel(banner, style="cyan"))
        self.console.print("[yellow]Advanced WiFi Security Analysis Platform[/yellow]")
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

    def system_check(self):
        """Check system requirements and dependencies"""
        try:
            self.console.print("\n[cyan]Checking system requirements...[/cyan]")
            
            # Check Python version
            python_version = sys.version_info
            if python_version.major < 3 or (python_version.major == 3 and python_version.minor < 6):
                self.console.print("[red]Error: Python 3.6 or higher is required[/red]")
                return False
            self.console.print("[green]Python version: OK[/green]")
            
            # Check for root privileges
            if os.geteuid() != 0:
                self.console.print("[red]Error: Root privileges required[/red]")
                return False
            self.console.print("[green]Root privileges: OK[/green]")
            
            # Check wireless interfaces
            interfaces = []
            result = subprocess.run(['iwconfig'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'IEEE 802.11' in line:
                    iface = line.split()[0]
                    interfaces.append(iface)
                    self.console.print(f"[green]Found wireless interface: {iface}[/green]")
            
            if not interfaces:
                self.console.print("[red]No wireless interfaces found![/red]")
                self.console.print("[yellow]Please connect a compatible wireless adapter[/yellow]")
            else:
                self.console.print(f"[green]Found {len(interfaces)} wireless interface(s)[/green]")
            
            log_activity("System check completed")
            
        except Exception as e:
            self.console.print(f"[red]Error during system check: {str(e)}[/red]")
        
        input("\nPress Enter to continue...")

    def run(self):
        """Main program loop"""
        while True:
            try:
                self.display_banner()
                self.display_menu()
                
                choice = Prompt.ask(
                    "\n[bold cyan]Select a module[/bold cyan]",
                    choices=list(self.modules.keys()),
                    show_choices=False
                )
                
                module_name, module_func, _ = self.modules[choice]
                self.console.print(f"\n[bold green]Running {module_name}...[/bold green]")
                
                # Check if root before running security modules
                if choice in ['1', '2', '3', '4'] and os.geteuid() != 0:
                    self.console.print("[red]This module requires root privileges. Please run as root.[/red]")
                    input("\nPress Enter to continue...")
                    continue
                
                module_func()
                
                if choice != '8':  # If not exit
                    input("\nPress Enter to continue...")
                
            except KeyboardInterrupt:
                self.console.print("\n[yellow]Operation cancelled by user[/yellow]")
                continue
            except Exception as e:
                self.console.print(f"[red]Error: {str(e)}[/red]")
                continue

if __name__ == "__main__":
    try:
        toolkit = Infidelity()
        toolkit.run()
    except KeyboardInterrupt:
        console.print("\n[yellow]Exiting WiFi Toolkit...[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]Fatal error: {str(e)}[/red]")
        sys.exit(1) 