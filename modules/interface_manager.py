#!/usr/bin/env python3

import subprocess
import time
import os
from rich.console import Console
from rich.table import Table

console = Console()

class InterfaceManager:
    @staticmethod
    def get_available_interfaces():
        """Get list of available wireless interfaces"""
        try:
            interfaces = []
            
            # Method 1: Using iwconfig
            result = subprocess.run(['iwconfig'], capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'IEEE 802.11' in line:
                        interface = line.split()[0]
                        interfaces.append(interface)
            
            # Method 2: Check /sys/class/net for wireless devices
            if not interfaces:
                for iface in os.listdir('/sys/class/net'):
                    if os.path.exists(f'/sys/class/net/{iface}/wireless'):
                        interfaces.append(iface)
            
            return interfaces
        except Exception as e:
            console.print(f"[red]Error getting wireless interfaces: {str(e)}[/red]")
            return []

    @staticmethod
    def get_current_interface():
        """Get the currently selected interface from session"""
        from .session_manager import session
        return session.get('selected_interface')

    @staticmethod
    def set_current_interface(interface):
        """Set the current interface in session"""
        from .session_manager import session
        session.set('selected_interface', interface)
        session.set('interface_mode', 'managed')  # Default to managed mode

    @staticmethod
    def get_interface_mode():
        """Get current interface mode from session"""
        from .session_manager import session
        return session.get('interface_mode', 'managed')

    @staticmethod
    def set_interface_mode(mode):
        """Set current interface mode in session"""
        from .session_manager import session
        session.set('interface_mode', mode)

    @staticmethod
    def ensure_monitor_mode():
        """Ensure interface is in monitor mode"""
        interface = InterfaceManager.get_current_interface()
        if not interface:
            return False

        try:
            # Kill interfering processes
            subprocess.run(['airmon-ng', 'check', 'kill'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1)

            # Check if already in monitor mode
            if InterfaceManager.get_interface_mode() == 'monitor':
                return True

            # Try multiple methods to enable monitor mode
            methods = [
                ['airmon-ng', 'start', interface],
                ['iw', 'dev', interface, 'set', 'monitor', 'none'],
                ['iwconfig', interface, 'mode', 'monitor']
            ]

            for method in methods:
                try:
                    subprocess.run(method, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    time.sleep(2)
                    
                    # Verify monitor mode
                    result = subprocess.run(['iwconfig', interface], capture_output=True, text=True)
                    if 'Mode:Monitor' in result.stdout:
                        InterfaceManager.set_interface_mode('monitor')
                        return True
                except:
                    continue

            # If all methods failed, try with mon suffix
            mon_interface = interface + 'mon'
            if os.path.exists(f'/sys/class/net/{mon_interface}'):
                InterfaceManager.set_current_interface(mon_interface)
                InterfaceManager.set_interface_mode('monitor')
                return True

            console.print("[red]Failed to enable monitor mode.[/red]")
            return False

        except Exception as e:
            console.print(f"[red]Error setting up monitor mode: {str(e)}[/red]")
            return False

    @staticmethod
    def ensure_managed_mode():
        """Ensure interface is in managed mode"""
        interface = InterfaceManager.get_current_interface()
        if not interface:
            return False

        try:
            # If already in managed mode, nothing to do
            if InterfaceManager.get_interface_mode() == 'managed':
                return True

            console.print(f"[cyan]Current interface: {interface}[/cyan]")

            # Kill interfering processes more thoroughly
            subprocess.run(['airmon-ng', 'check', 'kill'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['pkill', 'wpa_supplicant'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['pkill', 'NetworkManager'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(2)

            # If interface name ends with 'mon', try to use base name first
            original_interface = interface
            if interface.endswith('mon'):
                base_interface = interface[:-3]
                # Check if base interface exists
                if os.path.exists(f'/sys/class/net/{base_interface}'):
                    interface = base_interface
                    InterfaceManager.set_current_interface(base_interface)
                    console.print(f"[cyan]Using base interface: {base_interface}[/cyan]")

            # First attempt: Stop monitor mode with airmon-ng
            try:
                subprocess.run(['airmon-ng', 'stop', original_interface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                time.sleep(2)
            except:
                pass

            # Second attempt: Try with the current interface name
            try:
                subprocess.run(['airmon-ng', 'stop', interface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                time.sleep(2)
            except:
                pass

            # Check available interfaces after stopping monitor mode
            available = InterfaceManager.get_available_interfaces()
            console.print(f"[cyan]Available interfaces after stop: {', '.join(available)}[/cyan]")

            # If base interface is now available, use it
            if interface in available:
                console.print(f"[cyan]Found interface {interface} in available interfaces[/cyan]")
            elif original_interface[:-3] in available:
                interface = original_interface[:-3]
                InterfaceManager.set_current_interface(interface)
                console.print(f"[cyan]Switching to available interface: {interface}[/cyan]")

            # Try multiple methods to restore managed mode
            methods = [
                ['ip', 'link', 'set', interface, 'down'],
                ['iw', 'dev', interface, 'set', 'type', 'managed'],
                ['ip', 'link', 'set', interface, 'up'],
                ['iwconfig', interface, 'mode', 'managed']
            ]

            for method in methods:
                try:
                    result = subprocess.run(method, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    time.sleep(1)
                    if result.returncode == 0:
                        console.print(f"[cyan]Successfully ran: {' '.join(method)}[/cyan]")
                except Exception as e:
                    console.print(f"[yellow]Failed to run {' '.join(method)}: {str(e)}[/yellow]")

            # Final verification
            try:
                result = subprocess.run(['iwconfig', interface], capture_output=True, text=True)
                if 'Mode:Managed' in result.stdout or 'Mode:Auto' in result.stdout:
                    InterfaceManager.set_interface_mode('managed')
                    console.print(f"[green]Successfully verified managed mode on {interface}[/green]")
                    return True
                else:
                    console.print(f"[yellow]Interface mode after attempts: {result.stdout.split('Mode:')[1].split()[0] if 'Mode:' in result.stdout else 'unknown'}[/yellow]")
            except Exception as e:
                console.print(f"[red]Error verifying interface mode: {str(e)}[/red]")

            console.print("[red]Failed to restore managed mode.[/red]")
            return False

        except Exception as e:
            console.print(f"[red]Error restoring managed mode: {str(e)}[/red]")
            return False

    @staticmethod
    def restore_managed_mode():
        """Restore interface to managed mode"""
        return InterfaceManager.ensure_managed_mode() 