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

            # Kill interfering processes
            subprocess.run(['airmon-ng', 'check', 'kill'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1)

            # Try multiple methods to restore managed mode
            methods = [
                ['airmon-ng', 'stop', interface],
                ['iw', 'dev', interface, 'set', 'type', 'managed'],
                ['iwconfig', interface, 'mode', 'managed']
            ]

            for method in methods:
                try:
                    subprocess.run(method, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    time.sleep(2)

                    # If interface name ends with 'mon', try to use base name
                    if interface.endswith('mon'):
                        base_interface = interface[:-3]
                        if os.path.exists(f'/sys/class/net/{base_interface}'):
                            InterfaceManager.set_current_interface(base_interface)
                            interface = base_interface

                    # Verify managed mode
                    result = subprocess.run(['iwconfig', interface], capture_output=True, text=True)
                    if 'Mode:Managed' in result.stdout or 'Mode:Auto' in result.stdout:
                        InterfaceManager.set_interface_mode('managed')
                        return True
                except:
                    continue

            console.print("[red]Failed to restore managed mode.[/red]")
            return False

        except Exception as e:
            console.print(f"[red]Error restoring managed mode: {str(e)}[/red]")
            return False

    @staticmethod
    def restore_managed_mode():
        """Restore interface to managed mode"""
        return InterfaceManager.ensure_managed_mode() 