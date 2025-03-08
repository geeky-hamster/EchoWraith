#!/usr/bin/env python3

import os
import json
from datetime import datetime
from rich.console import Console
from rich.prompt import Prompt
from .utils import get_data_path
from .interface_manager import InterfaceManager
import subprocess

class SessionManager:
    def __init__(self):
        self.console = Console()
        self.session_data = {
            "selected_interface": None,
            "interface_mode": None,
            "session_id": None
        }
        self.session_file = get_data_path('configs', 'session.json')
        self.load_session()

    def load_session(self):
        """Load session data from file"""
        try:
            if os.path.exists(self.session_file):
                with open(self.session_file, 'r') as f:
                    self.session_data = json.load(f)
        except Exception as e:
            self.console.print(f"[yellow]Warning: Could not load session data: {str(e)}[/yellow]")
            self.session_data = {
                "selected_interface": None,
                "interface_mode": None,
                "session_id": None
            }

    def save_session(self):
        """Save session data to file"""
        try:
            os.makedirs(os.path.dirname(self.session_file), exist_ok=True)
            with open(self.session_file, 'w') as f:
                json.dump(self.session_data, f, indent=4)
        except Exception as e:
            self.console.print(f"[yellow]Warning: Could not save session data: {str(e)}[/yellow]")

    def get(self, key, default=None):
        """Get a value from the session"""
        return self.session_data.get(key, default)

    def set(self, key, value):
        """Set a value in the session"""
        self.session_data[key] = value
        self.save_session()

    def clear(self):
        """Clear all session data"""
        self.session_data = {
            "selected_interface": None,
            "interface_mode": None,
            "session_id": None
        }
        self.save_session()

    def remove(self, key):
        """Remove a key from the session"""
        if key in self.session_data:
            del self.session_data[key]
            self.save_session()

    def get_interface(self):
        """Get the currently selected interface"""
        return self.session_data.get("selected_interface")

    def get_interface_mode(self):
        """Get the current interface mode"""
        return self.session_data.get("interface_mode", "managed")

    def select_interface(self):
        """Select wireless interface if not already selected"""
        if self.session_data.get("selected_interface"):
            return self.session_data["selected_interface"]

        interfaces = InterfaceManager.get_available_interfaces()
        if not interfaces:
            self.console.print("[red]No wireless interfaces found! Please ensure your wireless adapter is connected.[/red]")
            self.console.print("[yellow]Available network interfaces:[/yellow]")
            # Show all network interfaces for debugging
            try:
                result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
                self.console.print(result.stdout)
            except Exception as e:
                self.console.print(f"[red]Error listing network interfaces: {str(e)}[/red]")
            return None

        # Display available interfaces
        self.console.print("\n[cyan]Available wireless interfaces:[/cyan]")
        for i, iface in enumerate(interfaces, 1):
            # Get additional info about the interface
            try:
                info = subprocess.run(['iwconfig', iface], capture_output=True, text=True).stdout
                self.console.print(f"{i}. {iface} - {info.split('ESSID:')[0].strip()}")
            except:
                self.console.print(f"{i}. {iface}")

        # Let user select interface
        while True:
            try:
                choice = Prompt.ask(
                    "\n[yellow]Select interface number[/yellow]",
                    choices=[str(i) for i in range(1, len(interfaces) + 1)]
                )
                selected_interface = interfaces[int(choice) - 1]
                self.session_data["selected_interface"] = selected_interface
                self.session_data["interface_mode"] = "managed"  # Default to managed mode
                self.save_session()
                
                # Verify the interface exists and is accessible
                try:
                    subprocess.run(['iwconfig', selected_interface], check=True, capture_output=True)
                    self.console.print(f"[green]Successfully selected interface: {selected_interface}[/green]")
                    return selected_interface
                except subprocess.CalledProcessError:
                    self.console.print(f"[red]Error: Could not access interface {selected_interface}[/red]")
                    self.session_data["selected_interface"] = None
                    self.save_session()
                    return None
                    
            except (ValueError, IndexError):
                self.console.print("[red]Invalid selection. Please try again.[/red]")
            except Exception as e:
                self.console.print(f"[red]Error selecting interface: {str(e)}[/red]")
                return None

    def set_interface_mode(self, mode):
        """Set the interface mode (monitor/managed)"""
        if mode not in ["monitor", "managed"]:
            self.console.print("[red]Invalid interface mode. Must be 'monitor' or 'managed'.[/red]")
            return
        self.session_data["interface_mode"] = mode
        self.save_session()

    def clear_session(self):
        """Clear the current session data"""
        self.clear()
        if os.path.exists(self.session_file):
            try:
                os.remove(self.session_file)
            except Exception as e:
                self.console.print(f"[yellow]Warning: Could not remove session file: {str(e)}[/yellow]")

# Create a global session instance
session = SessionManager() 