# This file intentionally left mostly empty to avoid circular imports.
# Modules should be imported directly where needed, not through this file.

__version__ = '1.0.0'

# Import interface manager first as it has no dependencies on other modules
from .interface_manager import InterfaceManager

# Then import session manager which depends on interface manager
from .session_manager import session

# Make session and interface manager available to all modules
__all__ = ['session', 'InterfaceManager'] 