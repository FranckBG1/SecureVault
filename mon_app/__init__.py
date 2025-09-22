"""
Package SecureVault - Gestionnaire de mots de passe sécurisé
"""

__version__ = '1.0.0'
__author__ = 'SecureVault Team'

from .app import create_app

# Export des principales classes
from .database import DatabaseManager
from .crypto_utils import CryptoManager, PasswordGenerator
from .auth import SessionManager

__all__ = [
    'create_app',
    'DatabaseManager',
    'CryptoManager',
    'PasswordGenerator',
    'SessionManager'
]
