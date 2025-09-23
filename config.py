"""
Configuration de l'application SecureVault
"""
import os
from datetime import timedelta

class Config:
    """Configuration de base"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'

    # Configuration de la base de données
    DATABASE_PATH = os.path.join(os.path.dirname(__file__), 'securevault.db')

    # Configuration des sessions
    SESSION_TYPE = 'filesystem'
    SESSION_PERMANENT = False
    SESSION_USE_SIGNER = True
    SESSION_KEY_PREFIX = 'securevault:'
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)

    # Configuration de sécurité
    AUTO_LOGOUT_TIME = 300  # 5 minutes en secondes
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION = 300  # 5 minutes en secondes

    # Configuration du générateur de mots de passe
    DEFAULT_PASSWORD_LENGTH = 16
    PASSWORD_MIN_LENGTH = 8
    PASSWORD_MAX_LENGTH = 128

class DevelopmentConfig(Config):
    """Configuration pour le développement"""
    DEBUG = True

class ProductionConfig(Config):
    """Configuration pour la production"""
    DEBUG = False

    def __init__(self):
        # Vérification de la SECRET_KEY uniquement lors de l'instanciation
        secret_key = os.environ.get('SECRET_KEY')
        if not secret_key:
            raise ValueError("No SECRET_KEY set for production environment")
        self.SECRET_KEY = secret_key

# Configuration par défaut
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
