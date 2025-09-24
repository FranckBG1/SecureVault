"""
Configuration de l'application SecureVault
"""
import os
from datetime import timedelta

class Config:
    """Configuration de base"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'

    # Configuration de la base de données
    DATABASE_PATH = os.environ.get('DATABASE_PATH') or os.path.join(os.path.dirname(__file__), 'data', 'securevault.db')

    # Configuration des sessions - Utilisation des sessions Flask natives (en mémoire)
    SESSION_PERMANENT = False
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)

    # Configuration de sécurité
    AUTO_LOGOUT_TIME = 1800  # 30 minutes en secondes
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
