"""
Script principal pour lancer SecureVault en mode web
"""
import os
import sys

# Ajoute le répertoire parent au chemin Python
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app

def main():
    """Point d'entrée principal"""
    # Détermine l'environnement
    env = os.environ.get('FLASK_ENV', 'development')
    
    # Configuration du serveur
    host = os.environ.get('FLASK_HOST', '127.0.0.1')
    port = int(os.environ.get('FLASK_PORT', 5000))
    debug = env == 'development'
    

    try:
        app = create_app(env)
        app.run(host=host, port=port, debug=debug)
    except KeyboardInterrupt:
        print("\n👋 Arrêt de SecureVault")
    except Exception as e:
        print(f"❌ Erreur lors du démarrage: {e}")

if __name__ == '__main__':
    main()
