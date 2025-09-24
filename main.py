"""
Script principal pour lancer SecureVault en mode web
"""
import os
import sys

# Ajoute le répertoire parent au chemin Python
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def main():
    """Point d'entrée principal"""
    # Détermine l'environnement
    env = os.environ.get('FLASK_ENV', 'development')
    
    # Configuration du serveur
    host = os.environ.get('FLASK_HOST', '127.0.0.1')
    port = int(os.environ.get('FLASK_PORT', 5000))
    debug = env == 'development'
    
    try:
        # Import de la factory function
        from app import create_app

        # Création de l'application
        app = create_app(env)

        print(f"🚀 Démarrage de SecureVault sur http://{host}:{port}")
        print(f"📊 Environnement: {env}")
        print(f"🔧 Debug: {'Activé' if debug else 'Désactivé'}")

        app.run(host=host, port=port, debug=debug)

    except KeyboardInterrupt:
        print("\n👋 Arrêt de SecureVault")
    except ImportError as e:
        print(f"❌ Erreur d'import: {e}")
        print("💡 Vérifiez que tous les modules requis sont installés")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Erreur lors du démarrage: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
