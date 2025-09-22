# Script pour lancer en mode bureau avec pywebview

import webview
from .app import create_app

if __name__ == '__main__':
    # Créer l'application Flask
    app = create_app('development')

    # Créer une fenêtre de bureau avec pywebview
    webview.create_window(
        'SecureVault - Gestionnaire de Mots de Passe',
        app,
        width=1200,
        height=800,
        min_size=(800, 600),
        resizable=True
    )

    webview.start(debug=True)
