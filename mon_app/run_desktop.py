# Script pour lancer en mode bureau avec pywebview

import webview
from app import app

if __name__ == '__main__':
    # Créer une fenêtre de bureau avec pywebview
    webview.create_window(
        'Mon Application',
        app,
        width=1200,
        height=800,
        resizable=True
    )
    webview.start(debug=True)
