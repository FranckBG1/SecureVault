"""
Lance SecureVault en mode application desktop (fenêtre native)
"""
import os
import threading
import socket
import time
import webview
from app import create_app


def find_free_port():
    """Trouve un port libre sur localhost"""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    _, port = s.getsockname()
    s.close()
    return port


def run_flask(app, host, port, debug):
    """Lance Flask en thread"""
    app.run(host=host, port=port, debug=debug, threaded=True, use_reloader=False)


if __name__ == "__main__":
    # Environnement
    env = os.environ.get("FLASK_ENV", "production")
    host = "127.0.0.1"  # ⚠️ rester en local uniquement
    port = find_free_port()
    debug = env == "development"

    # Crée l'app Flask
    app = create_app(env)

    # Lance Flask en arrière-plan
    t = threading.Thread(target=run_flask, args=(app, host, port, debug), daemon=True)
    t.start()

    # Petite pause pour que Flask démarre
    time.sleep(1)

    # Fenêtre desktop
    webview.create_window("🔐 SecureVault", f"http://{host}:{port}")
    webview.start()
