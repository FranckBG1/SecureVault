"""
Module de gestion des sessions pour SecureVault
Gestion de l'authentification et des sessions sécurisées
"""
import secrets
import json
from datetime import datetime, timedelta
from functools import wraps
from flask import session, request, jsonify, current_app
from database import DatabaseManager
from crypto_utils import CryptoManager

class SessionManager:
    """Gestionnaire de sessions sécurisées"""

    def __init__(self, db_manager):
        self.db = db_manager
        self.crypto = CryptoManager()

    def create_session(self, user_id, remember_me=False):
        """Crée une nouvelle session pour l'utilisateur"""
        # Génère un token de session unique
        session_token = secrets.token_urlsafe(32)

        # Durée de la session
        if remember_me:
            expires_at = datetime.now() + timedelta(days=30)
        else:
            expires_at = datetime.now() + timedelta(hours=8)

        # Stocke la session en base
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO sessions (user_id, session_token, expires_at)
                VALUES (?, ?, ?)
            ''', (user_id, session_token, expires_at.isoformat()))
            conn.commit()

        # Configure la session Flask
        session['user_id'] = user_id
        session['session_token'] = session_token
        session['expires_at'] = expires_at.isoformat()
        session['last_activity'] = datetime.now().isoformat()
        session.permanent = remember_me

        return session_token

    def validate_session(self, session_token=None):
        """Valide une session existante"""
        if not session_token:
            session_token = session.get('session_token')

        if not session_token:
            return None

        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT user_id, expires_at FROM sessions 
                WHERE session_token = ? AND expires_at > ?
            ''', (session_token, datetime.now().isoformat()))

            session_data = cursor.fetchone()

            if session_data:
                # Met à jour la dernière activité
                cursor.execute('''
                    UPDATE sessions SET last_activity = ? WHERE session_token = ?
                ''', (datetime.now().isoformat(), session_token))
                conn.commit()

                # Met à jour la session Flask
                session['last_activity'] = datetime.now().isoformat()

                return session_data['user_id']

        return None

    def destroy_session(self, session_token=None):
        """Détruit une session"""
        if not session_token:
            session_token = session.get('session_token')

        if session_token:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM sessions WHERE session_token = ?', (session_token,))
                conn.commit()

        # Nettoie la session Flask
        session.clear()

    def destroy_all_user_sessions(self, user_id):
        """Détruit toutes les sessions d'un utilisateur"""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM sessions WHERE user_id = ?', (user_id,))
            conn.commit()

    def check_session_timeout(self):
        """Vérifie si la session a expiré par inactivité"""
        last_activity = session.get('last_activity')
        if not last_activity:
            return True

        last_activity_time = datetime.fromisoformat(last_activity)
        timeout_duration = timedelta(seconds=current_app.config.get('AUTO_LOGOUT_TIME', 1800))

        return datetime.now() - last_activity_time > timeout_duration

    def get_encryption_key(self, user_id, master_password):
        """Génère la clé de chiffrement pour les données utilisateur"""
        salt = self.db.get_user_salt(user_id)
        if not salt:
            raise ValueError("Utilisateur non trouvé")

        return self.crypto.derive_key(master_password, salt)

def login_required(f):
    """Décorateur pour vérifier l'authentification"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Vérifie si l'utilisateur est connecté
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'error': 'Authentification requise'}), 401

        # Vérifie la validité de la session
        session_manager = SessionManager(current_app.db)
        valid_user_id = session_manager.validate_session()

        if not valid_user_id:
            session.clear()
            return jsonify({'error': 'Session expirée'}), 401

        # Vérifie le timeout d'inactivité
        if session_manager.check_session_timeout():
            session_manager.destroy_session()
            return jsonify({'error': 'Session expirée par inactivité'}), 401

        return f(*args, **kwargs)

    return decorated_function

def get_current_user_id():
    """Récupère l'ID de l'utilisateur actuel"""
    return session.get('user_id')

def require_master_password(f):
    """Décorateur pour vérifier le mot de passe maître pour les opérations sensibles"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        data = request.get_json()
        master_password = data.get('master_password') if data else None

        if not master_password:
            return jsonify({'error': 'Mot de passe maître requis'}), 400

        user_id = get_current_user_id()
        if not user_id:
            return jsonify({'error': 'Authentification requise'}), 401

        # Vérifie le mot de passe maître
        try:
            current_app.db.authenticate_user(
                session.get('username', ''),
                master_password,
                request.remote_addr
            )
        except ValueError:
            return jsonify({'error': 'Mot de passe maître incorrect'}), 401

        # Stocke la clé de chiffrement dans la session temporairement
        session_manager = SessionManager(current_app.db)
        encryption_key = session_manager.get_encryption_key(user_id, master_password)
        request.encryption_key = encryption_key

        return f(*args, **kwargs)

    return decorated_function
