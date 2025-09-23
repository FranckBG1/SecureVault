"""
Module de gestion de la base de données pour SecureVault
Gestion SQLite avec chiffrement des données sensibles
"""
import sqlite3
import json
import os
from datetime import datetime, timedelta
from contextlib import contextmanager
from crypto_utils import CryptoManager


class DatabaseManager:
    """Gestionnaire de base de données pour SecureVault"""

    def __init__(self, db_path):
        self.db_path = db_path
        self.crypto = CryptoManager()
        self.init_database()

    def init_database(self):
        """Initialise la base de données avec les tables nécessaires"""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Table des utilisateurs (mot de passe maître)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    master_password_hash TEXT NOT NULL,
                    salt BLOB NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    failed_attempts INTEGER DEFAULT 0,
                    locked_until TIMESTAMP NULL
                )
            ''')

            # Table des mots de passe stockés
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    url TEXT,
                    username TEXT,
                    password_encrypted TEXT NOT NULL,
                    notes_encrypted TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_used TIMESTAMP,
                    tags TEXT,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                )
            ''')

            # Table des sessions
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    session_token TEXT UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                )
            ''')

            # Table des tentatives de connexion
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS login_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    ip_address TEXT,
                    success BOOLEAN NOT NULL,
                    attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Index pour améliorer les performances
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_passwords_user_id ON passwords(user_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_passwords_url ON passwords(url)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(session_token)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)')

            conn.commit()

    @contextmanager
    def get_connection(self):
        """Context manager pour les connexions à la base de données"""
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def create_user(self, username, master_password):
        """Crée un nouvel utilisateur"""
        # Génère le sel et hash le mot de passe maître
        salt = self.crypto.generate_salt()
        password_hash = self.crypto.hash_master_password(master_password)

        with self.get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    'INSERT INTO users (username, master_password_hash, salt) VALUES (?, ?, ?)',
                    (username, password_hash, salt)
                )
                conn.commit()
                return cursor.lastrowid
            except sqlite3.IntegrityError:
                raise ValueError("Nom d'utilisateur déjà existant")

    def authenticate_user(self, username, master_password, ip_address=None):
        """Authentifie un utilisateur"""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Vérifie si l'utilisateur existe
            cursor.execute(
                'SELECT id, master_password_hash, failed_attempts, locked_until FROM users WHERE username = ?',
                (username,)
            )
            user = cursor.fetchone()

            if not user:
                self._log_login_attempt(conn, username, False, ip_address)
                raise ValueError("Nom d'utilisateur ou mot de passe incorrect")

            # Vérifie si le compte est verrouillé
            if user['locked_until'] and datetime.now() < datetime.fromisoformat(user['locked_until']):
                raise ValueError("Compte temporairement verrouillé")

            # Vérifie le mot de passe
            if self.crypto.verify_master_password(master_password, user['master_password_hash']):
                # Réinitialise les tentatives échouées
                cursor.execute(
                    'UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = ? WHERE id = ?',
                    (datetime.now().isoformat(), user['id'])
                )
                self._log_login_attempt(conn, username, True, ip_address)
                conn.commit()
                return user['id']
            else:
                # Incrémente les tentatives échouées
                failed_attempts = user['failed_attempts'] + 1
                locked_until = None

                if failed_attempts >= 5:
                    locked_until = (datetime.now() + timedelta(minutes=5)).isoformat()

                cursor.execute(
                    'UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?',
                    (failed_attempts, locked_until, user['id'])
                )
                self._log_login_attempt(conn, username, False, ip_address)
                conn.commit()
                raise ValueError("Nom d'utilisateur ou mot de passe incorrect")

    def _log_login_attempt(self, conn, username, success, ip_address):
        """Enregistre une tentative de connexion"""
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO login_attempts (username, ip_address, success) VALUES (?, ?, ?)',
            (username, ip_address, success)
        )

    def get_user_salt(self, user_id):
        """Récupère le sel de l'utilisateur pour la dérivation de clé"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT salt FROM users WHERE id = ?', (user_id,))
            result = cursor.fetchone()
            return result['salt'] if result else None

    def add_password(self, user_id, title, url, username, password, notes="", tags=None, encryption_key=None):
        """Ajoute un nouveau mot de passe"""
        if not encryption_key:
            raise ValueError("Clé de chiffrement requise")

        # Chiffre le mot de passe et les notes
        encrypted_password = self.crypto.encrypt_data(password, encryption_key)
        encrypted_notes = self.crypto.encrypt_data(notes, encryption_key) if notes else ""

        tags_json = json.dumps(tags) if tags else "[]"

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO passwords (user_id, title, url, username, password_encrypted, notes_encrypted, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (user_id, title, url, username, encrypted_password, encrypted_notes, tags_json))
            conn.commit()
            return cursor.lastrowid

    def get_passwords(self, user_id, search_term=None):
        """Récupère tous les mots de passe d'un utilisateur"""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            query = '''
                SELECT id, title, url, username, password_encrypted, notes_encrypted,
                       created_at, updated_at, last_used, tags
                FROM passwords
                WHERE user_id = ?
            '''
            params = [user_id]

            if search_term:
                query += ' AND (title LIKE ? OR url LIKE ? OR username LIKE ?)'
                search_pattern = f'%{search_term}%'
                params.extend([search_pattern, search_pattern, search_pattern])

            query += ' ORDER BY title'

            cursor.execute(query, params)
            return cursor.fetchall()

    def get_password_by_id(self, password_id, user_id):
        """Récupère un mot de passe par son ID"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, title, url, username, password_encrypted, notes_encrypted,
                       created_at, updated_at, last_used, tags
                FROM passwords
                WHERE id = ? AND user_id = ?
            ''', (password_id, user_id))
            return cursor.fetchone()

    def update_password(self, password_id, user_id, title=None, url=None, username=None,
                        password=None, notes=None, tags=None, encryption_key=None):
        """Met à jour un mot de passe"""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Récupère l'enregistrement actuel
            current = self.get_password_by_id(password_id, user_id)
            if not current:
                raise ValueError("Mot de passe non trouvé")

            # Prépare les valeurs à mettre à jour
            updates = []
            params = []

            if title is not None:
                updates.append('title = ?')
                params.append(title)

            if url is not None:
                updates.append('url = ?')
                params.append(url)

            if username is not None:
                updates.append('username = ?')
                params.append(username)

            if password is not None and encryption_key:
                encrypted_password = self.crypto.encrypt_data(password, encryption_key)
                updates.append('password_encrypted = ?')
                params.append(encrypted_password)

            if notes is not None and encryption_key:
                encrypted_notes = self.crypto.encrypt_data(notes, encryption_key)
                updates.append('notes_encrypted = ?')
                params.append(encrypted_notes)

            if tags is not None:
                updates.append('tags = ?')
                params.append(json.dumps(tags))

            if updates:
                updates.append('updated_at = ?')
                params.append(datetime.now().isoformat())
                params.append(password_id)
                params.append(user_id)

                query = f'UPDATE passwords SET {", ".join(updates)} WHERE id = ? AND user_id = ?'
                cursor.execute(query, params)
                conn.commit()
                return cursor.rowcount > 0

        return False

    def delete_password(self, password_id, user_id):
        """Supprime un mot de passe"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM passwords WHERE id = ? AND user_id = ?', (password_id, user_id))
            conn.commit()
            return cursor.rowcount > 0

    def update_last_used(self, password_id, user_id):
        """Met à jour la date de dernière utilisation"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE passwords SET last_used = ? WHERE id = ? AND user_id = ?',
                (datetime.now().isoformat(), password_id, user_id)
            )
            conn.commit()

    def get_password_stats(self, user_id):
        """Récupère les statistiques des mots de passe"""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Total des mots de passe
            cursor.execute('SELECT COUNT(*) as total FROM passwords WHERE user_id = ?', (user_id,))
            total = cursor.fetchone()['total']

            # Mots de passe récemment utilisés (7 derniers jours)
            week_ago = (datetime.now() - timedelta(days=7)).isoformat()
            cursor.execute(
                'SELECT COUNT(*) as recent FROM passwords WHERE user_id = ? AND last_used >= ?',
                (user_id, week_ago)
            )
            recent = cursor.fetchone()['recent']

            # Mots de passe jamais utilisés
            cursor.execute(
                'SELECT COUNT(*) as never_used FROM passwords WHERE user_id = ? AND last_used IS NULL',
                (user_id,)
            )
            never_used = cursor.fetchone()['never_used']

            return {
                'total': total,
                'recent_used': recent,
                'never_used': never_used
            }

    def cleanup_old_sessions(self):
        """Nettoie les sessions expirées"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'DELETE FROM sessions WHERE expires_at < ?',
                (datetime.now().isoformat(),)
            )
            conn.commit()

    def cleanup_old_login_attempts(self, days=30):
        """Nettoie les anciennes tentatives de connexion"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
            cursor.execute(
                'DELETE FROM login_attempts WHERE attempted_at < ?',
                (cutoff_date,)
            )
            conn.commit()

    def get_user_info(self, user_id):
        """Récupère les informations de l'utilisateur"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT username, created_at, last_login FROM users WHERE id = ?', (user_id, ))
            return cursor.fetchone()
    def change_username(self, user_id, new_username):
        """Change le nom d'utilisateur"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET username = ? WHERE id = ?', (new_username, user_id))
            conn.commit()
    def delete_account(self, user_id):
        """Supprime un compte et toutes ses données associées"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Vérifie que l'utilisateur existe
            cursor.execute('SELECT id FROM users WHERE id = ?', (user_id,))
            if not cursor.fetchone():
                raise ValueError("Utilisateur non trouvé")
            
            # Supprime explicitement les données liées (même si CASCADE devrait le faire)
            cursor.execute('DELETE FROM sessions WHERE user_id = ?', (user_id,))
            cursor.execute('DELETE FROM passwords WHERE user_id = ?', (user_id,))
            
            # Supprime l'utilisateur
            cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
            
            # Vérifie que la suppression a réussi
            if cursor.rowcount == 0:
                raise ValueError("Erreur lors de la suppression")
            
            conn.commit()
            return True
    def change_password(self, user_id, new_password):
        """Change le mot de passe"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            salt = self.crypto.generate_salt()
            hashed_password = self.crypto.hash_master_password(new_password)
            cursor.execute('UPDATE users SET master_password_hash = ?, salt = ? WHERE id = ?', (hashed_password, salt, user_id))
            conn.commit()