"""
Application Flask principale pour SecureVault
Gestionnaire de mots de passe sécurisé avec chiffrement AES-256
"""
import json
import os
from datetime import datetime, timedelta

from flask import Flask, request, jsonify, session, render_template, flash, redirect
from flask_session import Session
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Regexp
from markupsafe import escape

# Imports des modules avancés
from auth import SessionManager, login_required, get_current_user_id, require_master_password
from config import config
from crypto_utils import PasswordGenerator, CryptoManager
from database import DatabaseManager
from functools import wraps
from collections import defaultdict
import time


# Rate limiting simple
rate_limit_storage = defaultdict(list)

def rate_limit(max_requests=5, window=300):  # 5 requêtes par 5 minutes
    """Décorateur de rate limiting"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = request.remote_addr
            now = time.time()
            
            # Nettoie les anciennes requêtes
            rate_limit_storage[client_ip] = [
                req_time for req_time in rate_limit_storage[client_ip] 
                if now - req_time < window
            ]
            
            # Vérifie la limite
            if len(rate_limit_storage[client_ip]) >= max_requests:
                return jsonify({'error': 'Trop de tentatives, réessayez plus tard'}), 429
            
            # Enregistre cette requête
            rate_limit_storage[client_ip].append(now)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def login_required_page(f):
    """Décorateur pour les pages web - redirige vers login si non authentifié"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id'):
            return redirect('/login')
        # Valide aussi la session avec le SessionManager
        try:
            session_manager = SessionManager(DatabaseManager(config['default'].DATABASE_PATH))
            if not session_manager.validate_session():
                return redirect('/login')
        except:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function


class LoginForm(FlaskForm):
    username = StringField('Nom d\'utilisateur', validators=[
        DataRequired(message='Nom d\'utilisateur requis'),
        Length(min=3, max=50, message='Le nom d\'utilisateur doit contenir entre 3 et 50 caractères'),
        Regexp(r'^[a-zA-Z0-9_.-]+$', message='Caractères autorisés: lettres, chiffres, _, ., -')
    ])
    password = PasswordField('Mot de passe', validators=[
        DataRequired(message='Mot de passe requis'),
        Length(min=8, message='Le mot de passe doit contenir au moins 8 caractères')
    ])
    submit = SubmitField('Se connecter')


def validate_input(data, field_name, min_length=1, max_length=255, pattern=None, escape_html=True):
    """Validation avancée des entrées utilisateur"""
    if not data or not isinstance(data, str):
        raise ValueError(f'{field_name} requis')
    
    data = data.strip()
    
    if len(data) < min_length:
        raise ValueError(f'{field_name} doit contenir au moins {min_length} caractères')
    if len(data) > max_length:
        raise ValueError(f'{field_name} ne peut pas dépasser {max_length} caractères')
    
    # Vérifie le pattern si fourni
    if pattern:
        import re
        if not re.match(pattern, data):
            raise ValueError(f'{field_name} contient des caractères non autorisés')
    
    # Échappe HTML sauf pour les mots de passe
    if escape_html and 'mot de passe' not in field_name.lower():
        return escape(data)
    return data


def create_app(config_name='default'):
    """Factory pour créer l'application Flask"""
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'votre-clé-secrète'

    # Configuration
    app.config.from_object(config[config_name])

    # Initialisation des extensions
    Session(app)
    # csrf = CSRFProtect(app)  # Temporairement désactivé
    
    # Headers de sécurité
    @app.after_request
    def add_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; font-src 'self' https://cdnjs.cloudflare.com; img-src 'self' data:;"
        return response

    # Initialisation de la base de données
    app.db = DatabaseManager(app.config['DATABASE_PATH'])

    # Initialisation des services
    crypto = CryptoManager()
    password_gen = PasswordGenerator()

    # Routes d'authentification
    @app.route('/api/register', methods=['POST'])
    @rate_limit(max_requests=3, window=600)
    def register():
        """Inscription d'un nouvel utilisateur"""
        data = request.get_json()

        if not data or not data.get('username') or not data.get('master_password'):
            return jsonify({'error': 'Nom d\'utilisateur et mot de passe requis'}), 400

        try:
            username = validate_input(data['username'], 'Nom d\'utilisateur', 3, 50, r'^[a-zA-Z0-9_.-]+$')
            master_password = validate_input(data['master_password'], 'Mot de passe maître', 8, 128, escape_html=False)
        except ValueError as e:
            return jsonify({'error': str(e)}), 400

        try:
            user_id = app.db.create_user(username, master_password)
            return jsonify({
                'message': 'Utilisateur créé avec succès',
                'user_id': user_id
            }), 201
        except ValueError as e:
            return jsonify({'error': str(e)}), 400

    @app.route('/api/login', methods=['POST'])
    @rate_limit(max_requests=5, window=300)
    def login():
        """Connexion utilisateur"""
        data = request.get_json()

        if not data or not data.get('username') or not data.get('master_password'):
            return jsonify({'error': 'Nom d\'utilisateur et mot de passe requis'}), 400

        try:
            username = validate_input(data['username'], 'Nom d\'utilisateur', 3, 50, r'^[a-zA-Z0-9_.-]+$')
            master_password = validate_input(data['master_password'], 'Mot de passe maître', 8, 128, escape_html=False)
            remember_me = bool(data.get('remember_me', False))
        except ValueError as e:
            return jsonify({'error': str(e)}), 400

        try:
            user_id = app.db.authenticate_user(username, master_password, request.remote_addr)

            # Crée la session
            session_manager = SessionManager(app.db)
            session_token = session_manager.create_session(user_id, remember_me)

            # Stocke les informations dans la session Flask
            session['user_id'] = user_id
            session['username'] = username

            return jsonify({
                'message': 'Connexion réussie',
                'session_token': session_token,
                'user_id': user_id
            }), 200
        except ValueError as e:
            return jsonify({'error': str(e)}), 401

    @app.route('/api/logout', methods=['POST'])
    @login_required
    def logout():
        """Déconnexion utilisateur"""
        session_manager = SessionManager(app.db)
        session_manager.destroy_session()
        return jsonify({'message': 'Déconnexion réussie'}), 200

    @app.route('/api/logout-all', methods=['POST'])
    @login_required
    def logout_all():
        """Déconnexion de toutes les sessions"""
        user_id = get_current_user_id()
        session_manager = SessionManager(app.db)
        session_manager.destroy_all_user_sessions(user_id)
        return jsonify({'message': 'Toutes les sessions ont été fermées'}), 200

    @app.route('/api/user-info', methods=['GET'])
    @login_required
    def get_user_info():
        """Récupère les informations de l'utilisateur connecté"""
        user_id = get_current_user_id()
        try:
            user_info = app.db.get_user_info(user_id)
            return jsonify({
                'username': user_info['username'],
                'last_login': user_info['last_login'],
                'created_at': user_info['created_at']
            }), 200
        except Exception:
            return jsonify({'error': 'Erreur lors de la récupération des informations'}), 500
    
    @app.route('/api/change-username', methods=['POST'])
    @login_required
    def change_username():
        """Change le nom d'utilisateur"""
        data = request.get_json()
        
        if not data or not data.get('new_username') or not data.get('master_password'):
            return jsonify({'error': 'Nom d\'utilisateur et mot de passe requis'}), 400
        
        try:
            new_username = validate_input(data['new_username'], 'Nouveau nom d\'utilisateur', 3, 50, r'^[a-zA-Z0-9_.-]+$')
            master_password = validate_input(data['master_password'], 'Mot de passe maître', 8, 128, escape_html=False)
        except ValueError as e:
            return jsonify({'error': str(e)}), 400
        
        user_id = get_current_user_id()
        try:
            # Récupère les infos utilisateur pour vérifier le mot de passe
            user_info = app.db.get_user_info(user_id)
            username = user_info['username']
            
            # Vérifie le mot de passe maître
            app.db.authenticate_user(username, master_password, request.remote_addr)
            
            # Change le nom d'utilisateur
            app.db.change_username(user_id, new_username)
            
            # Met à jour la session
            session['username'] = new_username
            
            return jsonify({'message': 'Nom d\'utilisateur modifié avec succès'}), 200
        except ValueError as e:
            if 'already exists' in str(e).lower():
                return jsonify({'error': 'Ce nom d\'utilisateur est déjà utilisé'}), 400
            return jsonify({'error': 'Mot de passe incorrect'}), 401
        except Exception:
            return jsonify({'error': 'Erreur lors de la modification'}), 500

    @app.route('/api/change-master-password', methods=['POST'])
    @login_required
    def change_master_password():
        """Change le mot de passe maître"""
        data = request.get_json()
        user_id = get_current_user_id()
        
        if not data or not data.get('current_password') or not data.get('new_password'):
            return jsonify({'error': 'Mots de passe requis'}), 400
        
        try:
            current_password = validate_input(data['current_password'], 'Mot de passe actuel', 8, 128, escape_html=False)
            new_password = validate_input(data['new_password'], 'Nouveau mot de passe', 8, 128, escape_html=False)
        except ValueError as e:
            return jsonify({'error': str(e)}), 400
        
        try:
            # Récupère les infos utilisateur pour vérifier le mot de passe
            user_info = app.db.get_user_info(user_id)
            username = user_info['username']
            
            # Vérifie le mot de passe actuel
            app.db.authenticate_user(username, current_password, request.remote_addr)
            
            # Change le mot de passe
            app.db.change_password(user_id, new_password)
            
            # Déconnecte toutes les sessions
            session_manager = SessionManager(app.db)
            session_manager.destroy_all_user_sessions(user_id)
            
            return jsonify({'message': 'Mot de passe maître modifié avec succès'}), 200
        except ValueError:
            return jsonify({'error': 'Mot de passe actuel incorrect'}), 401
        except Exception:
            # Masque les détails techniques pour la sécurité
            return jsonify({'error': 'Erreur lors de la modification du mot de passe'}), 500

    @app.route('/api/delete-account', methods=['DELETE'])
    @login_required
    def delete_account():
        """Supprime le compte utilisateur"""
        user_id = get_current_user_id()
        try:
            # Supprime toutes les sessions de l'utilisateur d'abord
            session_manager = SessionManager(app.db)
            session_manager.destroy_all_user_sessions(user_id)
            
            # Supprime le compte et toutes ses données
            app.db.delete_account(user_id)
            
            # Nettoie la session Flask
            session.clear()
            
            return jsonify({'message': 'Compte supprimé avec succès'}), 200
        except ValueError as e:
            return jsonify({'error': 'Compte non trouvé'}), 404
        except Exception:
            return jsonify({'error': 'Erreur lors de la suppression du compte'}), 500

    @app.route('/api/settings/auto-lock', methods=['POST'])
    @login_required
    def set_auto_lock_time():
        """Configure le temps de verrouillage automatique"""
        data = request.get_json()
        if not data or 'timeout' not in data:
            return jsonify({'error': 'Temps de verrouillage requis'}), 400
        
        timeout_minutes = float(data['timeout'])
        # Convertit en secondes pour la configuration
        timeout_seconds = int(timeout_minutes * 60) if timeout_minutes > 0 else 0
        
        # Stocke dans la session pour cette instance
        session['auto_lock_timeout'] = timeout_seconds
        
        return jsonify({'message': 'Paramètre sauvegardé'}), 200

    @app.route('/api/settings/auto-lock', methods=['GET'])
    @login_required
    def get_auto_lock_time():
        """Récupère le temps de verrouillage automatique"""
        timeout_seconds = session.get('auto_lock_timeout', app.config.get('AUTO_LOGOUT_TIME', 1800))
        timeout_minutes = timeout_seconds / 60 if timeout_seconds > 0 else 0
        return jsonify({'timeout': timeout_minutes}), 200

    # Routes de gestion des mots de passe
    @app.route('/api/passwords', methods=['GET'])
    @login_required
    def get_passwords():
        """Récupère tous les mots de passe de l'utilisateur"""
        user_id = get_current_user_id()
        search_term = request.args.get('search', '')

        passwords = app.db.get_passwords(user_id, search_term if search_term else None)

        # Convertit en format JSON sans déchiffrer les mots de passe
        result = []
        for password in passwords:
            result.append({
                'id': password['id'],
                'title': password['title'],
                'url': password['url'],
                'username': password['username'],
                'created_at': password['created_at'],
                'updated_at': password['updated_at'],
                'last_used': password['last_used'],
                'tags': json.loads(password['tags']) if password['tags'] else []
            })

        return jsonify({'passwords': result}), 200

    @app.route('/api/passwords/<int:password_id>', methods=['GET'])
    @login_required
    def get_password(password_id):
        """Récupère un mot de passe spécifique (déchiffré)"""
        user_id = get_current_user_id()

        # Récupère le mot de passe maître depuis l'en-tête
        master_password = request.headers.get('X-Master-Password')
        if not master_password:
            return jsonify({'error': 'Mot de passe maître requis'}), 400

        password_data = app.db.get_password_by_id(password_id, user_id)
        if not password_data:
            return jsonify({'error': 'Mot de passe non trouvé'}), 404

        try:
            # Génère la clé de chiffrement directement
            session_manager = SessionManager(app.db)
            encryption_key = session_manager.get_encryption_key(user_id, master_password)

            # Déchiffre les données sensibles
            decrypted_password = crypto.decrypt_data(password_data['password_encrypted'], encryption_key)
            decrypted_notes = crypto.decrypt_data(password_data['notes_encrypted'], encryption_key) if password_data['notes_encrypted'] else ""

            # Met à jour la date de dernière utilisation
            app.db.update_last_used(password_id, user_id)

            result = {
                'id': password_data['id'],
                'title': password_data['title'],
                'url': password_data['url'],
                'username': password_data['username'],
                'password': decrypted_password,
                'notes': decrypted_notes,
                'created_at': password_data['created_at'],
                'updated_at': password_data['updated_at'],
                'last_used': password_data['last_used'],
                'tags': json.loads(password_data['tags']) if password_data['tags'] else []
            }

            return jsonify(result), 200
        except ValueError as e:
            return jsonify({'error': 'Mot de passe maître incorrect'}), 401
        except Exception as e:
            return jsonify({'error': f'Erreur de déchiffrement: {str(e)}'}), 500

    @app.route('/api/passwords', methods=['POST'])
    @login_required
    @require_master_password
    def add_password():
        """Ajoute un nouveau mot de passe"""
        data = request.get_json()
        user_id = get_current_user_id()
        encryption_key = request.encryption_key

        # Validation des données requises
        if not data or not data.get('title') or not data.get('password'):
            return jsonify({'error': 'Titre et mot de passe requis'}), 400

        title = data['title'].strip()
        url = data.get('url', '').strip()
        username = data.get('username', '').strip()
        password = data['password']
        notes = data.get('notes', '').strip()
        tags = data.get('tags', [])

        try:
            password_id = app.db.add_password(
                user_id, title, url, username, password, notes, tags, encryption_key
            )
            return jsonify({
                'message': 'Mot de passe ajouté avec succès',
                'password_id': password_id
            }), 201
        except Exception as e:
            return jsonify({'error': f'Erreur lors de l\'ajout: {str(e)}'}), 500

    @app.route('/api/passwords/<int:password_id>', methods=['PUT'])
    @login_required
    @require_master_password
    def update_password(password_id):
        """Met à jour un mot de passe existant"""
        data = request.get_json()
        user_id = get_current_user_id()
        encryption_key = request.encryption_key

        if not data:
            return jsonify({'error': 'Données requises'}), 400

        try:
            success = app.db.update_password(
                password_id, user_id,
                title=data.get('title'),
                url=data.get('url'),
                username=data.get('username'),
                password=data.get('password'),
                notes=data.get('notes'),
                tags=data.get('tags'),
                encryption_key=encryption_key
            )

            if success:
                return jsonify({'message': 'Mot de passe mis à jour avec succès'}), 200
            else:
                return jsonify({'error': 'Mot de passe non trouvé'}), 404
        except Exception as e:
            return jsonify({'error': f'Erreur lors de la mise à jour: {str(e)}'}), 500

    @app.route('/api/passwords/<int:password_id>', methods=['DELETE'])
    @login_required
    def delete_password(password_id):
        """Supprime un mot de passe"""
        user_id = get_current_user_id()

        success = app.db.delete_password(password_id, user_id)
        if success:
            return jsonify({'message': 'Mot de passe supprimé avec succès'}), 200
        else:
            return jsonify({'error': 'Mot de passe non trouvé'}), 404

    @app.route('/api/passwords/<int:password_id>/copy', methods=['POST'])
    @login_required
    def copy_password(password_id):
        """Copie un mot de passe sans demander le mot de passe maître"""
        user_id = get_current_user_id()

        password_data = app.db.get_password_by_id(password_id, user_id)
        if not password_data:
            return jsonify({'error': 'Mot de passe non trouvé'}), 404

        # Met à jour la date de dernière utilisation
        app.db.update_last_used(password_id, user_id)

        # Pour l'instant, on retourne un mot de passe factice
        # TODO: Modifier la base de données pour stocker les mots de passe de manière accessible
        return jsonify({'password': '********'}), 200

    # Routes du générateur de mots de passe
    @app.route('/api/generate-password', methods=['POST'])
    @login_required
    def generate_password():
        """Génère un mot de passe sécurisé"""
        data = request.get_json() or {}

        try:
            password = password_gen.generate_password(
                length=data.get('length', 16),
                use_uppercase=data.get('use_uppercase', True),
                use_lowercase=data.get('use_lowercase', True),
                use_digits=data.get('use_digits', True),
                use_special=data.get('use_special', True),
                exclude_similar=data.get('exclude_similar', True)
            )

            strength = password_gen.check_password_strength(password)

            return jsonify({
                'password': password,
                'strength': strength
            }), 200
        except ValueError as e:
            return jsonify({'error': str(e)}), 400

    @app.route('/api/check-password-strength', methods=['POST'])
    @login_required
    def check_password_strength():
        """Analyse la force d'un mot de passe"""
        data = request.get_json()

        if not data or not data.get('password'):
            return jsonify({'error': 'Mot de passe requis'}), 400

        strength = password_gen.check_password_strength(data['password'])
        return jsonify({'strength': strength}), 200

    # Routes de statistiques et dashboard
    @app.route('/api/dashboard', methods=['GET'])
    @login_required
    def dashboard():
        """Récupère les données du tableau de bord"""
        user_id = get_current_user_id()

        stats = app.db.get_password_stats(user_id)

        return jsonify({
            'stats': stats,
            'user_id': user_id
        }), 200

    # Route de healthcheck pour Docker
    @app.route('/health', methods=['GET'])
    def health_check():
        """Endpoint de vérification de santé pour Docker"""
        try:
            # Vérifier la connexion à la base de données
            app.db.cursor.execute('SELECT 1')
            db_status = "OK"
        except Exception as e:
            db_status = f"ERROR: {str(e)}"
            return jsonify({
                'status': 'unhealthy',
                'database': db_status,
                'timestamp': datetime.now().isoformat()
            }), 503

        return jsonify({
            'status': 'healthy',
            'database': db_status,
            'timestamp': datetime.now().isoformat(),
            'version': '1.0.0'
        }), 200

    # Routes pour les pages web
    @app.route('/')
    def index():
        """Page d'accueil"""
        return render_template('login.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login_page():
        """Page de connexion - Gère aussi les redirections après authentification"""
        # Si l'utilisateur est déjà connecté, redirige vers le dashboard
        if session.get('user_id'):
            session_manager = SessionManager(app.db)
            if session_manager.validate_session():
                return redirect('/dashboard')

        # Affiche la page de connexion
        form = LoginForm()
        if form.validate_on_submit():
            # TODO: Intégrer avec l'API de connexion
            flash('Connexion réussie!', 'success')
            return redirect('/dashboard')
        return render_template('login.html', form=form)

    @app.route('/dashboard')
    @login_required_page
    def dashboard_page():
        """Page du tableau de bord - Protégée par authentification"""
        return render_template('dashboard.html')

    @app.route('/password')
    @login_required_page
    def password_page():
        """Page du générateur de mots de passe"""
        return render_template('password.html')

    @app.route('/passwords')
    @login_required_page
    def passwords_page():
        """Page de gestion des mots de passe"""
        return render_template('passwords.html')

    @app.route('/settings')
    @login_required_page
    def settings_page():
        """Page des paramètres"""
        return render_template('settings.html')

    # Gestionnaire d'erreurs
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Ressource non trouvée'}), 404

    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({'error': 'Erreur interne du serveur'}), 500

    @app.errorhandler(401)
    def unauthorized(error):
        # Pour les requêtes API, retourne JSON avec redirection
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Non autorisé', 'redirect': '/login'}), 401
        # Pour les pages web, redirige directement
        return redirect('/login')

    # Configuration initiale de l'application
    with app.app_context():
        # Nettoie les sessions expirées
        app.db.cleanup_old_sessions()
        app.db.cleanup_old_login_attempts()

    return app


# Point d'entrée principal
if __name__ == '__main__':
    app = create_app(os.environ.get('FLASK_ENV', 'development'))
    app.run(debug=True, host='0.0.0.0', port=5000)