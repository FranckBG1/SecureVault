"""
Application Flask principale pour SecureVault
Gestionnaire de mots de passe sécurisé avec chiffrement AES-256
"""
import json
import os

from flask import Flask, request, jsonify, session, render_template, flash, redirect
from flask_session import Session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired

from auth import SessionManager, login_required, get_current_user_id, require_master_password
from config import config
from crypto_utils import PasswordGenerator, CryptoManager
from database import DatabaseManager


class LoginForm(FlaskForm):
    username = StringField('Nom d\'utilisateur', validators=[DataRequired()])
    password = PasswordField('Mot de passe', validators=[DataRequired()])
    submit = SubmitField('Se connecter')


def create_app(config_name='default'):
    """Factory pour créer l'application Flask"""
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'votre-clé-secrète'

    # Configuration
    app.config.from_object(config[config_name])

    # Initialisation des extensions
    Session(app)

    # Initialisation de la base de données
    app.db = DatabaseManager(app.config['DATABASE_PATH'])

    # Initialisation des services
    crypto = CryptoManager()
    password_gen = PasswordGenerator()

    # Routes d'authentification
    @app.route('/api/register', methods=['POST'])
    def register():
        """Inscription d'un nouvel utilisateur"""
        data = request.get_json()

        if not data or not data.get('username') or not data.get('master_password'):
            return jsonify({'error': 'Nom d\'utilisateur et mot de passe requis'}), 400

        username = data['username'].strip()
        master_password = data['master_password']

        # Validation
        if len(username) < 3:
            return jsonify({'error': 'Le nom d\'utilisateur doit contenir au moins 3 caractères'}), 400

        if len(master_password) < 8:
            return jsonify({'error': 'Le mot de passe maître doit contenir au moins 8 caractères'}), 400

        try:
            user_id = app.db.create_user(username, master_password)
            return jsonify({
                'message': 'Utilisateur créé avec succès',
                'user_id': user_id
            }), 201
        except ValueError as e:
            return jsonify({'error': str(e)}), 400

    @app.route('/api/login', methods=['POST'])
    def login():
        """Connexion utilisateur"""
        data = request.get_json()

        if not data or not data.get('username') or not data.get('master_password'):
            return jsonify({'error': 'Nom d\'utilisateur et mot de passe requis'}), 400

        username = data['username'].strip()
        master_password = data['master_password']
        remember_me = data.get('remember_me', False)

        try:
            user_id = app.db.authenticate_user(username, master_password, request.remote_addr)

            # Crée la session
            session_manager = SessionManager(app.db)
            session_token = session_manager.create_session(user_id, remember_me)

            # Stocke le nom d'utilisateur pour les vérifications futures
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
    @require_master_password
    def get_password(password_id):
        """Récupère un mot de passe spécifique (déchiffré)"""
        user_id = get_current_user_id()
        encryption_key = request.encryption_key

        password_data = app.db.get_password_by_id(password_id, user_id)
        if not password_data:
            return jsonify({'error': 'Mot de passe non trouvé'}), 404

        try:
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
    @login_required
    def dashboard_page():
        """Page du tableau de bord - Protégée par authentification"""
        return render_template('dashboard.html')

    @app.route('/password')  # Corrigé pour correspondre aux liens du template
    def password_page():
        """Page du générateur de mots de passe"""
        return render_template('password.html')

    @app.route('/passwords')  # Garde cette route pour la cohérence
    def passwords_page():
        """Page de gestion des mots de passe"""
        return render_template('passwords.html')

    # Gestionnaire d'erreurs
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Ressource non trouvée'}), 404

    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({'error': 'Erreur interne du serveur'}), 500

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
