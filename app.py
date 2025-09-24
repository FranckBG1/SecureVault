"""
Application Flask principale pour SecureVault
Gestionnaire de mots de passe sécurisé avec chiffrement AES-256
"""
import json
import os
from datetime import datetime, timedelta

from flask import Flask, request, jsonify, session, render_template, flash, redirect
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired

# Imports conditionnels pour éviter les erreurs
try:
    from auth import SessionManager, login_required, get_current_user_id, require_master_password
    from config import config
    from crypto_utils import PasswordGenerator, CryptoManager
    from database import DatabaseManager

    FULL_FEATURES = True
except ImportError:
    FULL_FEATURES = False
    print("⚠️ Modules avancés non disponibles, mode simplifié activé")


    # Fonction simple de vérification d'authentification
    def check_auth():
        """Vérifie si l'utilisateur est connecté"""
        return session.get('logged_in', False)


    def login_required_simple(f):
        """Décorateur simple pour l'authentification"""
        from functools import wraps
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not check_auth():
                if request.path.startswith('/api/'):
                    return jsonify({'error': 'Non autorisé', 'redirect': '/login'}), 401
                return redirect('/login')
            return f(*args, **kwargs)

        return decorated_function


    def login_required_page(f):
        """Décorateur pour les pages web - redirige directement"""
        from functools import wraps
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not check_auth():
                return redirect('/login')
            return f(*args, **kwargs)

        return decorated_function


    login_required = login_required_simple


class LoginForm(FlaskForm):
    username = StringField('Nom d\'utilisateur', validators=[DataRequired()])
    password = PasswordField('Mot de passe', validators=[DataRequired()])
    submit = SubmitField('Se connecter')


def create_app(config_name='default'):
    """Factory pour créer l'application Flask"""
    app = Flask(__name__)

    # Configuration
    app.config.from_object(config[config_name])

    # Configuration de la secret key depuis les secrets Docker ou la config
    secret_key_file = os.environ.get('SECRET_KEY_FILE')
    if secret_key_file and os.path.exists(secret_key_file):
        # Chargement depuis le secret Docker
        with open(secret_key_file, 'r') as f:
            app.config['SECRET_KEY'] = f.read().strip()
    elif not app.config.get('SECRET_KEY'):
        # Fallback vers la variable d'environnement ou la config
        app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', app.config['SECRET_KEY'])

    # Sessions Flask natives (pas besoin d'initialisation d'extension)
    # Les sessions sont maintenant gérées nativement par Flask

    # S'assurer que le répertoire data existe
    data_dir = os.path.dirname(app.config['DATABASE_PATH'])
    if not os.path.exists(data_dir):
        os.makedirs(data_dir, exist_ok=True)

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

            # Stocke le nom d'utilisateur et le mot de passe maître en session
            session['username'] = username
            session['master_password'] = master_password  # Stockage temporaire pour déchiffrement

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
    def get_password(password_id):
        """Récupère un mot de passe spécifique (déchiffré)"""
        user_id = get_current_user_id()

        # Essayer d'abord avec le mot de passe maître en session
        master_password = session.get('master_password')

        # Si pas en session, récupérer depuis l'en-tête
        if not master_password:
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
            decrypted_notes = crypto.decrypt_data(password_data['notes_encrypted'], encryption_key) if password_data[
                'notes_encrypted'] else ""

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

        # Retourne directement le mot de passe chiffré (le frontend s'en chargera)
        # Pour simplifier, on retourne un mot de passe factice pour les tests
        # En production, vous pourriez vouloir stocker les mots de passe en clair ou avec un chiffrement plus simple

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
    def dashboard_page():
        """Page du tableau de bord - Protégée par authentification"""
        if FULL_FEATURES:
            # Utilise le décorateur avancé si disponible
            if not session.get('user_id'):
                return redirect('/login')
        else:
            # Mode simplifié
            if not check_auth():
                return redirect('/login')
        return render_template('dashboard.html')

    @app.route('/password')  # Corrigé pour correspondre aux liens du template
    def password_page():
        """Page du générateur de mots de passe"""
        if FULL_FEATURES:
            if not session.get('user_id'):
                return redirect('/login')
        else:
            if not check_auth():
                return redirect('/login')
        return render_template('password.html')

    @app.route('/passwords')  # Garde cette route pour la cohérence
    def passwords_page():
        """Page de gestion des mots de passe"""
        if FULL_FEATURES:
            if not session.get('user_id'):
                return redirect('/login')
        else:
            if not check_auth():
                return redirect('/login')
        return render_template('passwords.html')

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
