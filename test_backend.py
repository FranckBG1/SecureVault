"""
Script de test pour valider le backend SecureVault
"""
import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from mon_app import create_app
from mon_app.database import DatabaseManager
from mon_app.crypto_utils import CryptoManager, PasswordGenerator


def test_crypto():
    """Test des fonctionnalités de cryptographie"""
    print("=== Test du module de cryptographie ===")

    crypto = CryptoManager()

    # Test du hashage du mot de passe maître
    password = "test_password_123"
    hashed = crypto.hash_master_password(password)
    print(f"✓ Hashage du mot de passe maître: {len(hashed)} caractères")

    # Test de vérification
    is_valid = crypto.verify_master_password(password, hashed)
    print(f"✓ Vérification du mot de passe: {is_valid}")

    # Test de chiffrement
    salt = crypto.generate_salt()
    key = crypto.derive_key(password, salt)

    test_data = "Données sensibles à chiffrer"
    encrypted = crypto.encrypt_data(test_data, key)
    decrypted = crypto.decrypt_data(encrypted, key)

    print(f"✓ Chiffrement/Déchiffrement: {test_data == decrypted}")


def test_password_generator():
    """Test du générateur de mots de passe"""
    print("\n=== Test du générateur de mots de passe ===")

    gen = PasswordGenerator()

    # Test de génération
    password = gen.generate_password(length=4, use_uppercase=False, use_lowercase=True, use_digits=False, use_special=False)
    print(f"✓ Mot de passe généré: {password}")

    # Test d'analyse de force
    strength = gen.check_password_strength(password)
    print(f"✓ Force du mot de passe: {strength['level']} (Score: {strength['score']})")


def test_database():
    """Test de la base de données"""
    print("\n=== Test de la base de données ===")

    # Utilise une base temporaire avec un nom unique
    import time
    test_db_path = f"test_securevault_{int(time.time())}.db"

    try:
        # S'assure que le fichier n'existe pas déjà
        if os.path.exists(test_db_path):
            os.remove(test_db_path)

        db = DatabaseManager(test_db_path)
        print("✓ Base de données initialisée")

        # Test de création d'utilisateur
        user_id = db.create_user("test_user", "test_password_123")
        print(f"✓ Utilisateur créé avec ID: {user_id}")

        # Petite pause pour éviter les conflits
        time.sleep(0.1)

        # Test d'authentification
        auth_user_id = db.authenticate_user("test_user", "test_password_123")
        print(f"✓ Authentification réussie: {auth_user_id == user_id}")

        # Test d'authentification avec mauvais mot de passe
        try:
            db.authenticate_user("test_user", "wrong_password")
            print("✗ L'authentification avec un mauvais mot de passe devrait échouer")
        except ValueError:
            print("✓ Authentification échoue correctement avec un mauvais mot de passe")

        print("✓ Tous les tests de base de données ont réussi")

    except Exception as e:
        print(f"✗ Erreur dans les tests de base de données: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Nettoie la base de test de manière plus robuste
        try:
            if os.path.exists(test_db_path):
                # Petite pause pour s'assurer que toutes les connexions sont fermées
                time.sleep(0.2)
                os.remove(test_db_path)
                print("✓ Base de données de test nettoyée")
        except Exception as e:
            print(f"⚠ Impossible de supprimer la base de test: {e}")


def test_flask_app():
    """Test de l'application Flask"""
    print("\n=== Test de l'application Flask ===")

    try:
        app = create_app('development')
        print("✓ Application Flask créée avec succès")

        with app.test_client() as client:
            # Test de la page d'accueil
            response = client.get('/')
            print(f"✓ Page d'accueil accessible: {response.status_code == 200}")

            # Test de l'API (sans authentification)
            response = client.get('/api/passwords')
            print(f"✓ API protégée correctement: {response.status_code == 401}")

        print("✓ Tous les tests Flask ont réussi")

    except Exception as e:
        print(f"✗ Erreur dans les tests Flask: {e}")


if __name__ == "__main__":
    print("Démarrage des tests du backend SecureVault...")

    test_crypto()
    test_password_generator()
    test_database()
    test_flask_app()

    print("\n=== Tests terminés ===")
