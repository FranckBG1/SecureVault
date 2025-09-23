"""
Module de cryptographie pour SecureVault
Gestion du chiffrement AES-256 et des fonctions de sécurité
"""
import os
import base64
import bcrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import secrets
import string

class CryptoManager:
    """Gestionnaire de cryptographie pour l'application"""

    def __init__(self):
        self.backend = default_backend()

    def generate_salt(self, length=32):
        """Génère un sel aléatoire"""
        return os.urandom(length)

    def derive_key(self, password, salt, iterations=100000):
        """Dérive une clé de chiffrement à partir d'un mot de passe et d'un sel"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=self.backend
        )
        return kdf.derive(password.encode())

    def hash_master_password(self, password):
        """Hash le mot de passe maître avec bcrypt"""
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')

    def verify_master_password(self, password, hashed):
        """Vérifie le mot de passe maître"""
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

    def encrypt_data(self, data, key):
        """Chiffre des données avec AES-256"""
        if isinstance(data, str):
            data = data.encode('utf-8')

        # Génère un IV aléatoire
        iv = os.urandom(16)

        # Crée le cipher AES-256 en mode CBC
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()

        # Padding PKCS7
        padding_length = 16 - (len(data) % 16)
        padded_data = data + bytes([padding_length] * padding_length)

        # Chiffrement
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # Retourne IV + données chiffrées encodées en base64
        return base64.b64encode(iv + encrypted_data).decode('utf-8')

    def decrypt_data(self, encrypted_data, key):
        """Déchiffre des données"""
        try:
            # Décode de base64
            data = base64.b64decode(encrypted_data.encode('utf-8'))

            # Extrait l'IV (16 premiers bytes)
            iv = data[:16]
            encrypted_content = data[16:]

            # Crée le cipher
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
            decryptor = cipher.decryptor()

            # Déchiffrement
            decrypted_data = decryptor.update(encrypted_content) + decryptor.finalize()

            # Supprime le padding
            padding_length = decrypted_data[-1]
            decrypted_data = decrypted_data[:-padding_length]

            return decrypted_data.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Erreur de déchiffrement: {str(e)}")

class PasswordGenerator:
    """Générateur de mots de passe sécurisés"""

    def __init__(self):
        self.lowercase = string.ascii_lowercase
        self.uppercase = string.ascii_uppercase
        self.digits = string.digits
        self.special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"

    def generate_password(self, length=16, use_uppercase=True, use_lowercase=True,
                         use_digits=True, use_special=True, exclude_similar=True):
        """
        Génère un mot de passe sécurisé

        Args:
            length: Longueur du mot de passe
            use_uppercase: Inclure les majuscules
            use_lowercase: Inclure les minuscules
            use_digits: Inclure les chiffres
            use_special: Inclure les caractères spéciaux
            exclude_similar: Exclure les caractères similaires (0, O, l, 1, etc.)
        """
        if length < 4:
            raise ValueError("La longueur minimale est de 4 caractères")

        # Construction du jeu de caractères
        charset = ""
        required_chars = []

        if use_lowercase:
            chars = self.lowercase
            if exclude_similar:
                chars = chars.replace('l', '').replace('o', '')
            charset += chars
            required_chars.append(secrets.choice(chars))

        if use_uppercase:
            chars = self.uppercase
            if exclude_similar:
                chars = chars.replace('I', '').replace('O', '')
            charset += chars
            required_chars.append(secrets.choice(chars))

        if use_digits:
            chars = self.digits
            if exclude_similar:
                chars = chars.replace('0', '').replace('1', '')
            charset += chars
            required_chars.append(secrets.choice(chars))

        if use_special:
            charset += self.special_chars
            required_chars.append(secrets.choice(self.special_chars))

        if not charset:
            raise ValueError("Au moins un type de caractère doit être sélectionné")

        # Génère le mot de passe
        password = required_chars.copy()

        # Complète avec des caractères aléatoires
        for _ in range(length - len(required_chars)):
            password.append(secrets.choice(charset))

        # Mélange le mot de passe
        secrets.SystemRandom().shuffle(password)

        return ''.join(password)

    def check_password_strength(self, password):
        """
        Analyse la force d'un mot de passe

        Returns:
            dict: Score et recommandations
        """
        score = 0
        feedback = []

        # Longueur
        if len(password) >= 12:
            score += 25
        elif len(password) >= 8:
            score += 15
        else:
            feedback.append("Utilisez au moins 8 caractères")

        # Majuscules
        if any(c.isupper() for c in password):
            score += 20
        else:
            feedback.append("Ajoutez des lettres majuscules")

        # Minuscules
        if any(c.islower() for c in password):
            score += 20
        else:
            feedback.append("Ajoutez des lettres minuscules")

        # Chiffres
        if any(c.isdigit() for c in password):
            score += 20
        else:
            feedback.append("Ajoutez des chiffres")

        # Caractères spéciaux
        if any(c in self.special_chars for c in password):
            score += 15
        else:
            feedback.append("Ajoutez des caractères spéciaux")

        # Détermination du niveau
        if score >= 80:
            level = "Très fort"
        elif score >= 60:
            level = "Fort"
        elif score >= 40:
            level = "Moyen"
        elif score >= 20:
            level = "Faible"
        else:
            level = "Très faible"

        return {
            'score': score,
            'level': level,
            'feedback': feedback
        }
