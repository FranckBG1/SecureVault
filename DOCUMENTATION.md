# 📖 SecureVault - Guide d'utilisation

## 🔐 Gestionnaire de Mots de Passe Sécurisé

SecureVault est une application web sécurisée pour gérer vos mots de passe avec un chiffrement AES-256 et une interface intuitive.

---

## 🚀 Démarrage rapide

### 1. Installation et configuration

#### Étape 1 : Créer un environnement virtuel
```bash
# Créer l'environnement virtuel
python -m venv venv

# Activer l'environnement virtuel
# Sur Windows :
venv\Scripts\activate

# Sur Linux/macOS :
source venv/bin/activate
```

#### Étape 2 : Installer les dépendances
```bash
# Installer toutes les librairies requises
pip install -r requirements.txt
```

#### Étape 3 : Lancer l'application
```bash
python main.py
```
L'application sera accessible sur : `http://localhost:5000`

⚠️ **Important** : Assurez-vous que l'environnement virtuel est activé avant chaque utilisation !

### 2. Première connexion
- Créez votre compte avec un nom d'utilisateur (minimum 3 caractères)
- Définissez un mot de passe maître fort (minimum 8 caractères)
- **⚠️ IMPORTANT** : Mémorisez bien votre mot de passe maître, il ne peut pas être récupéré !

---

## 🎯 Fonctionnalités principales

### 🔑 Connexion et sécurité

#### Connexion
1. Saisissez votre nom d'utilisateur
2. Entrez votre mot de passe maître
3. Cochez "Se souvenir de moi" pour rester connecté plus longtemps

#### Sécurité automatique
- **Verrouillage automatique** : Par défaut après 5 minutes d'inactivité
- **Protection contre les attaques** : Compte bloqué après 5 tentatives échouées
- **Sessions sécurisées** : Chiffrement de toutes les données sensibles

---

### 🏠 Tableau de bord

Le tableau de bord vous donne un aperçu de :
- **Nombre total** de mots de passe stockés
- **Mots de passe récents** (utilisés dans les 7 derniers jours)
- **Mots de passe jamais utilisés**
- **Accès rapide** aux fonctionnalités principales

---

### 🔐 Gestion des mots de passe

#### Ajouter un mot de passe
1. Cliquez sur "Mes mots de passe" dans le menu
2. Cliquez sur "Ajouter un mot de passe"
3. Remplissez les informations :
   - **Titre** : Nom du service (ex: "Gmail", "Facebook")
   - **URL** : Adresse du site web (optionnel)
   - **Nom d'utilisateur** : Votre identifiant sur le service
   - **Mot de passe** : Le mot de passe du service
   - **Notes** : Informations supplémentaires (optionnel)
4. Cliquez sur "Enregistrer"

#### Consulter un mot de passe
1. Dans la liste des mots de passe, cliquez sur celui que vous voulez voir
2. **Saisissez votre mot de passe maître** pour déchiffrer les données
3. Le mot de passe s'affiche et peut être copié

#### Modifier un mot de passe
1. Cliquez sur l'icône "Modifier" (crayon) à côté du mot de passe
2. Modifiez les informations souhaitées
3. Confirmez avec votre mot de passe maître
4. Cliquez sur "Sauvegarder"

#### Supprimer un mot de passe
1. Cliquez sur l'icône "Supprimer" (poubelle)
2. Confirmez la suppression
3. Le mot de passe est définitivement supprimé

#### Recherche
- Utilisez la barre de recherche pour trouver rapidement un mot de passe
- La recherche fonctionne sur le titre, l'URL et le nom d'utilisateur

---

### 🎲 Générateur de mots de passe

#### Générer un mot de passe sécurisé
1. Allez dans "Générateur" dans le menu
2. Configurez les options :
   - **Longueur** : Entre 8 et 128 caractères (recommandé : 16+)
   - **Majuscules** : Inclure A-Z
   - **Minuscules** : Inclure a-z
   - **Chiffres** : Inclure 0-9
   - **Caractères spéciaux** : Inclure !@#$%^&*
   - **Exclure les caractères similaires** : Évite 0/O, 1/l/I
3. Cliquez sur "Générer"
4. Le mot de passe apparaît avec son niveau de sécurité
5. Cliquez sur "Copier" pour l'utiliser

#### Analyser la force d'un mot de passe
- Saisissez un mot de passe dans le champ "Analyser"
- L'application évalue sa force : Faible, Moyen, Fort, Très Fort

---

### ⚙️ Paramètres

#### Informations du compte
- **Nom d'utilisateur actuel** : Affiché en haut de la page
- **Dernière connexion** : Date et heure de votre dernière connexion
- **Date de création** : Quand le compte a été créé

#### Modifier le nom d'utilisateur
1. Cliquez sur l'icône "Modifier" à côté de votre nom
2. Saisissez le nouveau nom d'utilisateur
3. **Confirmez avec votre mot de passe maître**
4. Cliquez sur "Modifier"

#### Changer le mot de passe maître
1. Cliquez sur "Modifier" dans la section "Changer le mot de passe maître"
2. Saisissez votre **mot de passe actuel**
3. Saisissez le **nouveau mot de passe** (minimum 8 caractères)
4. **Confirmez le nouveau mot de passe**
5. Cliquez sur "Modifier"
6. **Vous serez déconnecté** de toutes les sessions

#### Verrouillage automatique
Configurez le délai avant verrouillage automatique :
- **30 secondes** : Pour tests ou sécurité maximale
- **1 minute** : Sécurité très élevée
- **5 minutes** : Sécurité élevée (par défaut)
- **15 minutes** : Sécurité normale
- **30 minutes** : Sécurité standard
- **1 heure** : Sécurité minimale
- **Jamais** : Pas de verrouillage automatique (non recommandé)

#### Sessions actives
- **Déconnecter partout** : Ferme toutes vos sessions sur tous les appareils
- Utile si vous pensez que votre compte est compromis

#### Supprimer le compte
⚠️ **ATTENTION : Cette action est irréversible !**
1. Cliquez sur "Supprimer le compte"
2. Tapez exactement "SUPPRIMER" pour confirmer
3. Toutes vos données seront définitivement effacées

---

## 🛡️ Sécurité et bonnes pratiques

### Mot de passe maître
- **Utilisez un mot de passe unique et fort** (minimum 12 caractères)
- **Mélangez majuscules, minuscules, chiffres et symboles**
- **Ne le partagez jamais** et ne l'écrivez pas
- **Mémorisez-le bien** : il ne peut pas être récupéré

### Utilisation sécurisée
- **Fermez toujours l'application** après utilisation
- **Ne laissez pas l'écran ouvert** sans surveillance
- **Utilisez le verrouillage automatique** (5 minutes recommandées)
- **Déconnectez-vous** sur les ordinateurs partagés

### Mots de passe stockés
- **Utilisez des mots de passe uniques** pour chaque service
- **Générez des mots de passe forts** avec l'outil intégré
- **Mettez à jour régulièrement** vos mots de passe importants
- **Supprimez les comptes** que vous n'utilisez plus

---

## 🔧 Dépannage

### Problèmes de connexion
- **Mot de passe oublié** : Impossible à récupérer, vous devrez recréer un compte
- **Compte bloqué** : Attendez 5 minutes après 5 tentatives échouées
- **Session expirée** : Reconnectez-vous avec vos identifiants

### Problèmes techniques
- **Application ne démarre pas** : 
  1. Vérifiez que l'environnement virtuel est activé
  2. Vérifiez que les dépendances sont installées : `pip install -r requirements.txt`
  3. Vérifiez que Python 3.8+ est installé
- **Erreur "Module not found"** : Activez l'environnement virtuel et réinstallez les dépendances
- **Page ne se charge pas** : Vérifiez que l'application tourne sur le port 5000
- **Erreur de base de données** : Redémarrez l'application

### Sauvegarde
- **Base de données** : Le fichier `securevault.db` contient toutes vos données
- **Sauvegardez régulièrement** ce fichier (chiffré)
- **Testez la restauration** sur un autre appareil

---

## 📱 Interface utilisateur

### Navigation
- **Sidebar gauche** : Menu principal avec toutes les fonctionnalités
- **Zone principale** : Contenu de la page sélectionnée
- **Notifications** : Messages d'information en haut à droite

### Raccourcis
- **Recherche rapide** : Tapez directement dans la barre de recherche
- **Copie rapide** : Clic sur l'icône copier à côté des mots de passe
- **Navigation clavier** : Tab pour naviguer entre les champs

---

## 🆘 Support

### En cas de problème
1. **Redémarrez l'application**
2. **Vérifiez les logs** dans le terminal
3. **Consultez cette documentation**
4. **Contactez le support technique**

### Informations système
- **Version Python** : 3.8+
- **Navigateur recommandé** : Chrome, Firefox, Edge
- **Système d'exploitation** : Windows, Linux, macOS

---

## 🛡️ Sécurité avancée

### Protections intégrées

SecureVault implémente plusieurs couches de sécurité pour protéger vos données :

#### 🔐 Chiffrement et cryptographie
- **AES-256** : Chiffrement militaire pour tous les mots de passe stockés
- **PBKDF2** : Dérivation de clés sécurisée pour le mot de passe maître
- **Sel unique** : Chaque utilisateur a un sel cryptographique unique
- **Hashage sécurisé** : Les mots de passe maîtres ne sont jamais stockés en clair

#### 😫 Protection contre les attaques web
- **Injection SQL** : Requêtes paramétrées pour toutes les interactions base de données
- **XSS (Cross-Site Scripting)** : Échappement automatique de toutes les données utilisateur
- **CSRF (Cross-Site Request Forgery)** : Tokens de protection sur tous les formulaires
- **Clickjacking** : Headers X-Frame-Options pour empêcher l'intégration malveillante

#### ⚡ Rate Limiting et protection brute force
- **Connexion** : Maximum 5 tentatives par 5 minutes par adresse IP
- **Création de compte** : Maximum 3 créations par 10 minutes par adresse IP
- **Verrouillage automatique** : Compte bloqué après 5 échecs consécutifs
- **Délai progressif** : Temps d'attente croissant entre les tentatives

#### 🔒 Headers de sécurité HTTP
- **Strict-Transport-Security** : Force l'utilisation HTTPS
- **X-Content-Type-Options** : Empêche le sniffing de type MIME
- **X-XSS-Protection** : Protection XSS native du navigateur
- **Content-Security-Policy** : Politique stricte de chargement des ressources

#### ✅ Validation des données
- **Côté serveur** : Validation stricte de tous les inputs utilisateur
- **Longueur limitée** : Contrôle des tailles de données (3-128 caractères)
- **Caractères autorisés** : Regex pour filtrer les caractères dangereux
- **Échappement automatique** : Protection contre l'injection de code

#### 🕐 Gestion des sessions
- **Tokens uniques** : Chaque session a un identifiant cryptographiquement sécurisé
- **Expiration automatique** : Sessions limitées dans le temps
- **Révocation** : Possibilité de fermer toutes les sessions à distance
- **Validation continue** : Vérification de la validité à chaque requête

### Audit de sécurité

#### ✅ Tests effectués
- **Injection SQL** : Toutes les entrées testées contre l'injection
- **XSS** : Vérification de l'échappement des données
- **CSRF** : Validation des tokens sur tous les formulaires
- **Brute Force** : Test des limites de tentatives
- **Session Hijacking** : Vérification de la sécurité des sessions

#### 🔍 Monitoring de sécurité
- **Tentatives de connexion** : Journalisation de tous les essais
- **Erreurs suspectes** : Détection des patterns d'attaque
- **Sessions anormales** : Surveillance des comportements inhabituels

### Recommandations de déploiement

#### 🌐 Production
- **HTTPS obligatoire** : Utilisez toujours un certificat SSL/TLS valide
- **Firewall** : Limitez l'accès aux ports nécessaires uniquement
- **Reverse Proxy** : Utilisez nginx ou Apache comme proxy inverse
- **Logs sécurisés** : Activez la journalisation sans exposer de données sensibles

#### 🔧 Configuration serveur
- **Variables d'environnement** : Stockez les secrets dans des variables d'env
- **Permissions fichiers** : Limitez l'accès en lecture/écriture
- **Base de données** : Sauvegardez régulièrement avec chiffrement
- **Mises à jour** : Maintenez Python et les dépendances à jour

---

## 🔒 Mentions légales

- **Chiffrement** : AES-256 avec clés dérivées PBKDF2
- **Stockage local** : Toutes les données restent sur votre appareil
- **Aucune télémétrie** : Aucune donnée n'est envoyée vers l'extérieur
- **Open Source** : Code source disponible pour audit
- **Conformité** : Respect des standards de sécurité OWASP
- **Audit** : Code régulièrement audité pour les vulnérabilités

---

**SecureVault v1.0** - Gestionnaire de mots de passe sécurisé
*Protégez vos données, simplifiez votre vie numérique* 🔐