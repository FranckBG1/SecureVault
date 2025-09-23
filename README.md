#SecureVault 
pour avoir un rendu desktop de l'application veuillez lancer le fichier "Securevault.lnk" ou "Securevault.vbs"

==================================================================================================
Cahier des charges - Application de gestion des mots de passe

1. Contexte et objectifs
   Les utilisateurs possèdent de nombreux comptes en ligne nécessitant des mots de passe distincts.
   L'application a pour objectif de permettre le stockage sécurisé, la gestion et la génération de mots de passe
   robustes. Elle doit être facile à utiliser tout en garantissant un haut niveau de sécurité.

2. Fonctionnalités principales
   Gestion des comptes : ajout, modification, suppression, recherche par url.
   Sécurité : chiffrement AES-256, mot de passe maître, déconnexion automatique, option biométrie.
   Générateur de mots de passe : configurable (longueur, caractères spéciaux, chiffres, majuscules).
   Interface utilisateur : ergonomique, tableau de bord clair, recherche rapide.

3. Contraintes techniques
   • Plateformes : Desktop (Windows/Linux/Mac).
   • Langages/Frameworks : Python(flask)/JS selon plateforme.
   • Base de données : SQLite chiffrée (SQLCipher).
   • Sécurité : hashage du mot de passe maître avec PBKDF2. Aucune donnée ne doit être stockée en clair.

4. Exigences non fonctionnelles
   • Robustesse : l'application doit être fiable, stable et tolérante aux erreurs.
   • Performance : ouverture en moins de 2 secondes.
   • Ergonomie : interface simple et intuitive, adaptée aux utilisateurs non experts.
   • Fiabilité : sauvegarde automatique, pas de perte de données.

5. Livrables
   • Prototype fonctionnel.
   • Application finale livrée (APK, EXE, etc.).
   • Documentation utilisateur et technique.

6. Déploiement et Infrastructure (optionnel)
   L'application doit être packagée et déployée de manière standardisée et
   reproductible. L'utilisation de Docker permettra de garantir la portabilité et la cohérence des environnements.
   6.1 Conteneurisation
   • Chaque composant (application, base de données, éventuel service d’API) sera déployé dans un
   conteneur Docker.
   • Un fichier Dockerfile sera fourni pour définir l’image de l’application.
   • Une configuration docker-compose.yml sera utilisée pour orchestrer plusieurs services (application + base de
   données chiffrée).
   6.2 Infrastructure
   • Base de données : SQLite chiffrée, stockée dans un volume Docker persistant.
   • Sauvegardes : automatisées via scripts ou jobs planifiés dans un conteneur dédié.
   • Sécurité : communication interne sécurisée, gestion stricte des secrets (fichier .env ou gestionnaire de secrets).
   6.3 CI/CD
   • Mise en place d’une intégration continue (CI) pour automatiser les tests et la construction de l’image
   Docker.
   • Déploiement continu (CD) vers l’environnement cible après validation.

# 🔐 SecureVault - Gestionnaire de Mots de Passe Sécurisé

Un gestionnaire de mots de passe desktop moderne et sécurisé développé en Python avec PySide6 et SQLite.

## ✨ Fonctionnalités

- 🛡️ **Chiffrement AES-256** pour une sécurité maximale
- 🎯 **Interface intuitive** avec PySide6
- 🔍 **Recherche rapide** dans vos mots de passe
- 🎲 **Générateur de mots de passe** personnalisable
- 📋 **Copie automatique** avec effacement sécurisé
- ⏰ **Verrouillage automatique** après inactivité
- 📊 **Analyse de force** des mots de passe
- 💾 **Base de données SQLite** chiffrée

## 🚀 Installation

### Prérequis

- Python 3.8 ou supérieur
- pip (gestionnaire de paquets Python)

### Installation des dépendances







