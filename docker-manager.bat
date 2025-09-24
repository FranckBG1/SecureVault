@echo off
setlocal enabledelayedexpansion

REM Script de gestion de l'environnement Docker SecureVault pour Windows
REM Usage: docker-manager.bat [start|stop|restart|logs|status]

set PROJECT_NAME=securevault
set COMPOSE_FILE=docker-compose.yml

if "%1"=="start" (
    echo 🚀 Démarrage de SecureVault...

    REM Créer les répertoires nécessaires
    if not exist "data" mkdir data
    if not exist "logs" mkdir logs

    REM Générer les secrets si ils n'existent pas
    if not exist "secrets\flask_secret.txt" (
        echo 🔑 Génération des secrets...
        python scripts\generate_secrets.py > secrets\flask_secret.txt
    )

    REM Démarrer les services
    docker-compose up -d

    echo ✅ SecureVault démarré avec succès!
    echo 📱 Application disponible sur: http://localhost:5000
    echo 📊 Logs: docker-manager.bat logs

) else if "%1"=="stop" (
    echo 🛑 Arrêt de SecureVault...
    docker-compose down
    echo ✅ SecureVault arrêté

) else if "%1"=="restart" (
    echo 🔄 Redémarrage de SecureVault...
    docker-compose restart
    echo ✅ SecureVault redémarré

) else if "%1"=="logs" (
    echo 📋 Affichage des logs...
    docker-compose logs -f --tail=100

) else if "%1"=="status" (
    echo 📊 État des services SecureVault:
    docker-compose ps
    echo.
    echo 🔍 Utilisation des volumes:
    docker volume ls | findstr securevault

) else if "%1"=="clean" (
    echo 🧹 Nettoyage complet (ATTENTION: supprime toutes les données)...
    set /p confirm="Êtes-vous sûr ? (oui/non): "
    if "!confirm!"=="oui" (
        docker-compose down -v
        docker system prune -f
        del /q data\* 2>nul
        del /q logs\* 2>nul
        echo ✅ Nettoyage terminé
    ) else (
        echo ❌ Nettoyage annulé
    )

) else (
    echo 🔐 SecureVault - Gestionnaire Docker
    echo.
    echo Usage: %0 [commande]
    echo.
    echo Commandes disponibles:
    echo   start    - Démarrer SecureVault
    echo   stop     - Arrêter SecureVault
    echo   restart  - Redémarrer SecureVault
    echo   logs     - Afficher les logs en temps réel
    echo   status   - Afficher l'état des services
    echo   clean    - Nettoyage complet (DANGER)
    echo.
    echo Exemples:
    echo   %0 start
    echo   %0 logs
)
