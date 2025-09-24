#!/bin/bash

# Script de gestion de l'environnement Docker SecureVault
# Usage: ./docker-manager.sh [start|stop|restart|logs|status]

set -e

PROJECT_NAME="securevault"
COMPOSE_FILE="docker-compose.yml"

case "$1" in
    start)
        echo "🚀 Démarrage de SecureVault..."

        # Créer les répertoires nécessaires
        mkdir -p data logs

        # Générer les secrets si ils n'existent pas
        if [ ! -f "secrets/flask_secret.txt" ]; then
            echo "🔑 Génération des secrets..."
            python3 scripts/generate_secrets.py > secrets/flask_secret.txt
        fi

        # Démarrer les services
        docker-compose up -d

        echo "✅ SecureVault démarré avec succès!"
        echo "📱 Application disponible sur: http://localhost:5000"
        echo "📊 Logs: ./docker-manager.sh logs"
        ;;

    stop)
        echo "🛑 Arrêt de SecureVault..."
        docker-compose down
        echo "✅ SecureVault arrêté"
        ;;

    restart)
        echo "🔄 Redémarrage de SecureVault..."
        docker-compose restart
        echo "✅ SecureVault redémarré"
        ;;

    logs)
        echo "📋 Affichage des logs..."
        docker-compose logs -f --tail=100
        ;;

    status)
        echo "📊 État des services SecureVault:"
        docker-compose ps
        echo ""
        echo "🔍 Utilisation des volumes:"
        docker volume ls | grep securevault || echo "Aucun volume trouvé"
        ;;

    clean)
        echo "🧹 Nettoyage complet (ATTENTION: supprime toutes les données)..."
        read -p "Êtes-vous sûr ? (oui/non): " confirm
        if [ "$confirm" = "oui" ]; then
            docker-compose down -v
            docker system prune -f
            rm -rf data/* logs/*
            echo "✅ Nettoyage terminé"
        else
            echo "❌ Nettoyage annulé"
        fi
        ;;

    *)
        echo "🔐 SecureVault - Gestionnaire Docker"
        echo ""
        echo "Usage: $0 [commande]"
        echo ""
        echo "Commandes disponibles:"
        echo "  start    - Démarrer SecureVault"
        echo "  stop     - Arrêter SecureVault"
        echo "  restart  - Redémarrer SecureVault"
        echo "  logs     - Afficher les logs en temps réel"
        echo "  status   - Afficher l'état des services"
        echo "  clean    - Nettoyage complet (DANGER)"
        echo ""
        echo "Exemples:"
        echo "  $0 start"
        echo "  $0 logs"
        ;;
esac
