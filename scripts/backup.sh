#!/bin/bash

# Script de sauvegarde automatisée pour SecureVault
# Ce script sauvegarde la base de données chiffrée avec rotation

set -e

# Configuration
BACKUP_DIR="/backups"
DATA_DIR="/data"
DB_FILE="securevault.db"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="securevault_backup_${TIMESTAMP}.db"
RETENTION_DAYS=${BACKUP_RETENTION_DAYS:-30}

# Créer le répertoire de sauvegarde s'il n'existe pas
mkdir -p "$BACKUP_DIR"

echo "[$(date)] Début de la sauvegarde de SecureVault..."

# Vérifier que la base de données existe
if [ ! -f "$DATA_DIR/$DB_FILE" ]; then
    echo "[$(date)] ERREUR: Base de données non trouvée: $DATA_DIR/$DB_FILE"
    exit 1
fi

# Créer la sauvegarde
if cp "$DATA_DIR/$DB_FILE" "$BACKUP_DIR/$BACKUP_FILE"; then
    echo "[$(date)] Sauvegarde créée: $BACKUP_FILE"

    # Compresser la sauvegarde si activé
    if [ "${BACKUP_COMPRESSION:-true}" = "true" ]; then
        gzip "$BACKUP_DIR/$BACKUP_FILE"
        BACKUP_FILE="${BACKUP_FILE}.gz"
        echo "[$(date)] Sauvegarde compressée: $BACKUP_FILE"
    fi

    # Nettoyer les anciennes sauvegardes
    echo "[$(date)] Nettoyage des sauvegardes anciennes (> $RETENTION_DAYS jours)..."
    find "$BACKUP_DIR" -name "securevault_backup_*.db*" -mtime +$RETENTION_DAYS -delete

    # Afficher l'espace utilisé
    BACKUP_SIZE=$(du -h "$BACKUP_DIR/$BACKUP_FILE" | cut -f1)
    TOTAL_BACKUPS=$(ls -1 "$BACKUP_DIR"/securevault_backup_*.db* 2>/dev/null | wc -l)

    echo "[$(date)] Sauvegarde terminée avec succès"
    echo "[$(date)] Taille: $BACKUP_SIZE"
    echo "[$(date)] Total des sauvegardes: $TOTAL_BACKUPS"

else
    echo "[$(date)] ERREUR: Échec de la sauvegarde"
    exit 1
fi
