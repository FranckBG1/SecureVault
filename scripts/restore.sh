#!/bin/bash

# Script de restauration de sauvegarde pour SecureVault
# Usage: ./restore.sh <backup_file>

set -e

if [ $# -ne 1 ]; then
    echo "Usage: $0 <backup_file>"
    echo "Exemple: $0 securevault_backup_20231201_120000.db.gz"
    exit 1
fi

BACKUP_FILE="$1"
BACKUP_DIR="/backups"
DATA_DIR="/data"
DB_FILE="securevault.db"

# Vérifier que le fichier de sauvegarde existe
if [ ! -f "$BACKUP_DIR/$BACKUP_FILE" ]; then
    echo "ERREUR: Fichier de sauvegarde non trouvé: $BACKUP_DIR/$BACKUP_FILE"
    exit 1
fi

echo "[$(date)] Début de la restauration depuis: $BACKUP_FILE"

# Créer une sauvegarde de la base actuelle
if [ -f "$DATA_DIR/$DB_FILE" ]; then
    CURRENT_BACKUP="$DATA_DIR/${DB_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
    cp "$DATA_DIR/$DB_FILE" "$CURRENT_BACKUP"
    echo "[$(date)] Base actuelle sauvegardée: $CURRENT_BACKUP"
fi

# Restaurer selon le type de fichier
if [[ "$BACKUP_FILE" == *.gz ]]; then
    # Fichier compressé
    gunzip -c "$BACKUP_DIR/$BACKUP_FILE" > "$DATA_DIR/$DB_FILE"
else
    # Fichier non compressé
    cp "$BACKUP_DIR/$BACKUP_FILE" "$DATA_DIR/$DB_FILE"
fi

echo "[$(date)] Restauration terminée avec succès"
echo "[$(date)] Base de données restaurée: $DATA_DIR/$DB_FILE"
