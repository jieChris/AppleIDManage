#!/bin/sh
set -eu

DOCKER=/usr/bin/docker
CONTAINER=appleid-api
DATA_DIR=/root/appleid-vault/data
BACKUP_ROOT=/root/appleid-vault/backups
TODAY=$(/bin/date -u +%Y-%m-%d)
STAGING="$DATA_DIR/.vault-backup.db"
TARGET_DIR="$BACKUP_ROOT/$TODAY"

"$DOCKER" exec --user 10001 "$CONTAINER" /usr/local/bin/python /app/vault_api.py \
  --backup-sqlite \
  --db /data/vault.db \
  --output /data/.vault-backup.db >/dev/null

/usr/bin/install -d -m 0700 "$TARGET_DIR"
/usr/bin/install -m 0600 "$STAGING" "$TARGET_DIR/vault.db"
/usr/bin/install -m 0600 /root/appleid-vault/secrets/vault.key "$TARGET_DIR/vault.key"
/usr/bin/unlink "$STAGING"

/usr/bin/find "$BACKUP_ROOT" -mindepth 2 -maxdepth 2 -type f -mtime +7 -delete
/usr/bin/find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -empty -mtime +7 -delete
