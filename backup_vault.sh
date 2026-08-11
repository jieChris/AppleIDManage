#!/bin/sh
set -eu

DOCKER=/usr/bin/docker
CONTAINER=appleid-api

"$DOCKER" exec --user 0 "$CONTAINER" /usr/local/bin/python /app/vault_api.py \
  --backup \
  --db /data/vault.db \
  --key /app/vault.key \
  --backup-root /backups
