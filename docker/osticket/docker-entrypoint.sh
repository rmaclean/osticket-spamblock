#!/usr/bin/env bash
set -euo pipefail

CONFIG_FILE=/var/www/html/include/ost-config.php
SAMPLE_CONFIG=/var/www/html/include/ost-sampleconfig.php
PERSIST_DIR=/osticket-persist

if [[ -f "$PERSIST_DIR/ost-config.php" && -s "$PERSIST_DIR/ost-config.php" ]]; then
  cp "$PERSIST_DIR/ost-config.php" "$CONFIG_FILE"
else
  cp "$SAMPLE_CONFIG" "$CONFIG_FILE"
  mkdir -p "$PERSIST_DIR"
  cp "$CONFIG_FILE" "$PERSIST_DIR/ost-config.php"
fi

# chown -R www-data:www-data /var/www/html/include /var/www/html/attachments /var/www/html/scp || true
chmod 0666 "$CONFIG_FILE" || true

exec "$@"
