#!/usr/bin/env bash
set -euo pipefail

CONFIG_FILE=/var/www/html/include/ost-config.php
SAMPLE_CONFIG=/var/www/html/include/ost-sampleconfig.php

if [[ ! -f "$CONFIG_FILE" || ! -s "$CONFIG_FILE" ]]; then
  cp "$SAMPLE_CONFIG" "$CONFIG_FILE"
fi

chown -R www-data:www-data /var/www/html/include /var/www/html/attachments /var/www/html/scp || true
chmod 0666 "$CONFIG_FILE" || true

exec "$@"
