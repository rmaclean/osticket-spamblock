#!/usr/bin/env bash

set -euo pipefail

docker run --rm \
  -e SPAMBLOCK_RUN_INTEGRATION_TESTS=1 \
  -v "${PWD}:/app" \
  -w /app \
  composer:2 \
  sh -lc 'composer install --no-interaction --prefer-dist && composer test:integration'
