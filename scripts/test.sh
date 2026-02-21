#!/usr/bin/env bash

set -euo pipefail

docker run --rm \
  -v "${PWD}:/app" \
  -w /app \
  composer:2 \
  sh -lc 'composer install --no-interaction --prefer-dist && composer test'
