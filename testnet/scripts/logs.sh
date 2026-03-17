#!/usr/bin/env bash
# logs.sh — Stream live logs from all Ego Testnet containers.
# chmod +x scripts/logs.sh
set -e

cd "$(dirname "$0")/.."

docker-compose -f docker-compose.yml logs -f --tail=50
