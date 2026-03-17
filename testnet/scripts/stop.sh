#!/usr/bin/env bash
# stop.sh — Tear down the Ego Testnet.
# chmod +x scripts/stop.sh
set -e

cd "$(dirname "$0")/.."

echo "Stopping Ego Testnet..."
docker-compose -f docker-compose.yml down
echo "Done."
