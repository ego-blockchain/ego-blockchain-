#!/bin/bash
# Run Seed Node (Bootstrap Node)
echo "🌱 Starting Seed Node..."

cargo run --release -- \
    --type seed \
    --port 9000 \
    --enable-sharing \
    --sharing-bandwidth 200 \
    --sharing-limit 5000 \
    --enable-autonat \
    --enable-mdns \
    --max-peers 1000 \
    --metrics \
    --interactive
