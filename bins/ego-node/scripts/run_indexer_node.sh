#!/bin/bash
# Run Indexer Node
echo "🔍 Starting Indexer Node..."

cargo run --release -- \
    --type indexer \
    --shards 0,1,2,3 \
    --port 9006 \
    --bootstrap /ip4/127.0.0.1/tcp/9000,/ip4/127.0.0.1/tcp/9001 \
    --storage 200 \
    --bandwidth 300 \
    --enable-sharing \
    --sharing-bandwidth 40 \
    --sharing-limit 800 \
    --max-peers 150 \
    --metrics \
    --interactive
