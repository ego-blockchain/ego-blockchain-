#!/bin/bash
# Run Full Node 2 (connects to seed node)
echo "🔄 Starting Full Node 2..."

cargo run --release -- \
    --type full \
    --shards 1,2,3 \
    --port 9002 \
    --bootstrap /ip4/127.0.0.1/tcp/9000,/ip4/127.0.0.1/tcp/9001 \
    --storage 150 \
    --bandwidth 300 \
    --enable-sharing \
    --sharing-bandwidth 50 \
    --sharing-limit 1000 \
    --max-peers 200 \
    --metrics \
    --interactive
