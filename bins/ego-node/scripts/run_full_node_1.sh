#!/bin/bash
# Run Full Node 1 (connects to seed node)
echo "🔄 Starting Full Node 1..."

cargo run --release -- \
    --type full \
    --shards 0,1,2 \
    --port 9001 \
    --bootstrap /ip4/127.0.0.1/tcp/9000 \
    --storage 100 \
    --bandwidth 500 \
    --enable-sharing \
    --sharing-bandwidth 75 \
    --sharing-limit 1500 \
    --max-peers 200 \
    --metrics \
    --interactive
