#!/bin/bash
# Run Validator Node
echo "⚖️ Starting Validator Node..."

cargo run --release -- \
    --type validator \
    --shards 0,1,2,3 \
    --port 9005 \
    --bootstrap /ip4/127.0.0.1/tcp/9000,/ip4/127.0.0.1/tcp/9001 \
    --bandwidth 400 \
    --enable-sharing \
    --sharing-bandwidth 25 \
    --sharing-limit 500 \
    --max-peers 150 \
    --metrics \
    --interactive
