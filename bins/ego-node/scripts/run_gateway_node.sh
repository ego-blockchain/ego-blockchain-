#!/bin/bash
# Run 5G Gateway Node
echo "🌐 Starting 5G Gateway Node..."

cargo run --release -- \
    --type gateway \
    --port 9004 \
    --bootstrap /ip4/127.0.0.1/tcp/9000,/ip4/127.0.0.1/tcp/9001 \
    --lat 40.7128 \
    --lon -74.0060 \
    --bandwidth 1000 \
    --slice-id slice-001-ultra-low-latency \
    --enable-sharing \
    --sharing-bandwidth 300 \
    --sharing-limit 5000 \
    --max-peers 500 \
    --metrics \
    --interactive
