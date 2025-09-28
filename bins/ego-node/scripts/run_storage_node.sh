#!/bin/bash
# Run Storage Node
echo "💾 Starting Storage Node..."

cargo run --release -- \
    --type storage \
    --port 9003 \
    --bootstrap /ip4/127.0.0.1/tcp/9000,/ip4/127.0.0.1/tcp/9001 \
    --storage 500 \
    --lat 37.7749 \
    --lon -122.4194 \
    --bandwidth 200 \
    --enable-sharing \
    --sharing-bandwidth 100 \
    --sharing-limit 2000 \
    --max-peers 100 \
    --metrics \
    --interactive
