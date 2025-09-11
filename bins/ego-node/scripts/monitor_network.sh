#!/bin/bash
# Monitor the network status

echo "📊 Ego Blockchain Network Monitor"
echo "================================"

while true; do
    clear
    echo "📊 Network Status - $(date)"
    echo "================================"

    RUNNING=$(ps aux | grep -c "[e]go-node")
    echo "Running Nodes: $RUNNING"
    echo ""

    echo "📋 Node Processes:"
    ps aux | grep "[e]go-node" | awk '{print $2, $11, $12, $13, $14, $15}' | while read line; do
        echo "  $line"
    done
    echo ""

    echo "📜 Recent Activity (last 10 lines from each log):"
    for log in logs/*.log; do
        if [ -f "$log" ]; then
            echo "--- $(basename $log) ---"
            tail -n 3 "$log" | head -n 3
            echo ""
        fi
    done

    echo "Press Ctrl+C to stop monitoring"
    sleep 10
done
