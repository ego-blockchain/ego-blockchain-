#!/bin/bash
# Stop all running nodes

echo "🛑 Stopping Ego Blockchain Network..."

if [ -f .pids ]; then
    PIDS=$(cat .pids)
    echo "Killing processes: $PIDS"
    for pid in $PIDS; do
        if ps -p $pid > /dev/null; then
            echo "Stopping process $pid..."
            kill -TERM $pid
            sleep 1
            if ps -p $pid > /dev/null; then
                echo "Force killing process $pid..."
                kill -9 $pid
            fi
        else
            echo "Process $pid already stopped."
        fi
    done
    rm .pids
else
    echo "No PID file found. Manually killing all ego-node processes..."
    pkill -f ego-node || echo "No ego-node processes found."
fi

echo "✅ Network stopped."
