#!/bin/bash
# Setup entire network with all node types

echo "🚀 Setting up Ego Blockchain Network..."
echo "=================================="

run_node_bg() {
    local script_name=$1
    local log_file=$2
    echo "Starting $script_name..."
    bash "scripts/$script_name" > "logs/$log_file" 2>&1 &
    echo "Node started with PID: $!"
}

mkdir -p logs

echo "Step 1: Starting Seed Node (Bootstrap)..."
bash scripts/run_seed_node.sh > logs/seed_node.log 2>&1 &
SEED_PID=$!
echo "Seed node started with PID: $SEED_PID"
sleep 5

echo "Step 2: Starting Full Nodes..."
bash scripts/run_full_node_1.sh > logs/full_node_1.log 2>&1 &
FULL1_PID=$!
echo "Full node 1 started with PID: $FULL1_PID"
sleep 3

bash scripts/run_full_node_2.sh > logs/full_node_2.log 2>&1 &
FULL2_PID=$!
echo "Full node 2 started with PID: $FULL2_PID"
sleep 3

echo "Step 3: Starting Specialized Nodes..."
bash scripts/run_storage_node.sh > logs/storage_node.log 2>&1 &
STORAGE_PID=$!
echo "Storage node started with PID: $STORAGE_PID"
sleep 2

bash scripts/run_gateway_node.sh > logs/gateway_node.log 2>&1 &
GATEWAY_PID=$!
echo "Gateway node started with PID: $GATEWAY_PID"
sleep 2

bash scripts/run_validator_node.sh > logs/validator_node.log 2>&1 &
VALIDATOR_PID=$!
echo "Validator node started with PID: $VALIDATOR_PID"
sleep 2

bash scripts/run_indexer_node.sh > logs/indexer_node.log 2>&1 &
INDEXER_PID=$!
echo "Indexer node started with PID: $INDEXER_PID"

echo ""
echo "🎉 Network Setup Complete!"
echo "========================="
echo "Running Nodes:"
echo "  - Seed Node (Bootstrap): PID $SEED_PID, Port 9000"
echo "  - Full Node 1: PID $FULL1_PID, Port 9001"
echo "  - Full Node 2: PID $FULL2_PID, Port 9002"
echo "  - Storage Node: PID $STORAGE_PID, Port 9003"
echo "  - Gateway Node: PID $GATEWAY_PID, Port 9004"
echo "  - Validator Node: PID $VALIDATOR_PID, Port 9005"
echo "  - Indexer Node: PID $INDEXER_PID, Port 9006"
echo ""
echo "📋 Monitoring:"
echo "  - Check logs in ./logs/ directory"
echo "  - Use 'ps aux | grep ego-node' to see running processes"
echo "  - Use 'kill <PID>' to stop individual nodes"
echo ""
echo "🔧 Network will auto-connect and start synchronizing..."
echo "Wait 30-60 seconds for all nodes to discover each other."

echo "$SEED_PID $FULL1_PID $FULL2_PID $STORAGE_PID $GATEWAY_PID $VALIDATOR_PID $INDEXER_PID" > .pids

echo ""
echo "Use 'bash scripts/stop_network.sh' to stop all nodes."
