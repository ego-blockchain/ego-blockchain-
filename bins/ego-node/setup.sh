#!/bin/bash

# Ego Node Setup Script
# Automates the setup process for different node types

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
NODE_TYPE="full"
PORT=9000
STORAGE_GB=100
BANDWIDTH_MBPS=100
ENABLE_SHARING=false
INTERACTIVE=false
BOOTSTRAP_PEERS=""
LATITUDE=""
LONGITUDE=""
SLICE_ID=""

# Functions
print_header() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    Ego Blockchain Node                      ║"
    echo "║                      Setup Script                           ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_step() {
    echo -e "${GREEN}[STEP]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_dependencies() {
    print_step "Checking dependencies..."

    # Check if Rust is installed
    if ! command -v rustc &> /dev/null; then
        print_error "Rust is not installed. Please install Rust from https://rustup.rs/"
        exit 1
    fi

    # Check Rust version
    RUST_VERSION=$(rustc --version | cut -d' ' -f2)
    print_info "Rust version: $RUST_VERSION"

    # Check if Cargo is installed
    if ! command -v cargo &> /dev/null; then
        print_error "Cargo is not installed. Please install Rust toolchain."
        exit 1
    fi

    # Check if git is installed
    if ! command -v git &> /dev/null; then
        print_warning "Git is not installed. Some features may not work properly."
    fi

    print_info "All dependencies are satisfied ✓"
}

build_node() {
    print_step "Building Ego Node..."

    if [ -f "Cargo.toml" ]; then
        print_info "Building in release mode..."
        cargo build --release

        if [ $? -eq 0 ]; then
            print_info "Build successful ✓"
        else
            print_error "Build failed"
            exit 1
        fi
    else
        print_error "No Cargo.toml found. Please run this script from the project root."
        exit 1
    fi
}

generate_config() {
    print_step "Generating node configuration..."

    CONFIG_DIR="./config"
    mkdir -p "$CONFIG_DIR"

    CONFIG_FILE="$CONFIG_DIR/node-config.toml"

    cat > "$CONFIG_FILE" << EOF
# Ego Node Configuration
[node]
type = "$NODE_TYPE"
port = $PORT
interactive = $INTERACTIVE

[network]
max_peers = 200
enable_mdns = true
enable_autonat = true

[storage]
capacity_gb = $STORAGE_GB

[bandwidth]
capacity_mbps = $BANDWIDTH_MBPS
sharing_enabled = $ENABLE_SHARING

[optimization]
enable_compression = true
enable_auto_switching = true
cost_threshold_usd = 100.0
data_threshold_gb = 40.0

EOF

    if [ ! -z "$BOOTSTRAP_PEERS" ]; then
        echo "bootstrap_peers = [\"$BOOTSTRAP_PEERS\"]" >> "$CONFIG_FILE"
    fi

    if [ ! -z "$LATITUDE" ] && [ ! -z "$LONGITUDE" ]; then
        cat >> "$CONFIG_FILE" << EOF

[location]
latitude = $LATITUDE
longitude = $LONGITUDE
EOF
    fi

    if [ ! -z "$SLICE_ID" ]; then
        cat >> "$CONFIG_FILE" << EOF

[5g]
slice_id = "$SLICE_ID"
EOF
    fi

    print_info "Configuration saved to $CONFIG_FILE"
}

create_systemd_service() {
    print_step "Creating systemd service..."

    SERVICE_FILE="/tmp/ego-node.service"
    BINARY_PATH=$(pwd)/target/release/ego-node

    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Ego Blockchain Node
After=network.target
Wants=network.target

[Service]
Type=simple
User=$USER
ExecStart=$BINARY_PATH --type $NODE_TYPE --port $PORT
Restart=always
RestartSec=10
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
EOF

    print_info "Systemd service file created at $SERVICE_FILE"
    print_info "To install, run: sudo cp $SERVICE_FILE /etc/systemd/system/"
    print_info "Then run: sudo systemctl enable ego-node && sudo systemctl start ego-node"
}

setup_firewall() {
    print_step "Setting up firewall rules..."

    if command -v ufw &> /dev/null; then
        print_info "Configuring UFW firewall..."

        # Allow SSH
        sudo ufw allow 22/tcp

        # Allow P2P port
        sudo ufw allow $PORT/tcp

        # Allow HTTP for gateway nodes
        if [ "$NODE_TYPE" = "gateway" ]; then
            sudo ufw allow 8080/tcp
        fi

        print_info "Firewall rules configured. Enable with: sudo ufw enable"
    else
        print_warning "UFW not found. Please configure firewall manually:"
        print_info "  - Allow TCP port $PORT for P2P communication"
        if [ "$NODE_TYPE" = "gateway" ]; then
            print_info "  - Allow TCP port 8080 for HTTP API"
        fi
    fi
}

interactive_setup() {
    print_step "Interactive configuration..."

    echo -e "${YELLOW}Node Type Selection:${NC}"
    echo "1) Full Node (recommended for most users)"
    echo "2) Validator Node (requires stake and high uptime)"
    echo "3) Storage Node (earns rewards for storage)"
    echo "4) Gateway Node (5G edge computing)"
    echo "5) Seed Node (helps bootstrap network)"
    echo "6) Indexer Node (provides search capabilities)"

    read -p "Select node type (1-6): " NODE_CHOICE

    case $NODE_CHOICE in
        1) NODE_TYPE="full" ;;
        2) NODE_TYPE="validator" ;;
        3) NODE_TYPE="storage" ;;
        4) NODE_TYPE="gateway" ;;
        5) NODE_TYPE="seed" ;;
        6) NODE_TYPE="indexer" ;;
        *) print_warning "Invalid choice, using full node" ;;
    esac

    read -p "Port (default: 9000): " INPUT_PORT
    PORT=${INPUT_PORT:-9000}

    read -p "Storage capacity in GB (default: 100): " INPUT_STORAGE
    STORAGE_GB=${INPUT_STORAGE:-100}

    read -p "Bandwidth capacity in Mbps (default: 100): " INPUT_BANDWIDTH
    BANDWIDTH_MBPS=${INPUT_BANDWIDTH:-100}

    read -p "Enable bandwidth sharing to earn EGOC? (y/n): " SHARING_CHOICE
    if [ "$SHARING_CHOICE" = "y" ] || [ "$SHARING_CHOICE" = "Y" ]; then
        ENABLE_SHARING=true
    fi

    if [ "$NODE_TYPE" = "gateway" ] || [ "$NODE_TYPE" = "storage" ]; then
        read -p "Latitude (optional): " LATITUDE
        read -p "Longitude (optional): " LONGITUDE
    fi

    if [ "$NODE_TYPE" = "gateway" ]; then
        read -p "5G Slice ID (optional): " SLICE_ID
    fi

    read -p "Bootstrap peer addresses (optional, comma-separated): " BOOTSTRAP_PEERS

    read -p "Run in interactive mode? (y/n): " INTERACTIVE_CHOICE
    if [ "$INTERACTIVE_CHOICE" = "y" ] || [ "$INTERACTIVE_CHOICE" = "Y" ]; then
        INTERACTIVE=true
    fi
}

show_summary() {
    print_step "Configuration Summary"
    echo -e "${BLUE}================================${NC}"
    echo "Node Type: $NODE_TYPE"
    echo "Port: $PORT"
    echo "Storage: ${STORAGE_GB}GB"
    echo "Bandwidth: ${BANDWIDTH_MBPS}Mbps"
    echo "Sharing Enabled: $ENABLE_SHARING"
    echo "Interactive Mode: $INTERACTIVE"

    if [ ! -z "$LATITUDE" ] && [ ! -z "$LONGITUDE" ]; then
        echo "Location: $LATITUDE, $LONGITUDE"
    fi

    if [ ! -z "$SLICE_ID" ]; then
        echo "5G Slice: $SLICE_ID"
    fi

    if [ ! -z "$BOOTSTRAP_PEERS" ]; then
        echo "Bootstrap Peers: $BOOTSTRAP_PEERS"
    fi
    echo -e "${BLUE}================================${NC}"
}

start_node() {
    print_step "Starting Ego Node..."

    CMD="./target/release/ego-node --type $NODE_TYPE --port $PORT"

    if [ "$STORAGE_GB" -gt 0 ]; then
        CMD="$CMD --storage $STORAGE_GB"
    fi

    if [ "$BANDWIDTH_MBPS" -gt 0 ]; then
        CMD="$CMD --bandwidth $BANDWIDTH_MBPS"
    fi

    if [ "$ENABLE_SHARING" = true ]; then
        CMD="$CMD --enable-sharing"
    fi

    if [ "$INTERACTIVE" = true ]; then
        CMD="$CMD --interactive"
    fi

    if [ ! -z "$LATITUDE" ] && [ ! -z "$LONGITUDE" ]; then
        CMD="$CMD --lat $LATITUDE --lon $LONGITUDE"
    fi

    if [ ! -z "$SLICE_ID" ]; then
        CMD="$CMD --slice-id $SLICE_ID"
    fi

    if [ ! -z "$BOOTSTRAP_PEERS" ]; then
        CMD="$CMD --bootstrap $BOOTSTRAP_PEERS"
    fi

    print_info "Executing: $CMD"
    print_info "Starting node... Press Ctrl+C to stop"

    exec $CMD
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--type)
            NODE_TYPE="$2"
            shift 2
            ;;
        -p|--port)
            PORT="$2"
            shift 2
            ;;
        -s|--storage)
            STORAGE_GB="$2"
            shift 2
            ;;
        -b|--bandwidth)
            BANDWIDTH_MBPS="$2"
            shift 2
            ;;
        --enable-sharing)
            ENABLE_SHARING=true
            shift
            ;;
        -i|--interactive)
            INTERACTIVE=true
            shift
            ;;
        --bootstrap)
            BOOTSTRAP_PEERS="$2"
            shift 2
            ;;
        --lat)
            LATITUDE="$2"
            shift 2
            ;;
        --lon)
            LONGITUDE="$2"
            shift 2
            ;;
        --slice-id)
            SLICE_ID="$2"
            shift 2
            ;;
        --build-only)
            BUILD_ONLY=true
            shift
            ;;
        --config-only)
            CONFIG_ONLY=true
            shift
            ;;
        --service)
            CREATE_SERVICE=true
            shift
            ;;
        --setup)
            INTERACTIVE_SETUP=true
            shift
            ;;
        -h|--help)
            echo "Ego Node Setup Script"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -t, --type TYPE       Node type (full, validator, storage, gateway, seed, indexer)"
            echo "  -p, --port PORT       P2P port (default: 9000)"
            echo "  -s, --storage GB      Storage capacity in GB (default: 100)"
            echo "  -b, --bandwidth MBPS  Bandwidth capacity in Mbps (default: 100)"
            echo "  --enable-sharing      Enable bandwidth sharing"
            echo "  -i, --interactive     Run in interactive mode"
            echo "  --bootstrap PEERS     Bootstrap peer addresses"
            echo "  --lat LATITUDE        Node latitude"
            echo "  --lon LONGITUDE       Node longitude"
            echo "  --slice-id ID         5G slice identifier"
            echo "  --build-only          Only build, don't start"
            echo "  --config-only         Only generate config"
            echo "  --service             Create systemd service"
            echo "  --setup               Interactive setup"
            echo "  -h, --help            Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 --setup                           # Interactive setup"
            echo "  $0 --type validator --port 9000      # Validator node"
            echo "  $0 --type storage --enable-sharing   # Storage node with sharing"
            echo "  $0 --type gateway --slice-id slice1  # 5G gateway node"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Main execution
main() {
    print_header

    if [ "$INTERACTIVE_SETUP" = true ]; then
        interactive_setup
    fi

    check_dependencies

    if [ "$CONFIG_ONLY" != true ]; then
        build_node
    fi

    generate_config

    if [ "$CREATE_SERVICE" = true ]; then
        create_systemd_service
    fi

    setup_firewall

    show_summary

    if [ "$BUILD_ONLY" = true ] || [ "$CONFIG_ONLY" = true ]; then
        print_info "Setup complete. Binary location: ./target/release/ego-node"
        print_info "Configuration: ./config/node-config.toml"
        exit 0
    fi

    print_info "Setup complete! Starting node..."
    sleep 2
    start_node
}

# Run main function
main
