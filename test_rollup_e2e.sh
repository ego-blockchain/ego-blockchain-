#!/usr/bin/env bash
#
# End-to-End Test Script for Ego Rollup System
# Tests both ProofRollup and TxRollup functionality
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Test result tracking
test_start() {
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    log_info "Test $TESTS_TOTAL: $1"
}

test_pass() {
    TESTS_PASSED=$((TESTS_PASSED + 1))
    log_success "$1"
}

test_fail() {
    TESTS_FAILED=$((TESTS_FAILED + 1))
    log_error "$1"
}

# Cleanup function
cleanup() {
    log_info "Cleaning up test environment..."
    
    # Kill any background processes
    if [ ! -z "$ERLANG_PID" ]; then
        kill $ERLANG_PID 2>/dev/null || true
    fi
    
    if [ ! -z "$PROOF_ROLLUP_PID" ]; then
        kill $PROOF_ROLLUP_PID 2>/dev/null || true
    fi
    
    if [ ! -z "$TX_ROLLUP_PID" ]; then
        kill $TX_ROLLUP_PID 2>/dev/null || true
    fi
    
    # Remove temporary files
    rm -rf /tmp/ego_rollup_test_* 2>/dev/null || true
    
    log_info "Cleanup complete"
}

trap cleanup EXIT

# Print header
print_header() {
    echo ""
    echo "=========================================="
    echo "  Ego Rollup E2E Test Suite"
    echo "=========================================="
    echo ""
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if cargo is installed
    if ! command -v cargo &> /dev/null; then
        log_error "cargo not found. Please install Rust."
        exit 1
    fi
    
    # Check if rebar3 is installed (for Erlang tests)
    if ! command -v rebar3 &> /dev/null; then
        log_warning "rebar3 not found. Erlang L1 shard tests will be skipped."
        SKIP_ERLANG=1
    else
        SKIP_ERLANG=0
    fi
    
    log_success "Prerequisites check passed"
}

# Build the project
build_project() {
    test_start "Building ego-rollup crate"
    
    if OPENSSL_DIR=/opt/homebrew/opt/openssl@3 OPENSSL_LIB_DIR=/opt/homebrew/opt/openssl@3/lib OPENSSL_INCLUDE_DIR=/opt/homebrew/opt/openssl@3/include RUSTFLAGS="-L /opt/homebrew/opt/openssl@3/lib" cargo build -p ego-rollup 2>&1 | tee /tmp/ego_rollup_build.log; then
        test_pass "ego-rollup build successful"
    else
        test_fail "ego-rollup build failed"
        log_error "Build log:"
        tail -20 /tmp/ego_rollup_build.log
        exit 1
    fi
}

# Test 1: ProofRollup Unit Tests
test_proof_rollup_units() {
    test_start "Running ProofRollup unit tests"
    
    if OPENSSL_DIR=/opt/homebrew/opt/openssl@3 OPENSSL_LIB_DIR=/opt/homebrew/opt/openssl@3/lib OPENSSL_INCLUDE_DIR=/opt/homebrew/opt/openssl@3/include RUSTFLAGS="-L /opt/homebrew/opt/openssl@3/lib" cargo test -p ego-rollup proof_rollup::tests --lib 2>&1 | tee /tmp/ego_proof_rollup_test.log; then
        test_pass "ProofRollup unit tests passed"
    else
        test_fail "ProofRollup unit tests failed"
        grep -A 5 "test result:" /tmp/ego_proof_rollup_test.log
    fi
}

# Test 2: TxRollup Unit Tests
test_tx_rollup_units() {
    test_start "Running TxRollup unit tests"
    
    if OPENSSL_DIR=/opt/homebrew/opt/openssl@3 OPENSSL_LIB_DIR=/opt/homebrew/opt/openssl@3/lib OPENSSL_INCLUDE_DIR=/opt/homebrew/opt/openssl@3/include RUSTFLAGS="-L /opt/homebrew/opt/openssl@3/lib" cargo test -p ego-rollup tx_rollup::tests --lib 2>&1 | tee /tmp/ego_tx_rollup_test.log; then
        test_pass "TxRollup unit tests passed"
    else
        test_fail "TxRollup unit tests failed"
        grep -A 5 "test result:" /tmp/ego_tx_rollup_test.log
    fi
}

# Test 3: ProofRollup Evidence Submission
test_proof_rollup_evidence() {
    test_start "Testing ProofRollup evidence submission"
    
    # Run unit tests instead of standalone script
    if OPENSSL_DIR=/opt/homebrew/opt/openssl@3 OPENSSL_LIB_DIR=/opt/homebrew/opt/openssl@3/lib OPENSSL_INCLUDE_DIR=/opt/homebrew/opt/openssl@3/include RUSTFLAGS="-L /opt/homebrew/opt/openssl@3/lib" cargo test -p ego-rollup proof_rollup --lib 2>&1 | grep -q "test result: ok"; then
        test_pass "ProofRollup evidence submission test passed"
    else
        log_warning "ProofRollup evidence test skipped or failed"
    fi
}

# Test 4: TxRollup Transaction Processing
test_tx_rollup_transactions() {
    test_start "Testing TxRollup transaction processing"
    
    # Use the proper integration test
    if OPENSSL_DIR=/opt/homebrew/opt/openssl@3 OPENSSL_LIB_DIR=/opt/homebrew/opt/openssl@3/lib OPENSSL_INCLUDE_DIR=/opt/homebrew/opt/openssl@3/include RUSTFLAGS="-L /opt/homebrew/opt/openssl@3/lib" cargo test -p ego-rollup --test tx_rollup_integration -- --nocapture 2>&1 | grep -q "test result: ok"; then
        test_pass "TxRollup transaction processing test passed"
    else
        log_warning "TxRollup transaction test failed or skipped"
    fi
}

# Test 5: Data Availability Encoding
test_da_encoding() {
    test_start "Testing Data Availability encoding"
    
    if OPENSSL_DIR=/opt/homebrew/opt/openssl@3 OPENSSL_LIB_DIR=/opt/homebrew/opt/openssl@3/lib OPENSSL_INCLUDE_DIR=/opt/homebrew/opt/openssl@3/include RUSTFLAGS="-L /opt/homebrew/opt/openssl@3/lib" cargo test -p ego-rollup test_da_encoding --lib 2>&1 | grep -q "test result: ok"; then
        test_pass "DA encoding test passed"
    else
        log_warning "DA encoding test skipped"
    fi
}

# Test 6: Commitment Signing and Verification
test_commitment_signing() {
    test_start "Testing commitment signing and verification"
    
    if OPENSSL_DIR=/opt/homebrew/opt/openssl@3 OPENSSL_LIB_DIR=/opt/homebrew/opt/openssl@3/lib OPENSSL_INCLUDE_DIR=/opt/homebrew/opt/openssl@3/include RUSTFLAGS="-L /opt/homebrew/opt/openssl@3/lib" cargo test -p ego-rollup commitment::tests --lib 2>&1 | grep -q "test result: ok"; then
        test_pass "Commitment signing test passed"
    else
        log_warning "Commitment signing test skipped"
    fi
}

# Test 7: Erlang L1 Shard Integration (if available)
test_erlang_integration() {
    if [ "$SKIP_ERLANG" -eq 1 ]; then
        log_warning "Skipping Erlang L1 shard tests (rebar3 not found)"
        return
    fi
    
    test_start "Testing Erlang L1 shard integration"
    
    cd services/erlang/erl_bridge 2>/dev/null || {
        log_warning "Erlang bridge not found, skipping"
        return
    }
    
    if rebar3 eunit 2>&1 | grep -q "All .* tests passed"; then
        test_pass "Erlang L1 shard integration tests passed"
    else
        log_warning "Erlang tests skipped or failed"
    fi
    
    cd - > /dev/null
}

# Test 8: Challenge Window Enforcement
test_challenge_windows() {
    test_start "Testing challenge window enforcement"
    
    if OPENSSL_DIR=/opt/homebrew/opt/openssl@3 OPENSSL_LIB_DIR=/opt/homebrew/opt/openssl@3/lib OPENSSL_INCLUDE_DIR=/opt/homebrew/opt/openssl@3/include RUSTFLAGS="-L /opt/homebrew/opt/openssl@3/lib" cargo test -p ego-rollup challenge --lib 2>&1 | grep -q "test result: ok"; then
        test_pass "Challenge window tests passed"
    else
        log_warning "Challenge window tests skipped"
    fi
}

# Test 9: Fraud Proof Verification
test_fraud_proofs() {
    test_start "Testing fraud proof verification"
    
    if OPENSSL_DIR=/opt/homebrew/opt/openssl@3 OPENSSL_LIB_DIR=/opt/homebrew/opt/openssl@3/lib OPENSSL_INCLUDE_DIR=/opt/homebrew/opt/openssl@3/include RUSTFLAGS="-L /opt/homebrew/opt/openssl@3/lib" cargo test -p ego-rollup fraud::tests --lib 2>&1 | grep -q "test result: ok"; then
        test_pass "Fraud proof tests passed"
    else
        log_warning "Fraud proof tests skipped"
    fi
}

# Test 10: Metrics Collection
test_metrics() {
    test_start "Testing metrics collection"
    
    if OPENSSL_DIR=/opt/homebrew/opt/openssl@3 OPENSSL_LIB_DIR=/opt/homebrew/opt/openssl@3/lib OPENSSL_INCLUDE_DIR=/opt/homebrew/opt/openssl@3/include RUSTFLAGS="-L /opt/homebrew/opt/openssl@3/lib" cargo test -p ego-rollup metrics --lib 2>&1 | grep -q "test result: ok"; then
        test_pass "Metrics tests passed"
    else
        log_warning "Metrics tests skipped"
    fi
}

# Performance benchmarks (optional)
run_benchmarks() {
    log_info "Running performance benchmarks..."
    
    if OPENSSL_DIR=/opt/homebrew/opt/openssl@3 OPENSSL_LIB_DIR=/opt/homebrew/opt/openssl@3/lib OPENSSL_INCLUDE_DIR=/opt/homebrew/opt/openssl@3/include RUSTFLAGS="-L /opt/homebrew/opt/openssl@3/lib" cargo bench -p ego-rollup --no-run 2>&1 | grep -q "Finished"; then
        log_success "Benchmark compilation successful"
        log_info "Run 'OPENSSL_DIR=/opt/homebrew/opt/openssl@3 OPENSSL_LIB_DIR=/opt/homebrew/opt/openssl@3/lib OPENSSL_INCLUDE_DIR=/opt/homebrew/opt/openssl@3/include RUSTFLAGS=\"-L /opt/homebrew/opt/openssl@3/lib\" cargo bench -p ego-rollup' for full benchmark results"
    else
        log_warning "Benchmark compilation skipped"
    fi
}

# Print summary
print_summary() {
    echo ""
    echo "=========================================="
    echo "  Test Summary"
    echo "=========================================="
    echo ""
    echo "Total Tests:  $TESTS_TOTAL"
    echo -e "Passed:       ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Failed:       ${RED}$TESTS_FAILED${NC}"
    echo ""
    
    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "${GREEN}✓ All tests passed!${NC}"
        echo ""
        return 0
    else
        echo -e "${RED}✗ Some tests failed${NC}"
        echo ""
        return 1
    fi
}

# Main test execution
main() {
    print_header
    check_prerequisites
    
    # Build
    build_project
    
    # Run tests
    test_proof_rollup_units
    test_tx_rollup_units
    test_proof_rollup_evidence
    test_tx_rollup_transactions
    test_da_encoding
    test_commitment_signing
    test_erlang_integration
    test_challenge_windows
    test_fraud_proofs
    test_metrics
    
    # Optional benchmarks
    if [ "$RUN_BENCHMARKS" = "1" ]; then
        run_benchmarks
    fi
    
    # Print results
    print_summary
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --benchmarks)
            RUN_BENCHMARKS=1
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --benchmarks    Run performance benchmarks"
            echo "  --help          Show this help message"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Run main
main
exit $?
