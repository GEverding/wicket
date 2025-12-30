#!/bin/bash

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
NAMESPACE="wicket-poc"
TIMEOUT=300
POLL_INTERVAL=5

# Helper functions
log_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
}

wait_for_pods() {
    log_info "Waiting for all pods to be ready (timeout: ${TIMEOUT}s)..."
    
    local elapsed=0
    while [ $elapsed -lt $TIMEOUT ]; do
        local ready=$(kubectl get pods -n $NAMESPACE --no-headers 2>/dev/null | grep -c "Running" || echo 0)
        local total=$(kubectl get pods -n $NAMESPACE --no-headers 2>/dev/null | wc -l || echo 0)
        
        if [ $total -gt 0 ] && [ $ready -eq $total ]; then
            log_pass "All pods are ready ($ready/$total)"
            return 0
        fi
        
        echo -ne "\r  Ready: $ready/$total pods"
        sleep $POLL_INTERVAL
        elapsed=$((elapsed + POLL_INTERVAL))
    done
    
    log_fail "Pods did not become ready within ${TIMEOUT}s"
    kubectl get pods -n $NAMESPACE
    return 1
}

test_routing() {
    log_info "Testing routing..."
    
    local pass=0
    local fail=0
    
    # Test 1: Root path to echo
    log_info "  Test 1: GET / → echo"
    if response=$(curl -s -w "\n%{http_code}" http://localhost:8080/ 2>/dev/null); then
        http_code=$(echo "$response" | tail -n1)
        body=$(echo "$response" | head -n-1)
        
        if [ "$http_code" = "200" ] && echo "$body" | grep -q "Hostname"; then
            log_pass "    Root path routed to echo (HTTP $http_code)"
            ((pass++))
        else
            log_fail "    Root path failed (HTTP $http_code)"
            ((fail++))
        fi
    else
        log_fail "    Root path request failed"
        ((fail++))
    fi
    
    # Test 2: /echo/test path
    log_info "  Test 2: GET /echo/test → echo"
    if response=$(curl -s -w "\n%{http_code}" http://localhost:8080/echo/test 2>/dev/null); then
        http_code=$(echo "$response" | tail -n1)
        body=$(echo "$response" | head -n-1)
        
        if [ "$http_code" = "200" ] && echo "$body" | grep -q "Hostname"; then
            log_pass "    /echo/test routed to echo (HTTP $http_code)"
            ((pass++))
        else
            log_fail "    /echo/test failed (HTTP $http_code)"
            ((fail++))
        fi
    else
        log_fail "    /echo/test request failed"
        ((fail++))
    fi
    
    # Test 3: /api/get path to httpbin
    log_info "  Test 3: GET /api/get → httpbin"
    if response=$(curl -s -w "\n%{http_code}" http://localhost:8080/api/get 2>/dev/null); then
        http_code=$(echo "$response" | tail -n1)
        body=$(echo "$response" | head -n-1)
        
        if [ "$http_code" = "200" ] && echo "$body" | grep -q "args"; then
            log_pass "    /api/get routed to httpbin (HTTP $http_code)"
            ((pass++))
        else
            log_fail "    /api/get failed (HTTP $http_code)"
            ((fail++))
        fi
    else
        log_fail "    /api/get request failed"
        ((fail++))
    fi
    
    echo ""
    echo "Routing: $pass passed, $fail failed"
    [ $fail -eq 0 ]
}

test_load_balancing() {
    log_info "Testing load balancing..."
    
    local iterations=10
    declare -A pod_hits
    
    log_info "  Sending $iterations requests to /echo..."
    
    for i in $(seq 1 $iterations); do
        if response=$(curl -s http://localhost:8080/echo 2>/dev/null); then
            # Extract hostname from response
            hostname=$(echo "$response" | grep -oP 'Hostname: \K[^ ]+' | head -1)
            if [ -n "$hostname" ]; then
                pod_hits[$hostname]=$((${pod_hits[$hostname]:-0} + 1))
            fi
        fi
    done
    
    echo ""
    if [ ${#pod_hits[@]} -eq 0 ]; then
        log_fail "  No responses received"
        return 1
    fi
    
    log_pass "  Responses from ${#pod_hits[@]} pod(s):"
    for pod in "${!pod_hits[@]}"; do
        echo "    $pod: ${pod_hits[$pod]} hits"
    done
    
    if [ ${#pod_hits[@]} -gt 1 ]; then
        log_pass "  Load balancing is working (requests distributed across pods)"
        return 0
    else
        log_fail "  Load balancing not working (all requests hit same pod)"
        return 1
    fi
}

main() {
    echo "=========================================="
    echo "Wicket k3d POC - Integration Tests"
    echo "=========================================="
    echo ""
    
    # Check if cluster is accessible
    if ! kubectl cluster-info &>/dev/null; then
        log_fail "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    # Check if namespace exists
    if ! kubectl get namespace $NAMESPACE &>/dev/null; then
        log_fail "Namespace '$NAMESPACE' not found"
        exit 1
    fi
    
    # Wait for pods
    if ! wait_for_pods; then
        exit 1
    fi
    
    echo ""
    
    # Run tests
    local all_pass=true
    
    if ! test_routing; then
        all_pass=false
    fi
    
    echo ""
    
    if ! test_load_balancing; then
        all_pass=false
    fi
    
    echo ""
    echo "=========================================="
    
    if [ "$all_pass" = true ]; then
        log_pass "All tests passed!"
        exit 0
    else
        log_fail "Some tests failed"
        exit 1
    fi
}

main "$@"
