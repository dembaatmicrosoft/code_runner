#!/bin/bash
# =============================================================================
# Run CodeRunner Integration Tests
# =============================================================================
#
# This script builds and runs the Docker-based integration tests.
# It handles container lifecycle and cleanup automatically.
#
# Usage:
#   ./scripts/run-integration-tests.sh
#
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="$PROJECT_ROOT/docker/docker-compose.yml"

echo "=== CodeRunner Integration Tests ==="
echo ""

# Change to project root
cd "$PROJECT_ROOT"

# Cleanup function
cleanup() {
    echo ""
    echo "=== Cleaning up ==="
    docker-compose -f "$COMPOSE_FILE" down -v 2>/dev/null || true
}

# Register cleanup on exit
trap cleanup EXIT

# Build and run tests
echo "=== Building containers ==="
docker-compose -f "$COMPOSE_FILE" build

echo ""
echo "=== Starting services ==="
docker-compose -f "$COMPOSE_FILE" up \
    --abort-on-container-exit \
    --exit-code-from test-runner

echo ""
echo "=== Integration tests completed successfully ==="
