#!/bin/bash
# =============================================================================
# Wait for CodeRunner to be healthy
# =============================================================================
#
# Polls the health endpoint until the service is ready.
# Useful for CI/CD pipelines and manual testing.
#
# Usage:
#   ./scripts/wait-for-healthy.sh [URL] [TIMEOUT]
#
# Arguments:
#   URL     - Base URL (default: http://localhost:7071)
#   TIMEOUT - Max seconds to wait (default: 60)
#
# =============================================================================

set -e

URL="${1:-http://localhost:7071}"
TIMEOUT="${2:-60}"
INTERVAL=2

HEALTH_URL="$URL/api/health"
START_TIME=$(date +%s)

echo "Waiting for $HEALTH_URL to be healthy..."

while true; do
    CURRENT_TIME=$(date +%s)
    ELAPSED=$((CURRENT_TIME - START_TIME))

    if [ $ELAPSED -ge $TIMEOUT ]; then
        echo "ERROR: Timeout after ${TIMEOUT}s waiting for service to be healthy"
        exit 1
    fi

    if curl -sf "$HEALTH_URL" > /dev/null 2>&1; then
        echo "Service is healthy after ${ELAPSED}s"
        exit 0
    fi

    echo "  Not ready yet (${ELAPSED}s elapsed)..."
    sleep $INTERVAL
done
