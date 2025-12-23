# Multi-stage Dockerfile for CodeRunner Azure Functions
# Simulates production Azure Functions environment for integration testing

ARG PYTHON_VERSION=3.11

# =============================================================================
# Stage 1: Builder - Prepare Python packages
# =============================================================================
FROM python:${PYTHON_VERSION}-slim AS builder

WORKDIR /build

# Copy requirements and install to a target directory
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    --target /build/packages \
    --quiet

# =============================================================================
# Stage 2: Runtime - Azure Functions environment
# =============================================================================
FROM mcr.microsoft.com/azure-functions/python:4-python${PYTHON_VERSION} AS runtime

ENV AzureWebJobsScriptRoot=/home/site/wwwroot \
    AzureFunctionsJobHost__Logging__Console__IsEnabled=true \
    FUNCTIONS_WORKER_RUNTIME=python \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /home/site/wwwroot

# Copy pre-built packages from builder stage
COPY --from=builder /build/packages /home/site/wwwroot/.python_packages/lib/site-packages

# Set PYTHONPATH to include bundled packages (matches production behavior)
ENV PYTHONPATH=/home/site/wwwroot/.python_packages/lib/site-packages

# Copy application code
COPY function_app.py .
COPY host.json .
COPY requirements.txt .
COPY src/ ./src/

# Health check - verify function host is responding
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:80/api/health || exit 1

EXPOSE 80

# =============================================================================
# Stage 3: Test Runner - For running integration tests
# =============================================================================
FROM python:${PYTHON_VERSION}-slim AS test-runner

WORKDIR /app

# Install test dependencies
COPY requirements-dev.txt .
RUN pip install --no-cache-dir -r requirements-dev.txt

# Copy test files
COPY tests/ ./tests/

# Default command runs integration tests
CMD ["pytest", "tests/integration/", "-v", "--tb=short"]
