"""
Shared fixtures for CodeRunner integration tests.

These tests run against the Docker container to validate real behavior
that cannot be verified through unit tests alone.
"""

import os
import time
import uuid

import httpx
import pytest


# Configuration from environment
CODERUNNER_URL = os.environ.get("CODERUNNER_URL", "http://localhost:7071")
HEALTH_TIMEOUT = 60  # seconds to wait for container startup
HEALTH_INTERVAL = 2  # seconds between health checks


@pytest.fixture(scope="session")
def base_url() -> str:
    """Base URL for the CodeRunner API."""
    return CODERUNNER_URL


@pytest.fixture(scope="session")
def api_client(base_url: str) -> httpx.Client:
    """HTTP client configured for the CodeRunner API."""
    client = httpx.Client(
        base_url=base_url,
        timeout=httpx.Timeout(60.0, connect=10.0),
    )
    yield client
    client.close()


@pytest.fixture(scope="session", autouse=True)
def wait_for_healthy(base_url: str):
    """Wait for the CodeRunner container to be healthy before running tests."""
    health_url = f"{base_url}/api/health"
    start_time = time.time()

    while time.time() - start_time < HEALTH_TIMEOUT:
        try:
            response = httpx.get(health_url, timeout=5.0)
            if response.status_code == 200:
                return
        except httpx.RequestError:
            pass
        time.sleep(HEALTH_INTERVAL)

    pytest.fail(f"CodeRunner did not become healthy within {HEALTH_TIMEOUT}s")


@pytest.fixture
def unique_id() -> str:
    """Generate a unique identifier for test isolation."""
    return str(uuid.uuid4())[:8]


@pytest.fixture
def run_script(api_client: httpx.Client):
    """Helper fixture to execute scripts via the API."""
    def _run(
        script: str,
        timeout_s: int = 30,
        context: dict = None,
        dependencies: list = None,
        content_type: str = "application/json",
    ) -> httpx.Response:
        if content_type == "application/json":
            payload = {"script": script, "timeout_s": timeout_s}
            if context:
                payload["context"] = context
            if dependencies:
                payload["dependencies"] = dependencies
            return api_client.post("/api/run", json=payload)
        else:
            return api_client.post(
                "/api/run",
                content=script,
                headers={"Content-Type": "text/plain"},
                params={"timeout_s": timeout_s},
            )
    return _run


@pytest.fixture
def run_files(api_client: httpx.Client):
    """Helper fixture to execute files via the API."""
    def _run(
        files: dict,
        entry_point: str,
        timeout_s: int = 30,
        dependencies: list = None,
    ) -> httpx.Response:
        payload = {
            "files": files,
            "entry_point": entry_point,
            "timeout_s": timeout_s,
        }
        if dependencies:
            payload["dependencies"] = dependencies
        return api_client.post("/api/run", json=payload)
    return _run
