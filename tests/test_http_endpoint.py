"""
Integration tests for HTTP endpoint behavior.

Tests the CodeRunner API's HTTP interface including:
- Route handling and content-type negotiation
- JSON and raw request modes
- Error responses and status codes
"""

import pytest


class TestHealthEndpoint:
    """Tests for the /api/health endpoint."""

    def test_health_returns_ok(self, api_client):
        """Health endpoint should return 200 OK."""
        response = api_client.get("/api/health")
        assert response.status_code == 200
        assert response.text == "OK"


class TestRunEndpoint:
    """Tests for the /api/run endpoint."""

    def test_json_mode_basic_execution(self, run_script):
        """JSON mode should execute script and return result."""
        response = run_script('print("hello")')
        assert response.status_code == 200

        data = response.json()
        assert data["exit_code"] == 0
        assert data["stdout"] == "hello\n"
        assert data["stderr"] == ""
        assert data["artifacts"] == {}

    def test_raw_mode_basic_execution(self, api_client):
        """Raw mode (text/plain) should execute script."""
        response = api_client.post(
            "/api/run",
            content='print("raw mode")',
            headers={"Content-Type": "text/plain"},
        )
        assert response.status_code == 200

        data = response.json()
        assert data["exit_code"] == 0
        assert data["stdout"] == "raw mode\n"

    def test_missing_script_returns_400(self, api_client):
        """Request without script should return 400."""
        response = api_client.post("/api/run", json={})
        assert response.status_code == 400
        assert "error" in response.json()

    def test_invalid_json_returns_400(self, api_client):
        """Malformed JSON should return 400."""
        response = api_client.post(
            "/api/run",
            content="not valid json",
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 400

    def test_response_format(self, run_script):
        """Response should have required fields."""
        response = run_script('x = 1')
        assert response.status_code == 200

        data = response.json()
        assert "exit_code" in data
        assert "stdout" in data
        assert "stderr" in data
        assert "artifacts" in data
