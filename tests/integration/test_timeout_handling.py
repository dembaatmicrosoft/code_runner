"""
Integration tests for timeout handling.

Tests the timeout enforcement including:
- Process termination after timeout
- Exit code 124 for timeouts
- Partial output capture
"""

import pytest


class TestTimeoutBehavior:
    """Tests for script timeout handling."""

    def test_timeout_kills_long_running_script(self, run_script):
        """Scripts exceeding timeout should be terminated."""
        script = """
import time
print("starting")
time.sleep(60)  # Will be killed before this completes
print("finished")
"""
        response = run_script(script, timeout_s=2)
        data = response.json()

        assert data["exit_code"] == 124  # Timeout exit code
        assert "starting" in data["stdout"]
        assert "finished" not in data["stdout"]

    def test_timeout_returns_exit_code_124(self, run_script):
        """Timed out scripts should return exit code 124."""
        script = "import time; time.sleep(30)"
        response = run_script(script, timeout_s=1)
        data = response.json()

        assert data["exit_code"] == 124

    def test_timeout_includes_error_message(self, run_script):
        """Timed out scripts should include timeout message in stderr."""
        script = "import time; time.sleep(30)"
        response = run_script(script, timeout_s=1)
        data = response.json()

        assert "timed out" in data["stderr"].lower()

    def test_fast_script_completes_before_timeout(self, run_script):
        """Scripts completing before timeout should succeed."""
        script = 'print("quick")'
        response = run_script(script, timeout_s=30)
        data = response.json()

        assert data["exit_code"] == 0
        assert data["stdout"] == "quick\n"

    @pytest.mark.timeout(30)
    def test_partial_output_captured_on_timeout(self, run_script):
        """Output produced before timeout should be captured."""
        script = """
import time
import sys
for i in range(100):
    print(f"line {i}")
    sys.stdout.flush()
    time.sleep(0.1)
"""
        response = run_script(script, timeout_s=2)
        data = response.json()

        assert data["exit_code"] == 124
        # Should have captured some output before timeout
        assert "line 0" in data["stdout"]
