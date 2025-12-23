"""
Integration tests for subprocess execution behavior.

Tests the actual Python subprocess execution including:
- Script execution in isolated subprocess
- PYTHONPATH inheritance for pre-installed packages
- Environment variable isolation
- Exit code propagation
"""

import pytest


class TestBasicExecution:
    """Tests for basic script execution."""

    def test_simple_print(self, run_script):
        """Simple print statement should work."""
        response = run_script('print("hello world")')
        data = response.json()

        assert data["exit_code"] == 0
        assert data["stdout"] == "hello world\n"

    def test_multiline_script(self, run_script):
        """Multiline scripts should execute correctly."""
        script = """
x = 5
y = 10
print(x + y)
"""
        response = run_script(script)
        data = response.json()

        assert data["exit_code"] == 0
        assert data["stdout"].strip() == "15"

    def test_stderr_capture(self, run_script):
        """stderr should be captured separately."""
        script = """
import sys
print("stdout", file=sys.stdout)
print("stderr", file=sys.stderr)
"""
        response = run_script(script)
        data = response.json()

        assert data["exit_code"] == 0
        assert "stdout" in data["stdout"]
        assert "stderr" in data["stderr"]

    def test_exit_code_propagation(self, run_script):
        """Non-zero exit codes should propagate."""
        script = "import sys; sys.exit(42)"
        response = run_script(script)
        data = response.json()

        assert data["exit_code"] == 42

    def test_exception_returns_nonzero_exit(self, run_script):
        """Uncaught exceptions should return non-zero exit code."""
        script = 'raise ValueError("test error")'
        response = run_script(script)
        data = response.json()

        assert data["exit_code"] != 0
        assert "ValueError" in data["stderr"]
        assert "test error" in data["stderr"]


class TestPythonPath:
    """Tests for PYTHONPATH and package imports."""

    def test_pythonpath_includes_packages(self, run_script):
        """PYTHONPATH should include .python_packages directory."""
        script = """
import sys
paths = [p for p in sys.path if 'python_packages' in p]
print(len(paths) > 0)
"""
        response = run_script(script)
        data = response.json()

        assert data["exit_code"] == 0
        assert "True" in data["stdout"]


class TestEnvironmentIsolation:
    """Tests for environment variable isolation."""

    def test_basic_env_vars_available(self, run_script):
        """Basic env vars like PATH should be available."""
        script = """
import os
print('PATH' in os.environ)
"""
        response = run_script(script)
        data = response.json()

        assert data["exit_code"] == 0
        assert "True" in data["stdout"]

    def test_pythonioencoding_set(self, run_script):
        """PYTHONIOENCODING should be set to utf-8."""
        script = """
import os
print(os.environ.get('PYTHONIOENCODING', ''))
"""
        response = run_script(script)
        data = response.json()

        assert data["exit_code"] == 0
        assert "utf-8" in data["stdout"].lower()
