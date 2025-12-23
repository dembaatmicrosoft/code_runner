"""
Integration tests for the Files API.

Tests the files + entry_point execution mode including:
- Basic file execution
- Multi-file projects with imports
- Nested directory structures
- Binary files
- Backward compatibility with legacy API
"""

import base64

import pytest


class TestBasicFilesExecution:
    """Tests for basic files API execution."""

    def test_single_file_execution(self, run_files):
        """Single file with entry_point executes correctly."""
        files = {
            "main.py": "print('hello from files api')"
        }
        response = run_files(files, "main.py")
        data = response.json()

        assert response.status_code == 200
        assert data["exit_code"] == 0
        assert "hello from files api" in data["stdout"]

    def test_multi_file_project(self, run_files):
        """Multi-file project with imports works."""
        files = {
            "main.py": "from utils import greet\nprint(greet('world'))",
            "utils.py": "def greet(name):\n    return f'Hello, {name}!'"
        }
        response = run_files(files, "main.py")
        data = response.json()

        assert response.status_code == 200
        assert data["exit_code"] == 0
        assert "Hello, world!" in data["stdout"]

    def test_nested_directory_imports(self, run_files):
        """Nested directories with imports work correctly."""
        files = {
            "main.py": "from lib.helpers import add\nprint(add(2, 3))",
            "lib/__init__.py": "",
            "lib/helpers.py": "def add(a, b):\n    return a + b"
        }
        response = run_files(files, "main.py")
        data = response.json()

        assert response.status_code == 200
        assert data["exit_code"] == 0
        assert "5" in data["stdout"]

    def test_entry_point_in_subdirectory(self, run_files):
        """Entry point can be in a subdirectory."""
        files = {
            "src/main.py": "print('running from src/')",
            "src/__init__.py": ""
        }
        response = run_files(files, "src/main.py")
        data = response.json()

        assert response.status_code == 200
        assert data["exit_code"] == 0
        assert "running from src/" in data["stdout"]


class TestFilesWithData:
    """Tests for files API with data files."""

    def test_read_data_file(self, run_files):
        """Script can read data files from files dict."""
        files = {
            "main.py": """
with open('data.csv') as f:
    print(f.read())
""",
            "data.csv": "name,value\nalice,100\nbob,200"
        }
        response = run_files(files, "main.py")
        data = response.json()

        assert response.status_code == 200
        assert data["exit_code"] == 0
        assert "alice,100" in data["stdout"]

    def test_read_nested_data_file(self, run_files):
        """Script can read nested data files."""
        files = {
            "main.py": """
with open('config/settings.json') as f:
    import json
    config = json.load(f)
    print(config['debug'])
""",
            "config/settings.json": '{"debug": true, "env": "test"}'
        }
        response = run_files(files, "main.py")
        data = response.json()

        assert response.status_code == 200
        assert data["exit_code"] == 0
        assert "True" in data["stdout"]

    def test_binary_file_support(self, run_files):
        """Binary files encoded as base64 are handled correctly."""
        binary_data = bytes([0, 1, 2, 3, 255, 254, 253])
        encoded = base64.b64encode(binary_data).decode("ascii")
        files = {
            "main.py": """
with open('data.bin', 'rb') as f:
    data = f.read()
    print(len(data))
    print(list(data[:4]))
""",
            "data.bin": {"content": encoded, "encoding": "base64"}
        }
        response = run_files(files, "main.py")
        data = response.json()

        assert response.status_code == 200
        assert data["exit_code"] == 0
        assert "7" in data["stdout"]  # Length
        assert "[0, 1, 2, 3]" in data["stdout"]


class TestFilesWithArtifacts:
    """Tests for files API artifact collection."""

    def test_artifacts_collected(self, run_files):
        """Output files are collected as artifacts."""
        files = {
            "main.py": """
import os
os.makedirs('output', exist_ok=True)
with open('output/result.txt', 'w') as f:
    f.write('computation result')
print('done')
"""
        }
        response = run_files(files, "main.py")
        data = response.json()

        assert response.status_code == 200
        assert data["exit_code"] == 0
        assert "result.txt" in data["artifacts"]
        assert "computation result" in data["artifacts"]["result.txt"]

    def test_nested_artifacts_collected(self, run_files):
        """Files mode collects artifacts from nested directories."""
        files = {
            "main.py": """
import os
os.makedirs('output/reports/daily', exist_ok=True)
with open('output/summary.txt', 'w') as f:
    f.write('top level')
with open('output/reports/daily/report.txt', 'w') as f:
    f.write('nested report')
"""
        }
        response = run_files(files, "main.py")
        data = response.json()

        assert response.status_code == 200
        assert data["exit_code"] == 0
        assert "summary.txt" in data["artifacts"]
        assert "reports/daily/report.txt" in data["artifacts"]
        assert data["artifacts"]["reports/daily/report.txt"] == "nested report"


class TestFilesWithDependencies:
    """Tests for files API with dependencies."""

    def test_pre_installed_packages(self, run_files):
        """Pre-installed packages work with files API."""
        files = {
            "main.py": "import numpy as np\nprint(np.array([1,2,3]).sum())"
        }
        response = run_files(files, "main.py")
        data = response.json()

        assert response.status_code == 200
        assert data["exit_code"] == 0
        assert "6" in data["stdout"]


class TestFilesValidation:
    """Tests for files API validation."""

    def test_rejects_missing_entry_point(self, api_client):
        """Missing entry_point returns 400."""
        response = api_client.post(
            "/api/run",
            json={"files": {"main.py": "print(1)"}}
        )
        assert response.status_code == 400

    def test_rejects_entry_point_not_in_files(self, run_files):
        """Entry point not in files returns 400."""
        files = {"utils.py": "pass"}
        response = run_files(files, "main.py")

        assert response.status_code == 400
        assert "not found" in response.text

    def test_rejects_path_traversal(self, api_client):
        """Path traversal attempts are rejected."""
        response = api_client.post(
            "/api/run",
            json={
                "files": {
                    "main.py": "print(1)",
                    "../../../etc/passwd": "x"
                },
                "entry_point": "main.py"
            }
        )
        assert response.status_code == 400

    def test_rejects_mixed_api_modes(self, api_client):
        """Cannot mix files with script."""
        response = api_client.post(
            "/api/run",
            json={
                "files": {"main.py": "print(1)"},
                "script": "print(2)",
                "entry_point": "main.py"
            }
        )
        assert response.status_code == 400
        assert "Cannot use both" in response.text


class TestBackwardCompatibility:
    """Tests ensuring legacy API still works."""

    def test_legacy_script_mode(self, run_script):
        """Legacy script mode continues to work."""
        response = run_script("print('legacy mode works')")
        data = response.json()

        assert response.status_code == 200
        assert data["exit_code"] == 0
        assert "legacy mode works" in data["stdout"]

    def test_legacy_with_context(self, run_script):
        """Legacy mode with context files works."""
        response = run_script(
            "with open('./input/data.txt') as f: print(f.read())",
            context={"data.txt": "context content"}
        )
        data = response.json()

        assert response.status_code == 200
        assert data["exit_code"] == 0
        assert "context content" in data["stdout"]
