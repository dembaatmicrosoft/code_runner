# Copyright (c) 2025 Microsoft Corporation.
# Licensed under the MIT License. See LICENSE file in the project root.
"""
Unit Tests for Security Harness (PEP 578 Audit Hooks)

Tests the runtime security enforcement that blocks dangerous operations
at the interpreter level before they reach the OS.

Test Philosophy:
    - Tests run the harness as a subprocess to avoid audit hook pollution
    - Each test validates one specific blocked or allowed operation
    - Security violations result in non-zero exit and error in stderr
"""
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

HARNESS_PATH = Path(__file__).parent.parent.parent / "src" / "harness.py"


def run_script_with_harness(script_content: str, timeout: int = 5) -> tuple:
    """
    Run a script through the security harness.

    Returns (exit_code, stdout, stderr).
    """
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False
    ) as f:
        f.write(script_content)
        script_path = f.name

    try:
        result = subprocess.run(
            [sys.executable, str(HARNESS_PATH), script_path],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=HARNESS_PATH.parent,
        )
        return result.returncode, result.stdout, result.stderr
    finally:
        Path(script_path).unlink(missing_ok=True)


class TestBlockedOperations:
    """Tests that verify dangerous operations are blocked."""

    def test_blocks_socket_connect(self):
        """Verify socket.connect is blocked."""
        script = """
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 80))
"""
        exit_code, stdout, stderr = run_script_with_harness(script)

        assert exit_code != 0
        assert "socket.connect" in stderr
        assert "Security policy violation" in stderr

    def test_blocks_socket_bind(self):
        """Verify socket.bind is blocked."""
        script = """
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('127.0.0.1', 0))
"""
        exit_code, stdout, stderr = run_script_with_harness(script)

        assert exit_code != 0
        assert "socket.bind" in stderr
        assert "Security policy violation" in stderr

    def test_blocks_subprocess_popen(self):
        """Verify subprocess.Popen is blocked."""
        script = """
import subprocess
subprocess.Popen(['echo', 'hello'])
"""
        exit_code, stdout, stderr = run_script_with_harness(script)

        assert exit_code != 0
        assert "subprocess.Popen" in stderr
        assert "Security policy violation" in stderr

    def test_blocks_subprocess_run(self):
        """Verify subprocess.run (uses Popen internally) is blocked."""
        script = """
import subprocess
subprocess.run(['echo', 'hello'])
"""
        exit_code, stdout, stderr = run_script_with_harness(script)

        assert exit_code != 0
        assert "subprocess.Popen" in stderr

    def test_blocks_os_system(self):
        """Verify os.system is blocked."""
        script = """
import os
os.system('echo hello')
"""
        exit_code, stdout, stderr = run_script_with_harness(script)

        assert exit_code != 0
        assert "os.system" in stderr
        assert "Security policy violation" in stderr

    def test_blocks_os_exec(self):
        """Verify os.exec* family is blocked (prevents process replacement)."""
        script = """
import os
os.execvp('echo', ['echo', 'hello'])
"""
        exit_code, stdout, stderr = run_script_with_harness(script)

        assert exit_code != 0
        assert "os.exec" in stderr
        assert "Security policy violation" in stderr

    def test_blocks_os_fork(self):
        """Verify os.fork is blocked (used by os.spawn* on POSIX)."""
        script = """
import os
os.fork()
"""
        exit_code, stdout, stderr = run_script_with_harness(script)

        assert exit_code != 0
        assert "os.fork" in stderr
        assert "Security policy violation" in stderr

    def test_blocks_os_posix_spawn(self):
        """Verify os.posix_spawn is blocked."""
        script = """
import os
os.posix_spawn('/bin/echo', ['/bin/echo', 'hello'], os.environ)
"""
        exit_code, stdout, stderr = run_script_with_harness(script)

        assert exit_code != 0
        assert "os.posix_spawn" in stderr
        assert "Security policy violation" in stderr


class TestAllowedOperations:
    """Tests that verify legitimate operations still work."""

    def test_allows_print(self):
        """Verify basic print works."""
        script = "print('hello world')"

        exit_code, stdout, stderr = run_script_with_harness(script)

        assert exit_code == 0
        assert "hello world" in stdout

    def test_allows_file_read(self):
        """Verify file reading works."""
        script = """
import tempfile
import os
with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
    f.write('test content')
    path = f.name
with open(path, 'r') as f:
    print(f.read())
os.unlink(path)
"""
        exit_code, stdout, stderr = run_script_with_harness(script)

        assert exit_code == 0
        assert "test content" in stdout

    def test_allows_file_write(self):
        """Verify file writing works."""
        script = """
import tempfile
import os
with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
    f.write('written content')
    path = f.name
print(f'wrote to {path}')
os.unlink(path)
"""
        exit_code, stdout, stderr = run_script_with_harness(script)

        assert exit_code == 0
        assert "wrote to" in stdout

    def test_allows_math_operations(self):
        """Verify math/numpy-style operations work."""
        script = """
import math
result = math.sqrt(16) + math.pi
print(f'result={result}')
"""
        exit_code, stdout, stderr = run_script_with_harness(script)

        assert exit_code == 0
        assert "result=" in stdout

    def test_allows_json_operations(self):
        """Verify JSON serialization works."""
        script = """
import json
data = {'key': 'value', 'numbers': [1, 2, 3]}
print(json.dumps(data))
"""
        exit_code, stdout, stderr = run_script_with_harness(script)

        assert exit_code == 0
        assert '"key"' in stdout

    def test_allows_sys_exit(self):
        """Verify sys.exit with code works."""
        script = """
import sys
sys.exit(42)
"""
        exit_code, stdout, stderr = run_script_with_harness(script)

        assert exit_code == 42


class TestErrorHandling:
    """Tests for error message clarity and edge cases."""

    def test_error_message_includes_event_name(self):
        """Verify error messages clearly identify the blocked event."""
        script = """
import socket
s = socket.socket()
s.connect(('localhost', 80))
"""
        exit_code, stdout, stderr = run_script_with_harness(script)

        assert "socket.connect" in stderr
        assert "blocked" in stderr

    def test_script_exception_propagates(self):
        """Verify user script exceptions are reported correctly."""
        script = """
raise ValueError('intentional error')
"""
        exit_code, stdout, stderr = run_script_with_harness(script)

        assert exit_code != 0
        assert "ValueError" in stderr
        assert "intentional error" in stderr

    def test_missing_script_path_shows_usage(self):
        """Verify missing script path shows usage message."""
        result = subprocess.run(
            [sys.executable, str(HARNESS_PATH)],
            capture_output=True,
            text=True,
            cwd=HARNESS_PATH.parent,
        )

        assert result.returncode == 1
        assert "Usage" in result.stderr


class TestScriptContext:
    """Tests that verify script execution context is correct."""

    def test_name_is_main(self):
        """Verify __name__ is '__main__' in executed script."""
        script = """
print(f'name={__name__}')
"""
        exit_code, stdout, stderr = run_script_with_harness(script)

        assert exit_code == 0
        assert "name=__main__" in stdout

    def test_argv_excludes_harness(self):
        """Verify sys.argv[0] is the user script, not harness."""
        script = """
import sys
print(f'argv0={sys.argv[0]}')
"""
        exit_code, stdout, stderr = run_script_with_harness(script)

        assert exit_code == 0
        assert "harness" not in stdout.lower()
