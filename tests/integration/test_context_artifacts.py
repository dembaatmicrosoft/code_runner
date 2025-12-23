"""
Integration tests for context files and artifacts.

Tests the input/output file handling including:
- Reading context files from ./input/
- Writing artifacts to ./output/
- Binary file handling with base64 encoding
- Size limit enforcement
"""

import base64

import pytest


class TestContextFiles:
    """Tests for input context file handling."""

    def test_read_text_context_file(self, run_script):
        """Script should be able to read text context files."""
        context = {"data.txt": "hello from context"}
        script = """
with open('input/data.txt') as f:
    print(f.read())
"""
        response = run_script(script, context=context)
        data = response.json()

        assert data["exit_code"] == 0
        assert "hello from context" in data["stdout"]

    def test_read_json_context_file(self, run_script):
        """Script should be able to read and parse JSON context."""
        context = {"config.json": '{"key": "value"}'}
        script = """
import json
with open('input/config.json') as f:
    data = json.load(f)
print(data['key'])
"""
        response = run_script(script, context=context)
        data = response.json()

        assert data["exit_code"] == 0
        assert "value" in data["stdout"]

    def test_read_binary_context_file(self, run_script):
        """Script should be able to read base64-encoded binary context."""
        binary_content = b"\x00\x01\x02\x03"
        encoded = base64.b64encode(binary_content).decode()
        context = {
            "data.bin": {"content": encoded, "encoding": "base64"}
        }
        script = """
with open('input/data.bin', 'rb') as f:
    data = f.read()
print(len(data))
"""
        response = run_script(script, context=context)
        data = response.json()

        assert data["exit_code"] == 0
        assert "4" in data["stdout"]

    def test_multiple_context_files(self, run_script):
        """Multiple context files should all be accessible."""
        context = {
            "file1.txt": "content1",
            "file2.txt": "content2",
        }
        script = """
import os
files = os.listdir('input')
print(len(files))
"""
        response = run_script(script, context=context)
        data = response.json()

        assert data["exit_code"] == 0
        assert "2" in data["stdout"]


class TestArtifacts:
    """Tests for output artifact collection."""

    def test_write_text_artifact(self, run_script):
        """Text files written to output/ should be returned as artifacts."""
        script = """
import os
os.makedirs('output', exist_ok=True)
with open('output/result.txt', 'w') as f:
    f.write('artifact content')
"""
        response = run_script(script)
        data = response.json()

        assert data["exit_code"] == 0
        assert "result.txt" in data["artifacts"]
        assert data["artifacts"]["result.txt"] == "artifact content"

    def test_write_binary_artifact(self, run_script):
        """Binary files should be returned base64-encoded."""
        script = """
import os
os.makedirs('output', exist_ok=True)
with open('output/data.bin', 'wb') as f:
    f.write(bytes([0, 1, 2, 3]))
"""
        response = run_script(script)
        data = response.json()

        assert data["exit_code"] == 0
        assert "data.bin" in data["artifacts"]
        artifact = data["artifacts"]["data.bin"]
        assert artifact["encoding"] == "base64"
        decoded = base64.b64decode(artifact["content"])
        assert decoded == bytes([0, 1, 2, 3])

    def test_nested_output_directory_not_collected_in_legacy_mode(self, run_script):
        """Legacy mode only collects top-level artifacts for backward compatibility."""
        script = """
import os
os.makedirs('output/subdir', exist_ok=True)
with open('output/result.txt', 'w') as f:
    f.write('top level')
with open('output/subdir/nested.txt', 'w') as f:
    f.write('nested content')
"""
        response = run_script(script)
        data = response.json()

        assert data["exit_code"] == 0
        assert "result.txt" in data["artifacts"]
        assert "subdir/nested.txt" not in data["artifacts"]

    def test_no_artifacts_without_output(self, run_script):
        """Scripts that don't write to output/ should have empty artifacts."""
        script = 'print("no output")'
        response = run_script(script)
        data = response.json()

        assert data["exit_code"] == 0
        assert data["artifacts"] == {}
