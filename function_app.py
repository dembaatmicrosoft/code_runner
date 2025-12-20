# Copyright (c) 2025 Microsoft Corporation.
# Licensed under the MIT License. See LICENSE file in the project root.

"""
CodeRunner Azure Function

A serverless endpoint for executing Python scripts in isolated subprocesses.
Supports input files (context) and output files (artifacts) for data processing
workflows.

Features:
    - Execute arbitrary Python code with configurable timeout
    - Provide input files via context (text or base64-encoded binary)
    - Collect output files as artifacts (auto-detected encoding)
    - Size limits and path validation for security

Usage:
    POST /api/run with JSON body: {"script": "...", "timeout_s": 60, "context": {...}}
    POST /api/run with text/plain body containing Python code

See README.md for full documentation.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional, Tuple, Union
import azure.functions as func
import base64
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import uuid


# Script and timeout constants
MAX_SCRIPT_BYTES = 256 * 1024
MAX_TIMEOUT_S = 300
DEFAULT_TIMEOUT_S = 60

# Context and artifacts constants
MAX_CONTEXT_BYTES = 10 * 1024 * 1024
MAX_ARTIFACTS_BYTES = 10 * 1024 * 1024
MAX_CONTEXT_FILES = 20
MAX_SINGLE_FILE_BYTES = 5 * 1024 * 1024
INPUT_DIR = "input"
OUTPUT_DIR = "output"

# Content types and encoding
CONTENT_TYPE_JSON = "application/json"
CONTENT_TYPE_TEXT = "text/plain"
ENCODING_UTF8 = "utf-8"
ENCODING_BASE64 = "base64"

# Exit codes
EXIT_CODE_TIMEOUT = 124
EXIT_CODE_INTERNAL_ERROR = -1


@dataclass
class ContextFile:
    """Represents a file in the execution context."""
    name: str
    content: str
    encoding: str = ENCODING_UTF8


@dataclass
class ExecutionResult:
    """Result of script execution including artifacts."""
    exit_code: int
    stdout: str
    stderr: str
    artifacts: dict = field(default_factory=dict)


def error_response(message: str, status_code: int = 400) -> func.HttpResponse:
    """Create a standardized error response."""
    return func.HttpResponse(
        json.dumps({"error": message}),
        status_code=status_code,
        mimetype=CONTENT_TYPE_JSON
    )


def is_binary_content(data: bytes) -> bool:
    """Detect if content is binary (contains null bytes or non-decodable as UTF-8)."""
    if b"\x00" in data:
        return True
    try:
        data.decode(ENCODING_UTF8)
        return False
    except UnicodeDecodeError:
        return True


def decode_file_content(context_file: ContextFile) -> bytes:
    """Decode file content based on encoding. Returns raw bytes."""
    if context_file.encoding == ENCODING_BASE64:
        return base64.b64decode(context_file.content)
    return context_file.content.encode(ENCODING_UTF8)


def encode_file_content(data: bytes) -> Union[str, dict]:
    """Encode file content for response. Auto-detects binary vs text."""
    if is_binary_content(data):
        return {
            "content": base64.b64encode(data).decode("ascii"),
            "encoding": ENCODING_BASE64
        }
    return data.decode(ENCODING_UTF8)


def parse_context(raw_context: dict) -> Union[Dict[str, ContextFile], func.HttpResponse]:
    """Parse raw context dict into ContextFile objects. Returns parsed context or error."""
    if not isinstance(raw_context, dict):
        return error_response("`context` must be an object.")

    parsed = {}
    for name, value in raw_context.items():
        if not isinstance(name, str):
            return error_response(f"Context file name must be a string, got: {type(name).__name__}")

        if isinstance(value, str):
            parsed[name] = ContextFile(name=name, content=value, encoding=ENCODING_UTF8)
        elif isinstance(value, dict):
            content = value.get("content")
            encoding = value.get("encoding", ENCODING_UTF8)

            if not isinstance(content, str):
                return error_response(f"Context file '{name}' content must be a string.")
            if encoding not in (ENCODING_UTF8, ENCODING_BASE64):
                return error_response(f"Context file '{name}' encoding must be 'utf-8' or 'base64'.")

            parsed[name] = ContextFile(name=name, content=content, encoding=encoding)
        else:
            return error_response(
                f"Context file '{name}' must be a string or object with content/encoding."
            )

    return parsed


def validate_context(context: Dict[str, ContextFile]) -> Optional[func.HttpResponse]:
    """Validate context constraints. Returns None if valid, error response otherwise."""
    if len(context) > MAX_CONTEXT_FILES:
        return error_response(f"Too many context files: {len(context)} > {MAX_CONTEXT_FILES}")

    total_bytes = 0
    for name, ctx_file in context.items():
        # Validate filename (prevent path traversal)
        if "/" in name or "\\" in name or name.startswith("."):
            return error_response(f"Invalid context filename: '{name}'")

        # Decode and check size
        try:
            file_bytes = decode_file_content(ctx_file)
        except Exception:
            return error_response(f"Invalid base64 encoding for context file '{name}'.")

        file_size = len(file_bytes)
        if file_size > MAX_SINGLE_FILE_BYTES:
            return error_response(
                f"Context file '{name}' too large: {file_size} > {MAX_SINGLE_FILE_BYTES} bytes.",
                status_code=413
            )
        total_bytes += file_size

    if total_bytes > MAX_CONTEXT_BYTES:
        return error_response(
            f"Total context too large: {total_bytes} > {MAX_CONTEXT_BYTES} bytes.",
            status_code=413
        )

    return None


def materialize_context(context: Dict[str, ContextFile], exec_dir: Path) -> None:
    """Write context files to input directory."""
    input_dir = exec_dir / INPUT_DIR
    output_dir = exec_dir / OUTPUT_DIR

    input_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    for name, ctx_file in context.items():
        file_bytes = decode_file_content(ctx_file)
        (input_dir / name).write_bytes(file_bytes)


def collect_artifacts(exec_dir: Path) -> Union[dict, func.HttpResponse]:
    """Collect files from output directory. Returns artifacts dict or error response."""
    output_dir = exec_dir / OUTPUT_DIR

    if not output_dir.exists():
        return {}

    artifacts = {}
    total_bytes = 0

    for path in output_dir.iterdir():
        if not path.is_file():
            continue

        file_bytes = path.read_bytes()
        file_size = len(file_bytes)
        total_bytes += file_size

        if total_bytes > MAX_ARTIFACTS_BYTES:
            return error_response(
                f"Total artifacts too large: exceeds {MAX_ARTIFACTS_BYTES} bytes.",
                status_code=500
            )

        artifacts[path.name] = encode_file_content(file_bytes)

    return artifacts


def parse_request(req: func.HttpRequest) -> Union[Tuple[str, int, dict], func.HttpResponse]:
    """Extract script, timeout, and raw context from request."""
    content_type = req.headers.get("content-type", "")

    if content_type.startswith(CONTENT_TYPE_TEXT):
        return _parse_raw_request(req)
    return _parse_json_request(req)


def _parse_raw_request(req: func.HttpRequest) -> Union[Tuple[str, int, dict], func.HttpResponse]:
    """Parse raw text request: script in body, timeout in query param. No context support."""
    try:
        script = req.get_body().decode(ENCODING_UTF8)
    except Exception:
        return error_response("Unable to read request body as UTF-8 text.")

    timeout_param = req.params.get("timeout_s")
    if timeout_param is None:
        return (script, DEFAULT_TIMEOUT_S, {})

    try:
        return (script, int(timeout_param), {})
    except ValueError:
        return error_response("`timeout_s` query parameter must be integer.")


def _parse_json_request(req: func.HttpRequest) -> Union[Tuple[str, int, dict], func.HttpResponse]:
    """Parse JSON request: script, timeout, and context in body."""
    try:
        body = req.get_json()
    except ValueError:
        return error_response("Request body must be valid JSON.")

    script = body.get("script")
    if not isinstance(script, str):
        return error_response("`script` field is required and must be a string.")

    timeout_raw = body.get("timeout_s", DEFAULT_TIMEOUT_S)
    try:
        timeout_s = int(timeout_raw)
    except (ValueError, TypeError):
        return error_response("`timeout_s` must be an integer.")

    raw_context = body.get("context", {})
    return (script, timeout_s, raw_context)


def validate_timeout(timeout_s: int) -> Union[int, func.HttpResponse]:
    """Validate and clamp timeout. Returns clamped timeout or error response."""
    if timeout_s <= 0:
        return error_response("`timeout_s` must be > 0.")

    if timeout_s > MAX_TIMEOUT_S:
        logging.warning(f"Clamping timeout {timeout_s}s to {MAX_TIMEOUT_S}s.")
        return MAX_TIMEOUT_S

    return timeout_s


def validate_script_size(script: str) -> Optional[func.HttpResponse]:
    """Validate script size. Returns None if valid, error response if too large."""
    script_bytes = len(script.encode(ENCODING_UTF8))
    if script_bytes > MAX_SCRIPT_BYTES:
        return error_response(
            f"Script too large: {script_bytes} bytes > {MAX_SCRIPT_BYTES} bytes.",
            status_code=413
        )
    return None


def execute_script(
    script: str,
    timeout_s: int,
    context: Optional[Dict[str, ContextFile]] = None
) -> Union[ExecutionResult, func.HttpResponse]:
    """Execute script in subprocess with optional context. Returns ExecutionResult or error."""
    context = context or {}
    exec_id = str(uuid.uuid4())
    exec_dir = Path(tempfile.gettempdir()) / f"exec_{exec_id}"

    try:
        exec_dir.mkdir(parents=True, exist_ok=True)

        # Materialize context files
        if context:
            materialize_context(context, exec_dir)

        # Write script
        script_path = exec_dir / f"script_{exec_id}.py"
        try:
            script_path.write_text(script, encoding=ENCODING_UTF8)
        except Exception as e:
            logging.error(f"Failed to write script to disk: {e}")
            return error_response("Internal error writing script to disk.", status_code=500)

        # Execute
        result = _run_subprocess(str(script_path), str(exec_dir), timeout_s)

        # Collect artifacts
        artifacts = collect_artifacts(exec_dir)
        if isinstance(artifacts, func.HttpResponse):
            return artifacts

        return ExecutionResult(
            exit_code=result.exit_code,
            stdout=result.stdout,
            stderr=result.stderr,
            artifacts=artifacts,
        )

    finally:
        _cleanup_exec_dir(exec_dir)


def _run_subprocess(script_path: str, working_dir: str, timeout_s: int) -> ExecutionResult:
    """Run Python subprocess and capture output."""
    python_exe = sys.executable or "python3"
    cmd = [python_exe, "-X", "utf8", script_path]
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = ENCODING_UTF8

    try:
        completed = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=working_dir,
            timeout=timeout_s,
            check=False,
            env=env,
        )
        return ExecutionResult(
            exit_code=completed.returncode,
            stdout=completed.stdout.decode(ENCODING_UTF8, errors="replace"),
            stderr=completed.stderr.decode(ENCODING_UTF8, errors="replace"),
        )

    except subprocess.TimeoutExpired as te:
        stdout = te.stdout.decode(ENCODING_UTF8, errors="replace") if te.stdout else ""
        stderr = te.stderr.decode(ENCODING_UTF8, errors="replace") if te.stderr else ""
        return ExecutionResult(
            exit_code=EXIT_CODE_TIMEOUT,
            stdout=stdout,
            stderr=stderr + "\n[Error: Script timed out]",
        )

    except Exception as e:
        logging.exception("Unexpected error running user script.")
        return ExecutionResult(
            exit_code=EXIT_CODE_INTERNAL_ERROR,
            stdout="",
            stderr=f"[Internal execution error] {e}",
        )


def _cleanup_exec_dir(exec_dir: Path) -> None:
    """Remove execution directory and all contents."""
    try:
        shutil.rmtree(exec_dir)
    except Exception:
        pass


app = func.FunctionApp()


@app.function_name(name="RunPythonScript")
@app.route(route="run", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def run_script(req: func.HttpRequest) -> func.HttpResponse:
    """Execute user-supplied Python code and return exit_code/stdout/stderr/artifacts."""
    logging.info("Received request to run python script.")

    # Parse request
    parsed = parse_request(req)
    if isinstance(parsed, func.HttpResponse):
        return parsed
    script, timeout_s, raw_context = parsed

    # Validate timeout
    validated_timeout = validate_timeout(timeout_s)
    if isinstance(validated_timeout, func.HttpResponse):
        return validated_timeout

    # Validate script size
    size_error = validate_script_size(script)
    if size_error:
        return size_error

    # Parse and validate context
    context = {}
    if raw_context:
        parsed_context = parse_context(raw_context)
        if isinstance(parsed_context, func.HttpResponse):
            return parsed_context
        context = parsed_context

        context_error = validate_context(context)
        if context_error:
            return context_error

    # Execute
    result = execute_script(script, validated_timeout, context)
    if isinstance(result, func.HttpResponse):
        return result

    return func.HttpResponse(
        json.dumps({
            "exit_code": result.exit_code,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "artifacts": result.artifacts,
        }),
        status_code=200,
        mimetype=CONTENT_TYPE_JSON,
    )

