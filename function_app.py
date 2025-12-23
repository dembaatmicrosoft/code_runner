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
from typing import Dict, List, Optional, Tuple, Union
import azure.functions as func
import base64
import hashlib
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid


# Execution lock - ensures sequential processing within a single instance
# This prevents concurrent scripts from interfering with each other
_execution_lock = threading.Lock()


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

# Dependency constants
MAX_DEPENDENCIES = 15
DEPENDENCY_TIMEOUT_S = 30
DEPENDENCY_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$')
VERSION_SPEC_PATTERN = re.compile(
    r'^(==|>=|<=|~=|!=|<|>)[0-9]+(\.[0-9]+)*([ab][0-9]+)?(\.post[0-9]+)?(\.dev[0-9]+)?$'
)

# Pre-installed packages (lowercase names for matching)
PRE_INSTALLED_PACKAGES: frozenset = frozenset([
    "azure-functions",
    "numpy", "pandas", "scipy", "scikit-learn", "matplotlib",
    "requests", "httpx", "beautifulsoup4",
    "pyyaml", "toml", "python-dateutil",
    "tqdm", "pillow",
])


def get_client_ip(req: func.HttpRequest) -> str:
    """Extract client IP from request headers (handles proxies)."""
    # Azure Front Door / API Management / Load Balancer headers
    forwarded_for = req.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        # Take the first IP in the chain (original client)
        return forwarded_for.split(",")[0].strip()

    # Direct connection (rare in Azure)
    return req.headers.get("X-Client-IP", "unknown")


def compute_script_hash(script: str) -> str:
    """Compute SHA256 hash of script for audit logging (not storage)."""
    return hashlib.sha256(script.encode(ENCODING_UTF8)).hexdigest()[:16]


def log_audit_event(
    event_type: str,
    request_id: str,
    client_ip: str,
    script_hash: str,
    script_size: int,
    timeout_s: int,
    context_files: int,
    dependencies: Optional[List[str]] = None,
    duration_ms: Optional[float] = None,
    exit_code: Optional[int] = None,
    error: Optional[str] = None,
) -> None:
    """Log structured audit event for security monitoring."""
    audit_data = {
        "audit": True,
        "event": event_type,
        "request_id": request_id,
        "client_ip": client_ip,
        "script_hash": script_hash,
        "script_size_bytes": script_size,
        "timeout_s": timeout_s,
        "context_files": context_files,
    }

    if dependencies is not None:
        audit_data["dependencies"] = dependencies
        audit_data["dependency_count"] = len(dependencies)
    if duration_ms is not None:
        audit_data["duration_ms"] = round(duration_ms, 2)
    if exit_code is not None:
        audit_data["exit_code"] = exit_code
    if error is not None:
        audit_data["error"] = error

    # Use structured JSON logging for easy parsing in Azure Monitor
    logging.info(f"AUDIT: {json.dumps(audit_data)}")


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


@dataclass
class Dependency:
    """A package dependency with optional version constraint."""
    name: str
    version_spec: Optional[str] = None

    def __str__(self) -> str:
        if self.version_spec:
            return f"{self.name}{self.version_spec}"
        return self.name

    def is_pre_installed(self) -> bool:
        """Check if this package is pre-installed (ignores version)."""
        return self.name.lower() in PRE_INSTALLED_PACKAGES


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


def parse_dependency(dep_str: str) -> Union[Dependency, func.HttpResponse]:
    """Parse a dependency string into a Dependency object."""
    if not isinstance(dep_str, str):
        return error_response(f"Dependency must be a string, got: {type(dep_str).__name__}")

    dep_str = dep_str.strip()
    if not dep_str:
        return error_response("Dependency cannot be empty.")

    # Split name from version specifier
    # Match version operators: ==, >=, <=, ~=, !=, <, >
    match = re.match(r'^([a-zA-Z0-9._-]+)((?:==|>=|<=|~=|!=|<|>).+)?$', dep_str)
    if not match:
        return error_response(f"Invalid dependency format: '{dep_str}'")

    name = match.group(1)
    version_spec = match.group(2)

    # Validate package name
    if not DEPENDENCY_NAME_PATTERN.match(name):
        return error_response(f"Invalid package name: '{name}'")

    # Validate version specifier if present
    if version_spec and not VERSION_SPEC_PATTERN.match(version_spec):
        return error_response(f"Invalid version specifier: '{version_spec}'")

    return Dependency(name=name, version_spec=version_spec)


def parse_dependencies(raw_deps: list) -> Union[List[Dependency], func.HttpResponse]:
    """Parse raw dependency list into Dependency objects."""
    if not isinstance(raw_deps, list):
        return error_response("`dependencies` must be an array.")

    if len(raw_deps) > MAX_DEPENDENCIES:
        return error_response(f"Too many dependencies: {len(raw_deps)} > {MAX_DEPENDENCIES}")

    dependencies = []
    seen_names = set()

    for dep_str in raw_deps:
        parsed = parse_dependency(dep_str)
        if isinstance(parsed, func.HttpResponse):
            return parsed

        # Check for duplicates
        name_lower = parsed.name.lower()
        if name_lower in seen_names:
            return error_response(f"Duplicate dependency: '{parsed.name}'")
        seen_names.add(name_lower)

        dependencies.append(parsed)

    return dependencies


def filter_pre_installed(deps: List[Dependency]) -> List[Dependency]:
    """Remove dependencies that are already pre-installed."""
    return [d for d in deps if not d.is_pre_installed()]


def install_dependencies(deps: List[Dependency], exec_dir: Path) -> Optional[str]:
    """
    Install dependencies using UV.

    Returns None on success, error message on failure.

    SECURITY: Uses --only-binary :all: to prevent setup.py execution.
    """
    if not deps:
        return None

    # Build package list
    packages = [str(d) for d in deps]

    # Check if UV is available, fall back to pip if not
    uv_path = shutil.which("uv")
    if uv_path:
        cmd = [
            uv_path, "pip", "install",
            "--only-binary", ":all:",
            "--no-cache-dir",
            "--quiet",
        ] + packages
    else:
        # Fall back to pip with same security flags
        python_exe = sys.executable or "python3"
        cmd = [
            python_exe, "-m", "pip", "install",
            "--only-binary", ":all:",
            "--no-cache-dir",
            "--quiet",
            "--disable-pip-version-check",
        ] + packages

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=DEPENDENCY_TIMEOUT_S,
            cwd=str(exec_dir),
            env=_create_safe_environment(),
        )

        if result.returncode != 0:
            stderr = result.stderr.decode(ENCODING_UTF8, errors="replace")
            # Truncate long error messages
            if len(stderr) > 500:
                stderr = stderr[:500] + "..."
            return f"Dependency installation failed: {stderr}"

        return None

    except subprocess.TimeoutExpired:
        return f"Dependency installation timed out after {DEPENDENCY_TIMEOUT_S}s"
    except Exception as e:
        return f"Dependency installation error: {e}"


def materialize_context(context: Dict[str, ContextFile], exec_dir: Path) -> None:
    """Write context files to input directory with secure permissions."""
    input_dir = exec_dir / INPUT_DIR
    output_dir = exec_dir / OUTPUT_DIR

    # Create directories with restrictive permissions
    input_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    for name, ctx_file in context.items():
        file_bytes = decode_file_content(ctx_file)
        file_path = input_dir / name
        file_path.write_bytes(file_bytes)
        # Set file to read-only for the script
        file_path.chmod(0o400)


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


def parse_request(req: func.HttpRequest) -> Union[Tuple[str, int, dict, list], func.HttpResponse]:
    """Extract script, timeout, raw context, and raw dependencies from request."""
    content_type = req.headers.get("content-type", "")

    if content_type.startswith(CONTENT_TYPE_TEXT):
        return _parse_raw_request(req)
    return _parse_json_request(req)


def _parse_raw_request(req: func.HttpRequest) -> Union[Tuple[str, int, dict, list], func.HttpResponse]:
    """Parse raw text request: script in body, timeout in query param. No context/deps support."""
    try:
        script = req.get_body().decode(ENCODING_UTF8)
    except Exception:
        return error_response("Unable to read request body as UTF-8 text.")

    timeout_param = req.params.get("timeout_s")
    if timeout_param is None:
        return (script, DEFAULT_TIMEOUT_S, {}, [])

    try:
        return (script, int(timeout_param), {}, [])
    except ValueError:
        return error_response("`timeout_s` query parameter must be integer.")


def _parse_json_request(req: func.HttpRequest) -> Union[Tuple[str, int, dict, list], func.HttpResponse]:
    """Parse JSON request: script, timeout, context, and dependencies in body."""
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
    raw_deps = body.get("dependencies", [])
    return (script, timeout_s, raw_context, raw_deps)


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
    context: Optional[Dict[str, ContextFile]] = None,
    dependencies: Optional[List[Dependency]] = None,
) -> Union[ExecutionResult, func.HttpResponse]:
    """Execute script in subprocess with optional context and dependencies."""
    context = context or {}
    dependencies = dependencies or []
    exec_id = str(uuid.uuid4())
    exec_dir = Path(tempfile.gettempdir()) / f"exec_{exec_id}"

    try:
        # Create execution directory with restrictive permissions (owner only)
        exec_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

        # Install dependencies (only non-pre-installed ones)
        deps_to_install = filter_pre_installed(dependencies)
        if deps_to_install:
            install_error = install_dependencies(deps_to_install, exec_dir)
            if install_error:
                return error_response(install_error, status_code=500)

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


# Environment variables safe to pass to subprocess
SAFE_ENV_VARS = frozenset([
    # Essential for Python to function
    "PATH",
    "PYTHONPATH",
    "PYTHONHOME",
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TMPDIR",
    "TMP",
    "TEMP",
    # Linux essentials
    "USER",
    "SHELL",
])


def _create_safe_environment() -> dict:
    """Create a minimal, safe environment for subprocess execution."""
    safe_env = {}

    # Copy only safe variables that exist
    for var in SAFE_ENV_VARS:
        if var in os.environ:
            safe_env[var] = os.environ[var]

    # Ensure Python encoding is set
    safe_env["PYTHONIOENCODING"] = ENCODING_UTF8
    safe_env["PYTHONUNBUFFERED"] = "1"

    return safe_env


def _kill_process_tree(pid: int) -> None:
    """Kill a process and all its children using process group."""
    try:
        # Kill the entire process group
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        # Process already dead or we don't have permission
        pass
    except Exception as e:
        logging.warning(f"Failed to kill process tree {pid}: {e}")


def _run_subprocess(script_path: str, working_dir: str, timeout_s: int) -> ExecutionResult:
    """Run Python subprocess and capture output with process group isolation."""
    python_exe = sys.executable or "python3"
    cmd = [python_exe, "-X", "utf8", script_path]
    env = _create_safe_environment()

    process = None
    try:
        # Start process in new process group for clean termination
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=working_dir,
            env=env,
            start_new_session=True,  # Creates new process group
        )

        try:
            stdout, stderr = process.communicate(timeout=timeout_s)
            return ExecutionResult(
                exit_code=process.returncode,
                stdout=stdout.decode(ENCODING_UTF8, errors="replace"),
                stderr=stderr.decode(ENCODING_UTF8, errors="replace"),
            )
        except subprocess.TimeoutExpired:
            # Kill entire process group on timeout
            _kill_process_tree(process.pid)
            stdout, stderr = process.communicate()
            timeout_stderr = (stderr.decode(ENCODING_UTF8, errors="replace") if stderr else "")
            timeout_stderr += "\n[Error: Script timed out]"
            return ExecutionResult(
                exit_code=EXIT_CODE_TIMEOUT,
                stdout=stdout.decode(ENCODING_UTF8, errors="replace") if stdout else "",
                stderr=timeout_stderr,
            )

    except Exception as e:
        logging.exception("Unexpected error running user script.")
        return ExecutionResult(
            exit_code=EXIT_CODE_INTERNAL_ERROR,
            stdout="",
            stderr=f"[Internal execution error] {e}",
        )
    finally:
        # Ensure process is terminated even on unexpected errors
        if process and process.poll() is None:
            _kill_process_tree(process.pid)


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
    start_time = time.time()
    request_id = str(uuid.uuid4())[:8]
    client_ip = get_client_ip(req)

    logging.info(f"[{request_id}] Received script execution request from {client_ip}")

    # Parse request
    parsed = parse_request(req)
    if isinstance(parsed, func.HttpResponse):
        return parsed
    script, timeout_s, raw_context, raw_deps = parsed

    # Compute audit info early
    script_hash = compute_script_hash(script)
    script_size = len(script.encode(ENCODING_UTF8))

    # Validate timeout
    validated_timeout = validate_timeout(timeout_s)
    if isinstance(validated_timeout, func.HttpResponse):
        log_audit_event(
            "request_rejected", request_id, client_ip, script_hash,
            script_size, timeout_s, 0, error="invalid_timeout"
        )
        return validated_timeout

    # Validate script size
    size_error = validate_script_size(script)
    if size_error:
        log_audit_event(
            "request_rejected", request_id, client_ip, script_hash,
            script_size, validated_timeout, 0, error="script_too_large"
        )
        return size_error

    # Parse and validate dependencies
    dependencies: List[Dependency] = []
    dep_strings: List[str] = []
    if raw_deps:
        parsed_deps = parse_dependencies(raw_deps)
        if isinstance(parsed_deps, func.HttpResponse):
            log_audit_event(
                "request_rejected", request_id, client_ip, script_hash,
                script_size, validated_timeout, 0, error="invalid_dependencies"
            )
            return parsed_deps
        dependencies = parsed_deps
        dep_strings = [str(d) for d in dependencies]

    # Parse and validate context
    context = {}
    if raw_context:
        parsed_context = parse_context(raw_context)
        if isinstance(parsed_context, func.HttpResponse):
            log_audit_event(
                "request_rejected", request_id, client_ip, script_hash,
                script_size, validated_timeout, len(raw_context),
                dependencies=dep_strings, error="invalid_context"
            )
            return parsed_context
        context = parsed_context

        context_error = validate_context(context)
        if context_error:
            log_audit_event(
                "request_rejected", request_id, client_ip, script_hash,
                script_size, validated_timeout, len(context),
                dependencies=dep_strings, error="context_validation_failed"
            )
            return context_error

    # Acquire execution lock - ensures sequential processing
    # This prevents concurrent scripts from interfering with each other
    with _execution_lock:
        # Log execution start
        log_audit_event(
            "execution_started", request_id, client_ip, script_hash,
            script_size, validated_timeout, len(context),
            dependencies=dep_strings
        )

        # Execute
        result = execute_script(script, validated_timeout, context, dependencies)
        duration_ms = (time.time() - start_time) * 1000

        if isinstance(result, func.HttpResponse):
            log_audit_event(
                "execution_error", request_id, client_ip, script_hash,
                script_size, validated_timeout, len(context),
                dependencies=dep_strings, duration_ms=duration_ms,
                error="execution_failed"
            )
            return result

        # Log execution complete
        log_audit_event(
            "execution_completed", request_id, client_ip, script_hash,
            script_size, validated_timeout, len(context),
            dependencies=dep_strings, duration_ms=duration_ms,
            exit_code=result.exit_code
        )

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
