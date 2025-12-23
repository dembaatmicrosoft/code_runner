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
class FileEntry:
    """Represents a file in the files API (path can include directories)."""
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


@dataclass
class FilesRequest:
    """Request using the files API (files + entry_point mode)."""
    files: dict  # Raw files dict from request
    entry_point: str
    timeout_s: int
    raw_deps: list  # Raw dependencies list


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


def parse_files(raw_files: dict) -> Union[Dict[str, FileEntry], func.HttpResponse]:
    """Parse raw files dict into FileEntry objects. Returns parsed files or error."""
    if not isinstance(raw_files, dict):
        return error_response("`files` must be an object.")

    if not raw_files:
        return error_response("`files` cannot be empty.")

    parsed = {}
    for path, value in raw_files.items():
        if not isinstance(path, str):
            return error_response(f"File path must be a string, got: {type(path).__name__}")

        # Normalize path separators (accept both / and \, normalize to /)
        normalized_path = path.replace("\\", "/")

        if isinstance(value, str):
            parsed[normalized_path] = FileEntry(content=value, encoding=ENCODING_UTF8)
        elif isinstance(value, dict):
            content = value.get("content")
            encoding = value.get("encoding", ENCODING_UTF8)

            if not isinstance(content, str):
                return error_response(f"File '{path}' content must be a string.")
            if encoding not in (ENCODING_UTF8, ENCODING_BASE64):
                return error_response(f"File '{path}' encoding must be 'utf-8' or 'base64'.")

            parsed[normalized_path] = FileEntry(content=content, encoding=encoding)
        else:
            return error_response(
                f"File '{path}' must be a string or object with content/encoding."
            )

    return parsed


def validate_file_path(path: str) -> Optional[str]:
    """
    Validate a file path for security.

    Returns error message if invalid, None if valid.

    Rules:
    - No absolute paths (starting with / or drive letter)
    - No path traversal (..)
    - No leading dots (hidden files)
    - No empty segments
    """
    if not path:
        return "Path cannot be empty"

    # Check for absolute paths
    if path.startswith("/"):
        return f"Absolute paths not allowed: '{path}'"

    # Windows-style absolute paths (e.g., C:/)
    if len(path) >= 2 and path[1] == ":":
        return f"Absolute paths not allowed: '{path}'"

    # Split into segments
    segments = path.split("/")

    for segment in segments:
        if not segment:
            # Empty segment (from // or trailing /)
            continue
        if segment == "..":
            return f"Path traversal not allowed: '{path}'"
        if segment.startswith("."):
            return f"Hidden files/directories not allowed: '{path}'"

    return None


def decode_file_entry(file_entry: FileEntry) -> bytes:
    """Decode file entry content based on encoding. Returns raw bytes."""
    if file_entry.encoding == ENCODING_BASE64:
        return base64.b64decode(file_entry.content)
    return file_entry.content.encode(ENCODING_UTF8)


def validate_files(
    files: Dict[str, FileEntry],
    entry_point: str
) -> Optional[func.HttpResponse]:
    """
    Validate files constraints. Returns None if valid, error response otherwise.

    Checks:
    - File count limit
    - Path validation (security)
    - Entry point exists and is .py file
    - Size limits per file and total
    """
    # Check file count
    if len(files) > MAX_CONTEXT_FILES:
        return error_response(f"Too many files: {len(files)} > {MAX_CONTEXT_FILES}")

    # Validate entry point format
    if not entry_point.endswith(".py"):
        return error_response(f"Entry point must be a .py file: '{entry_point}'")

    # Validate entry point path security
    path_error = validate_file_path(entry_point)
    if path_error:
        return error_response(f"Invalid entry point path: {path_error}")

    # Check entry point exists in files
    if entry_point not in files:
        return error_response(f"Entry point '{entry_point}' not found in files.")

    total_bytes = 0
    for path, file_entry in files.items():
        # Validate path security
        path_error = validate_file_path(path)
        if path_error:
            return error_response(f"Invalid file path: {path_error}")

        # Decode and check size
        try:
            file_bytes = decode_file_entry(file_entry)
        except Exception:
            return error_response(f"Invalid base64 encoding for file '{path}'.")

        file_size = len(file_bytes)
        if file_size > MAX_SINGLE_FILE_BYTES:
            return error_response(
                f"File '{path}' too large: {file_size} > {MAX_SINGLE_FILE_BYTES} bytes.",
                status_code=413
            )
        total_bytes += file_size

    if total_bytes > MAX_CONTEXT_BYTES:
        return error_response(
            f"Total files too large: {total_bytes} > {MAX_CONTEXT_BYTES} bytes.",
            status_code=413
        )

    return None


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


def materialize_files(files: Dict[str, FileEntry], exec_dir: Path) -> None:
    """
    Write files to execution directory root with secure permissions.

    Files are written directly to exec_dir (not input/), supporting nested paths.
    Output directory is created for artifacts.
    """
    output_dir = exec_dir / OUTPUT_DIR
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    for path, file_entry in files.items():
        file_bytes = decode_file_entry(file_entry)
        file_path = exec_dir / path

        # Create parent directories if needed (for nested paths like config/settings.json)
        file_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

        file_path.write_bytes(file_bytes)
        # Set file to read-only for the script
        file_path.chmod(0o400)


def collect_artifacts(exec_dir: Path, recursive: bool = False) -> Union[dict, func.HttpResponse]:
    """Collect files from output directory. Returns artifacts dict or error response.

    Args:
        exec_dir: Execution directory containing output/ subdirectory
        recursive: If True, collect files from nested directories. If False, only top-level files.
    """
    output_dir = exec_dir / OUTPUT_DIR

    if not output_dir.exists():
        return {}

    artifacts = {}
    total_bytes = 0

    if recursive:
        paths = output_dir.rglob("*")
    else:
        paths = output_dir.iterdir()

    for path in paths:
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

        relative_path = path.relative_to(output_dir)
        artifact_key = str(relative_path).replace("\\", "/")
        artifacts[artifact_key] = encode_file_content(file_bytes)

    return artifacts


def parse_request(
    req: func.HttpRequest
) -> Union[Tuple[str, int, dict, list], FilesRequest, func.HttpResponse]:
    """
    Extract request parameters. Supports two modes:

    Legacy mode (script + context): Returns (script, timeout_s, raw_context, raw_deps)
    Files mode (files + entry_point): Returns FilesRequest
    Raw text mode: Returns legacy tuple (script in body, no context)
    """
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


def _parse_json_request(
    req: func.HttpRequest
) -> Union[Tuple[str, int, dict, list], FilesRequest, func.HttpResponse]:
    """
    Parse JSON request. Supports two modes:

    Legacy mode (script + context):
        Returns (script, timeout_s, raw_context, raw_deps)

    Files mode (files + entry_point):
        Returns FilesRequest
    """
    try:
        body = req.get_json()
    except ValueError:
        return error_response("Request body must be valid JSON.")

    has_script = "script" in body
    has_files = "files" in body
    has_entry_point = "entry_point" in body
    has_context = "context" in body

    # Check for mutual exclusivity
    if has_files and has_script:
        return error_response("Cannot use both `files` and `script`. Choose one mode.")
    if has_files and has_context:
        return error_response("Cannot use both `files` and `context`. Use `files` for all input files.")
    if has_entry_point and not has_files:
        return error_response("`entry_point` requires `files` to be provided.")

    # Parse timeout (common to both modes)
    timeout_raw = body.get("timeout_s", DEFAULT_TIMEOUT_S)
    try:
        timeout_s = int(timeout_raw)
    except (ValueError, TypeError):
        return error_response("`timeout_s` must be an integer.")

    raw_deps = body.get("dependencies", [])

    # Files mode
    if has_files:
        raw_files = body.get("files")
        if not isinstance(raw_files, dict):
            return error_response("`files` must be an object.")

        entry_point = body.get("entry_point")
        if not isinstance(entry_point, str):
            return error_response("`entry_point` is required and must be a string.")

        # Normalize entry_point path separators
        entry_point = entry_point.replace("\\", "/")

        return FilesRequest(
            files=raw_files,
            entry_point=entry_point,
            timeout_s=timeout_s,
            raw_deps=raw_deps
        )

    # Legacy mode (script + context)
    script = body.get("script")
    if not isinstance(script, str):
        return error_response("`script` field is required and must be a string.")

    raw_context = body.get("context", {})
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


def execute_files(
    files: Dict[str, FileEntry],
    entry_point: str,
    timeout_s: int,
    dependencies: Optional[List[Dependency]] = None,
) -> Union[ExecutionResult, func.HttpResponse]:
    """Execute files mode: materialize all files and run entry_point."""
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

        # Materialize all files to execution directory
        materialize_files(files, exec_dir)

        # Entry point path
        entry_point_path = exec_dir / entry_point

        # Execute
        result = _run_subprocess(str(entry_point_path), str(exec_dir), timeout_s)

        # Collect artifacts (recursive for files mode)
        artifacts = collect_artifacts(exec_dir, recursive=True)
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

    # Add .python_packages to PYTHONPATH for Azure Functions bundled dependencies
    packages_path = "/home/site/wwwroot/.python_packages/lib/site-packages"
    if os.path.isdir(packages_path):
        existing_path = safe_env.get("PYTHONPATH", "")
        if existing_path:
            safe_env["PYTHONPATH"] = f"{packages_path}:{existing_path}"
        else:
            safe_env["PYTHONPATH"] = packages_path

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


@app.function_name(name="Health")
@app.route(route="health", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def health(req: func.HttpRequest) -> func.HttpResponse:
    """Health check endpoint for container orchestration."""
    return func.HttpResponse("OK", status_code=200)


@app.function_name(name="RunPythonScript")
@app.route(route="run", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def run_script(req: func.HttpRequest) -> func.HttpResponse:
    """Execute user-supplied Python code and return exit_code/stdout/stderr/artifacts."""
    start_time = time.time()
    request_id = str(uuid.uuid4())[:8]
    client_ip = get_client_ip(req)

    logging.info(f"[{request_id}] Received script execution request from {client_ip}")

    # Parse request - returns FilesRequest, legacy tuple, or error
    parsed = parse_request(req)
    if isinstance(parsed, func.HttpResponse):
        return parsed

    # Dispatch based on request mode
    if isinstance(parsed, FilesRequest):
        return _handle_files_request(parsed, request_id, client_ip, start_time)
    else:
        script, timeout_s, raw_context, raw_deps = parsed
        return _handle_legacy_request(
            script, timeout_s, raw_context, raw_deps,
            request_id, client_ip, start_time
        )


def _handle_files_request(
    req: FilesRequest,
    request_id: str,
    client_ip: str,
    start_time: float
) -> func.HttpResponse:
    """Handle files API mode request."""
    # Parse files
    parsed_files = parse_files(req.files)
    if isinstance(parsed_files, func.HttpResponse):
        return parsed_files

    # Compute audit info (hash of entry_point content)
    entry_content = parsed_files.get(req.entry_point)
    if entry_content:
        script_hash = hashlib.sha256(entry_content.content.encode(ENCODING_UTF8)).hexdigest()[:16]
    else:
        script_hash = "unknown"
    total_size = sum(len(f.content) for f in parsed_files.values())

    # Validate timeout
    validated_timeout = validate_timeout(req.timeout_s)
    if isinstance(validated_timeout, func.HttpResponse):
        log_audit_event(
            "request_rejected", request_id, client_ip, script_hash,
            total_size, req.timeout_s, len(parsed_files),
            error="invalid_timeout"
        )
        return validated_timeout

    # Validate files (paths, sizes, entry_point exists)
    files_error = validate_files(parsed_files, req.entry_point)
    if files_error:
        log_audit_event(
            "request_rejected", request_id, client_ip, script_hash,
            total_size, validated_timeout, len(parsed_files),
            error="files_validation_failed"
        )
        return files_error

    # Parse and validate dependencies
    dependencies: List[Dependency] = []
    dep_strings: List[str] = []
    if req.raw_deps:
        parsed_deps = parse_dependencies(req.raw_deps)
        if isinstance(parsed_deps, func.HttpResponse):
            log_audit_event(
                "request_rejected", request_id, client_ip, script_hash,
                total_size, validated_timeout, len(parsed_files),
                error="invalid_dependencies"
            )
            return parsed_deps
        dependencies = parsed_deps
        dep_strings = [str(d) for d in dependencies]

    # Acquire execution lock
    with _execution_lock:
        log_audit_event(
            "execution_started", request_id, client_ip, script_hash,
            total_size, validated_timeout, len(parsed_files),
            dependencies=dep_strings
        )

        result = execute_files(parsed_files, req.entry_point, validated_timeout, dependencies)
        duration_ms = (time.time() - start_time) * 1000

        if isinstance(result, func.HttpResponse):
            log_audit_event(
                "execution_error", request_id, client_ip, script_hash,
                total_size, validated_timeout, len(parsed_files),
                dependencies=dep_strings, duration_ms=duration_ms,
                error="execution_failed"
            )
            return result

        log_audit_event(
            "execution_completed", request_id, client_ip, script_hash,
            total_size, validated_timeout, len(parsed_files),
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


def _handle_legacy_request(
    script: str,
    timeout_s: int,
    raw_context: dict,
    raw_deps: list,
    request_id: str,
    client_ip: str,
    start_time: float
) -> func.HttpResponse:
    """Handle legacy API mode request (script + context)."""
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
    with _execution_lock:
        log_audit_event(
            "execution_started", request_id, client_ip, script_hash,
            script_size, validated_timeout, len(context),
            dependencies=dep_strings
        )

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
