from dataclasses import dataclass
from typing import Optional, Tuple
import azure.functions as func
import json
import logging
import os
import subprocess
import sys
import tempfile
import uuid


# Constants
MAX_SCRIPT_BYTES = 256 * 1024
MAX_TIMEOUT_S = 300
DEFAULT_TIMEOUT_S = 60

CONTENT_TYPE_JSON = "application/json"
CONTENT_TYPE_TEXT = "text/plain"
ENCODING_UTF8 = "utf-8"

EXIT_CODE_TIMEOUT = 124
EXIT_CODE_INTERNAL_ERROR = -1


@dataclass
class ExecutionResult:
    exit_code: int
    stdout: str
    stderr: str


def error_response(message: str, status_code: int = 400) -> func.HttpResponse:
    """Create a standardized error response."""
    return func.HttpResponse(
        json.dumps({"error": message}),
        status_code=status_code,
        mimetype=CONTENT_TYPE_JSON
    )


def parse_request(req: func.HttpRequest) -> Tuple[str, int] | func.HttpResponse:
    """Extract script and timeout from request. Returns (script, timeout) or error response."""
    content_type = req.headers.get("content-type", "")

    if content_type.startswith(CONTENT_TYPE_TEXT):
        return _parse_raw_request(req)
    return _parse_json_request(req)


def _parse_raw_request(req: func.HttpRequest) -> Tuple[str, int] | func.HttpResponse:
    """Parse raw text request: script in body, timeout in query param."""
    try:
        script = req.get_body().decode(ENCODING_UTF8)
    except Exception:
        return error_response("Unable to read request body as UTF-8 text.")

    timeout_param = req.params.get("timeout_s")
    if timeout_param is None:
        return (script, DEFAULT_TIMEOUT_S)

    try:
        return (script, int(timeout_param))
    except ValueError:
        return error_response("`timeout_s` query parameter must be integer.")


def _parse_json_request(req: func.HttpRequest) -> Tuple[str, int] | func.HttpResponse:
    """Parse JSON request: script and timeout in body."""
    try:
        body = req.get_json()
    except ValueError:
        return error_response("Request body must be valid JSON.")

    script = body.get("script")
    if not isinstance(script, str):
        return error_response("`script` field is required and must be a string.")

    timeout_raw = body.get("timeout_s", DEFAULT_TIMEOUT_S)
    try:
        return (script, int(timeout_raw))
    except (ValueError, TypeError):
        return error_response("`timeout_s` must be an integer.")


def validate_timeout(timeout_s: int) -> int | func.HttpResponse:
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


def execute_script(script: str, timeout_s: int) -> ExecutionResult | func.HttpResponse:
    """Execute script in subprocess. Returns ExecutionResult or error response."""
    tmp_dir = tempfile.gettempdir()
    script_path = os.path.join(tmp_dir, f"user_script_{uuid.uuid4()}.py")

    try:
        with open(script_path, "w", encoding=ENCODING_UTF8) as f:
            f.write(script)
    except Exception as e:
        logging.error(f"Failed to write script to disk: {e}")
        return error_response("Internal error writing script to disk.", status_code=500)

    try:
        return _run_subprocess(script_path, tmp_dir, timeout_s)
    finally:
        _cleanup_script(script_path)


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


def _cleanup_script(script_path: str) -> None:
    """Remove temporary script file."""
    try:
        os.remove(script_path)
    except Exception:
        pass


app = func.FunctionApp()


@app.function_name(name="RunPythonScript")
@app.route(route="run", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def run_script(req: func.HttpRequest) -> func.HttpResponse:
    """Execute user-supplied Python code and return exit_code/stdout/stderr."""
    logging.info("Received request to run python script.")

    parsed = parse_request(req)
    if isinstance(parsed, func.HttpResponse):
        return parsed
    script, timeout_s = parsed

    validated_timeout = validate_timeout(timeout_s)
    if isinstance(validated_timeout, func.HttpResponse):
        return validated_timeout

    size_error = validate_script_size(script)
    if size_error:
        return size_error

    result = execute_script(script, validated_timeout)
    if isinstance(result, func.HttpResponse):
        return result

    return func.HttpResponse(
        json.dumps({
            "exit_code": result.exit_code,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }),
        status_code=200,
        mimetype=CONTENT_TYPE_JSON,
    )

