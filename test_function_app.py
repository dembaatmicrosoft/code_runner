# Copyright (c) 2025 Microsoft Corporation.
# Licensed under the MIT License. See LICENSE file in the project root.

"""
Unit tests for CodeRunner Azure Function.

Test organization follows AAA pattern (Arrange, Act, Assert).
Each test validates one specific behavior with minimal assertions.
All external dependencies (subprocess, filesystem, Azure request) are mocked for determinism.
"""

import json
import pytest
from unittest.mock import Mock, MagicMock, patch, mock_open, call
import azure.functions as func
import subprocess

import function_app
from function_app import (
    error_response,
    parse_request,
    _parse_raw_request,
    _parse_json_request,
    validate_timeout,
    validate_script_size,
    execute_script,
    _run_subprocess,
    _cleanup_exec_dir,
    _create_safe_environment,
    get_client_ip,
    compute_script_hash,
    log_audit_event,
    ExecutionResult,
    ContextFile,
    is_binary_content,
    decode_file_content,
    encode_file_content,
    parse_context,
    validate_context,
    materialize_context,
    collect_artifacts,
    MAX_SCRIPT_BYTES,
    MAX_TIMEOUT_S,
    DEFAULT_TIMEOUT_S,
    EXIT_CODE_TIMEOUT,
    EXIT_CODE_INTERNAL_ERROR,
    CONTENT_TYPE_JSON,
    CONTENT_TYPE_TEXT,
    ENCODING_UTF8,
    ENCODING_BASE64,
    MAX_CONTEXT_BYTES,
    MAX_CONTEXT_FILES,
    MAX_SINGLE_FILE_BYTES,
    MAX_ARTIFACTS_BYTES,
    SAFE_ENV_VARS,
    INPUT_DIR,
    OUTPUT_DIR,
)

# Get the underlying user function from the Azure Functions decorator
run_script = function_app.run_script._function.get_user_function()


# ============================================================================
# error_response() tests
# ============================================================================

def test_error_response_default_status():
    """error_response() with message only returns 400 status."""
    response = error_response("test error")

    assert response.status_code == 400


def test_error_response_custom_status():
    """error_response() with custom status returns that status."""
    response = error_response("test error", status_code=500)

    assert response.status_code == 500


def test_error_response_json_body():
    """error_response() returns JSON body with error field."""
    response = error_response("test error")
    body = json.loads(response.get_body().decode(ENCODING_UTF8))

    assert body == {"error": "test error"}


def test_error_response_content_type():
    """error_response() returns application/json content type."""
    response = error_response("test error")

    assert response.mimetype == CONTENT_TYPE_JSON


# ============================================================================
# _parse_raw_request() tests
# ============================================================================

def test_parse_raw_request_no_timeout():
    """_parse_raw_request() with no timeout param returns default timeout."""
    req = Mock(spec=func.HttpRequest)
    req.get_body.return_value = b"print('hello')"
    req.params.get.return_value = None

    result = _parse_raw_request(req)

    assert result == ("print('hello')", DEFAULT_TIMEOUT_S, {})


def test_parse_raw_request_with_valid_timeout():
    """_parse_raw_request() with valid timeout param returns parsed timeout."""
    req = Mock(spec=func.HttpRequest)
    req.get_body.return_value = b"print('hello')"
    req.params.get.return_value = "120"

    result = _parse_raw_request(req)

    assert result == ("print('hello')", 120, {})


def test_parse_raw_request_invalid_utf8():
    """_parse_raw_request() with invalid UTF-8 body returns error response."""
    req = Mock(spec=func.HttpRequest)
    req.get_body.return_value = b"\xff\xfe"
    req.params.get.return_value = None

    result = _parse_raw_request(req)

    assert isinstance(result, func.HttpResponse)
    assert result.status_code == 400


def test_parse_raw_request_non_integer_timeout():
    """_parse_raw_request() with non-integer timeout returns error response."""
    req = Mock(spec=func.HttpRequest)
    req.get_body.return_value = b"print('hello')"
    req.params.get.return_value = "abc"

    result = _parse_raw_request(req)

    assert isinstance(result, func.HttpResponse)
    assert result.status_code == 400


# ============================================================================
# _parse_json_request() tests
# ============================================================================

def test_parse_json_request_script_only():
    """_parse_json_request() with script only returns default timeout."""
    req = Mock(spec=func.HttpRequest)
    req.get_json.return_value = {"script": "print('hello')"}

    result = _parse_json_request(req)

    assert result == ("print('hello')", DEFAULT_TIMEOUT_S, {})


def test_parse_json_request_script_and_timeout():
    """_parse_json_request() with script and timeout returns both."""
    req = Mock(spec=func.HttpRequest)
    req.get_json.return_value = {"script": "print('hello')", "timeout_s": 120}

    result = _parse_json_request(req)

    assert result == ("print('hello')", 120, {})


def test_parse_json_request_with_context():
    """_parse_json_request() with context returns context dict."""
    req = Mock(spec=func.HttpRequest)
    req.get_json.return_value = {
        "script": "print('hello')",
        "context": {"data.csv": "a,b\n1,2"}
    }

    result = _parse_json_request(req)

    assert result == ("print('hello')", DEFAULT_TIMEOUT_S, {"data.csv": "a,b\n1,2"})


def test_parse_json_request_invalid_json():
    """_parse_json_request() with invalid JSON returns error response."""
    req = Mock(spec=func.HttpRequest)
    req.get_json.side_effect = ValueError("Invalid JSON")

    result = _parse_json_request(req)

    assert isinstance(result, func.HttpResponse)
    assert result.status_code == 400


def test_parse_json_request_missing_script():
    """_parse_json_request() with missing script field returns error response."""
    req = Mock(spec=func.HttpRequest)
    req.get_json.return_value = {"timeout_s": 60}

    result = _parse_json_request(req)

    assert isinstance(result, func.HttpResponse)
    assert result.status_code == 400


def test_parse_json_request_non_string_script():
    """_parse_json_request() with non-string script returns error response."""
    req = Mock(spec=func.HttpRequest)
    req.get_json.return_value = {"script": 123}

    result = _parse_json_request(req)

    assert isinstance(result, func.HttpResponse)
    assert result.status_code == 400


def test_parse_json_request_non_integer_timeout():
    """_parse_json_request() with non-integer timeout returns error response."""
    req = Mock(spec=func.HttpRequest)
    req.get_json.return_value = {"script": "print('hello')", "timeout_s": "abc"}

    result = _parse_json_request(req)

    assert isinstance(result, func.HttpResponse)
    assert result.status_code == 400


# ============================================================================
# parse_request() tests
# ============================================================================

def test_parse_request_routes_text_plain():
    """parse_request() routes text/plain content-type to _parse_raw_request."""
    req = Mock(spec=func.HttpRequest)
    req.headers.get.return_value = CONTENT_TYPE_TEXT
    req.get_body.return_value = b"print('hello')"
    req.params.get.return_value = None

    result = parse_request(req)

    assert result == ("print('hello')", DEFAULT_TIMEOUT_S, {})


def test_parse_request_routes_application_json():
    """parse_request() routes application/json to _parse_json_request."""
    req = Mock(spec=func.HttpRequest)
    req.headers.get.return_value = CONTENT_TYPE_JSON
    req.get_json.return_value = {"script": "print('hello')"}

    result = parse_request(req)

    assert result == ("print('hello')", DEFAULT_TIMEOUT_S, {})


def test_parse_request_default_to_json():
    """parse_request() defaults to JSON parsing when no content-type header."""
    req = Mock(spec=func.HttpRequest)
    req.headers.get.return_value = ""
    req.get_json.return_value = {"script": "print('hello')"}

    result = parse_request(req)

    assert result == ("print('hello')", DEFAULT_TIMEOUT_S, {})


# ============================================================================
# validate_timeout() tests
# ============================================================================

def test_validate_timeout_zero():
    """validate_timeout() with zero returns error response."""
    result = validate_timeout(0)

    assert isinstance(result, func.HttpResponse)
    assert result.status_code == 400


def test_validate_timeout_negative():
    """validate_timeout() with negative value returns error response."""
    result = validate_timeout(-5)

    assert isinstance(result, func.HttpResponse)
    assert result.status_code == 400


def test_validate_timeout_valid():
    """validate_timeout() with valid timeout returns same value."""
    result = validate_timeout(60)

    assert result == 60


def test_validate_timeout_exceeds_max():
    """validate_timeout() with timeout > MAX_TIMEOUT_S returns clamped value."""
    result = validate_timeout(500)

    assert result == MAX_TIMEOUT_S


@patch('function_app.logging')
def test_validate_timeout_logs_warning_on_clamp(mock_logging):
    """validate_timeout() logs warning when clamping timeout."""
    validate_timeout(500)

    assert mock_logging.warning.called


# ============================================================================
# validate_script_size() tests
# ============================================================================

def test_validate_script_size_within_limit():
    """validate_script_size() with small script returns None."""
    script = "print('hello')"

    result = validate_script_size(script)

    assert result is None


def test_validate_script_size_exceeds_limit():
    """validate_script_size() with oversized script returns 413 error."""
    script = "x" * (MAX_SCRIPT_BYTES + 1)

    result = validate_script_size(script)

    assert isinstance(result, func.HttpResponse)
    assert result.status_code == 413


def test_validate_script_size_exactly_at_limit():
    """validate_script_size() with script exactly at limit returns None."""
    script = "x" * MAX_SCRIPT_BYTES

    result = validate_script_size(script)

    assert result is None


# ============================================================================
# _cleanup_exec_dir() tests
# ============================================================================

@patch('function_app.shutil.rmtree')
def test_cleanup_exec_dir_success(mock_rmtree):
    """_cleanup_exec_dir() calls shutil.rmtree with directory path."""
    from pathlib import Path
    exec_dir = Path("/tmp/exec_abc123")

    _cleanup_exec_dir(exec_dir)

    mock_rmtree.assert_called_once_with(exec_dir)


@patch('function_app.shutil.rmtree')
def test_cleanup_exec_dir_swallows_exceptions(mock_rmtree):
    """_cleanup_exec_dir() does not raise when shutil.rmtree fails."""
    from pathlib import Path
    mock_rmtree.side_effect = OSError("Directory not found")
    exec_dir = Path("/tmp/exec_abc123")

    _cleanup_exec_dir(exec_dir)

    # No exception should be raised


# ============================================================================
# _run_subprocess() tests
# ============================================================================

@patch('function_app.subprocess.run')
@patch('function_app.sys.executable', '/usr/bin/python3')
def test_run_subprocess_success(mock_run):
    """_run_subprocess() returns ExecutionResult for successful execution."""
    mock_run.return_value = Mock(
        returncode=0,
        stdout=b"output",
        stderr=b""
    )

    result = _run_subprocess("/tmp/script.py", "/tmp", 60)

    assert result.exit_code == 0
    assert result.stdout == "output"
    assert result.stderr == ""


@patch('function_app.subprocess.run')
@patch('function_app.sys.executable', '/usr/bin/python3')
def test_run_subprocess_nonzero_exit(mock_run):
    """_run_subprocess() returns ExecutionResult with non-zero exit code."""
    mock_run.return_value = Mock(
        returncode=1,
        stdout=b"",
        stderr=b"error message"
    )

    result = _run_subprocess("/tmp/script.py", "/tmp", 60)

    assert result.exit_code == 1
    assert result.stderr == "error message"


@patch('function_app.subprocess.run')
@patch('function_app.sys.executable', '/usr/bin/python3')
def test_run_subprocess_timeout(mock_run):
    """_run_subprocess() returns ExecutionResult with timeout exit code on timeout."""
    mock_run.side_effect = subprocess.TimeoutExpired(
        cmd=["python3", "script.py"],
        timeout=60,
        output=b"partial output",
        stderr=b"partial error"
    )

    result = _run_subprocess("/tmp/script.py", "/tmp", 60)

    assert result.exit_code == EXIT_CODE_TIMEOUT
    assert "partial output" in result.stdout
    assert "timed out" in result.stderr


@patch('function_app.subprocess.run')
@patch('function_app.sys.executable', '/usr/bin/python3')
def test_run_subprocess_unexpected_exception(mock_run):
    """_run_subprocess() returns ExecutionResult with internal error on exception."""
    mock_run.side_effect = RuntimeError("Unexpected error")

    result = _run_subprocess("/tmp/script.py", "/tmp", 60)

    assert result.exit_code == EXIT_CODE_INTERNAL_ERROR
    assert "Internal execution error" in result.stderr


@patch('function_app.subprocess.run')
@patch('function_app.sys.executable', '/usr/bin/python3')
def test_run_subprocess_command_args(mock_run):
    """_run_subprocess() invokes subprocess with correct command arguments."""
    mock_run.return_value = Mock(returncode=0, stdout=b"", stderr=b"")

    _run_subprocess("/tmp/script.py", "/tmp", 60)

    call_args = mock_run.call_args
    assert call_args[0][0] == ['/usr/bin/python3', '-X', 'utf8', '/tmp/script.py']


@patch('function_app.subprocess.run')
@patch('function_app.sys.executable', '/usr/bin/python3')
def test_run_subprocess_timeout_parameter(mock_run):
    """_run_subprocess() passes timeout parameter to subprocess.run."""
    mock_run.return_value = Mock(returncode=0, stdout=b"", stderr=b"")

    _run_subprocess("/tmp/script.py", "/tmp", 120)

    call_args = mock_run.call_args
    assert call_args[1]['timeout'] == 120


# ============================================================================
# execute_script() tests
# ============================================================================

@patch('function_app._cleanup_exec_dir')
@patch('function_app.collect_artifacts')
@patch('function_app._run_subprocess')
@patch('function_app.uuid.uuid4')
@patch('function_app.tempfile.gettempdir')
def test_execute_script_creates_exec_dir(mock_gettempdir, mock_uuid, mock_run, mock_collect, mock_cleanup):
    """execute_script() creates execution directory."""
    import tempfile
    mock_gettempdir.return_value = tempfile.gettempdir()
    mock_uuid.return_value = "test-uuid-123"
    mock_run.return_value = ExecutionResult(0, "", "")
    mock_collect.return_value = {}

    execute_script("print('hello')", 60)

    assert mock_run.called
    call_args = mock_run.call_args[0]
    assert "exec_test-uuid-123" in call_args[1]


@patch('function_app._cleanup_exec_dir')
@patch('function_app.collect_artifacts')
@patch('function_app._run_subprocess')
@patch('function_app.uuid.uuid4')
@patch('function_app.tempfile.gettempdir')
def test_execute_script_calls_run_subprocess(mock_gettempdir, mock_uuid, mock_run, mock_collect, mock_cleanup):
    """execute_script() invokes _run_subprocess with correct arguments."""
    import tempfile
    mock_gettempdir.return_value = tempfile.gettempdir()
    mock_uuid.return_value = "abc123"
    mock_run.return_value = ExecutionResult(0, "", "")
    mock_collect.return_value = {}

    execute_script("print('hello')", 60)

    assert mock_run.called
    call_args = mock_run.call_args[0]
    assert "script_abc123.py" in call_args[0]
    assert call_args[2] == 60


@patch('function_app._cleanup_exec_dir')
@patch('function_app.collect_artifacts')
@patch('function_app._run_subprocess')
@patch('function_app.uuid.uuid4')
@patch('function_app.tempfile.gettempdir')
def test_execute_script_cleans_up_on_success(mock_gettempdir, mock_uuid, mock_run, mock_collect, mock_cleanup):
    """execute_script() cleans up execution directory after successful execution."""
    import tempfile
    mock_gettempdir.return_value = tempfile.gettempdir()
    mock_uuid.return_value = "abc123"
    mock_run.return_value = ExecutionResult(0, "", "")
    mock_collect.return_value = {}

    execute_script("print('hello')", 60)

    assert mock_cleanup.called


@patch('function_app._cleanup_exec_dir')
@patch('function_app.collect_artifacts')
@patch('function_app._run_subprocess')
@patch('function_app.uuid.uuid4')
@patch('function_app.tempfile.gettempdir')
def test_execute_script_cleans_up_on_failure(mock_gettempdir, mock_uuid, mock_run, mock_collect, mock_cleanup):
    """execute_script() cleans up execution directory even when execution fails."""
    import tempfile
    mock_gettempdir.return_value = tempfile.gettempdir()
    mock_uuid.return_value = "abc123"
    mock_run.side_effect = RuntimeError("Test error")
    mock_collect.return_value = {}

    try:
        execute_script("print('hello')", 60)
    except RuntimeError:
        pass

    assert mock_cleanup.called


@patch('function_app._cleanup_exec_dir')
@patch('function_app.collect_artifacts')
@patch('function_app._run_subprocess')
@patch('function_app.uuid.uuid4')
@patch('function_app.tempfile.gettempdir')
def test_execute_script_returns_execution_result_with_artifacts(mock_gettempdir, mock_uuid, mock_run, mock_collect, mock_cleanup):
    """execute_script() returns ExecutionResult with artifacts."""
    import tempfile
    mock_gettempdir.return_value = tempfile.gettempdir()
    mock_uuid.return_value = "abc123"
    mock_run.return_value = ExecutionResult(0, "output", "")
    mock_collect.return_value = {"result.txt": "data"}

    result = execute_script("print('hello')", 60)

    assert result.exit_code == 0
    assert result.stdout == "output"
    assert result.artifacts == {"result.txt": "data"}


# ============================================================================
# run_script() integration tests
# ============================================================================

@patch('function_app.execute_script')
def test_run_script_success_flow(mock_execute):
    """run_script() returns 200 JSON response for successful execution."""
    req = Mock(spec=func.HttpRequest)
    req.headers.get.return_value = CONTENT_TYPE_JSON
    req.get_json.return_value = {"script": "print('hello')"}
    mock_execute.return_value = ExecutionResult(0, "hello\n", "", {})

    response = run_script(req)

    assert response.status_code == 200
    body = json.loads(response.get_body().decode(ENCODING_UTF8))
    assert body["exit_code"] == 0
    assert body["stdout"] == "hello\n"
    assert body["artifacts"] == {}


@patch('function_app.execute_script')
def test_run_script_parse_error(mock_execute):
    """run_script() returns error when request parsing fails."""
    req = Mock(spec=func.HttpRequest)
    req.headers.get.return_value = CONTENT_TYPE_JSON
    req.get_json.side_effect = ValueError("Invalid JSON")

    response = run_script(req)

    assert response.status_code == 400
    assert not mock_execute.called


@patch('function_app.execute_script')
def test_run_script_timeout_validation_error(mock_execute):
    """run_script() returns error when timeout validation fails."""
    req = Mock(spec=func.HttpRequest)
    req.headers.get.return_value = CONTENT_TYPE_JSON
    req.get_json.return_value = {"script": "print('hello')", "timeout_s": 0}

    response = run_script(req)

    assert response.status_code == 400
    assert not mock_execute.called


@patch('function_app.execute_script')
def test_run_script_size_validation_error(mock_execute):
    """run_script() returns error when script size validation fails."""
    req = Mock(spec=func.HttpRequest)
    req.headers.get.return_value = CONTENT_TYPE_JSON
    large_script = "x" * (MAX_SCRIPT_BYTES + 1)
    req.get_json.return_value = {"script": large_script}

    response = run_script(req)

    assert response.status_code == 413
    assert not mock_execute.called


@patch('function_app.execute_script')
def test_run_script_execution_error(mock_execute):
    """run_script() returns error when execute_script returns error response."""
    req = Mock(spec=func.HttpRequest)
    req.headers.get.return_value = CONTENT_TYPE_JSON
    req.get_json.return_value = {"script": "print('hello')"}
    mock_execute.return_value = error_response("Execution failed", 500)

    response = run_script(req)

    assert response.status_code == 500


@patch('function_app.execute_script')
def test_run_script_timeout_clamps(mock_execute):
    """run_script() clamps excessive timeout and executes script."""
    req = Mock(spec=func.HttpRequest)
    req.headers.get.return_value = CONTENT_TYPE_JSON
    req.get_json.return_value = {"script": "print('hello')", "timeout_s": 500}
    mock_execute.return_value = ExecutionResult(0, "hello\n", "", {})

    response = run_script(req)

    assert response.status_code == 200
    call_args = mock_execute.call_args[0]
    assert call_args[1] == MAX_TIMEOUT_S


@patch('function_app.execute_script')
def test_run_script_response_structure(mock_execute):
    """run_script() returns response with correct JSON structure."""
    req = Mock(spec=func.HttpRequest)
    req.headers.get.return_value = CONTENT_TYPE_JSON
    req.get_json.return_value = {"script": "print('hello')"}
    mock_execute.return_value = ExecutionResult(42, "out", "err", {"result.txt": "data"})

    response = run_script(req)
    body = json.loads(response.get_body().decode(ENCODING_UTF8))

    assert "exit_code" in body
    assert "stdout" in body
    assert "stderr" in body
    assert "artifacts" in body
    assert body["exit_code"] == 42
    assert body["stdout"] == "out"
    assert body["stderr"] == "err"
    assert body["artifacts"] == {"result.txt": "data"}


@patch('function_app.execute_script')
def test_run_script_content_type(mock_execute):
    """run_script() returns application/json content type."""
    req = Mock(spec=func.HttpRequest)
    req.headers.get.return_value = CONTENT_TYPE_JSON
    req.get_json.return_value = {"script": "print('hello')"}
    mock_execute.return_value = ExecutionResult(0, "", "", {})

    response = run_script(req)

    assert response.mimetype == CONTENT_TYPE_JSON


# ============================================================================
# is_binary_content() tests
# ============================================================================

def test_is_binary_content_with_null_bytes():
    """is_binary_content() returns True for data with null bytes."""
    data = b"hello\x00world"

    result = is_binary_content(data)

    assert result is True


def test_is_binary_content_with_valid_utf8():
    """is_binary_content() returns False for valid UTF-8 text."""
    data = b"Hello, World!"

    result = is_binary_content(data)

    assert result is False


def test_is_binary_content_with_unicode():
    """is_binary_content() returns False for valid UTF-8 unicode."""
    data = "こんにちは".encode(ENCODING_UTF8)

    result = is_binary_content(data)

    assert result is False


def test_is_binary_content_with_invalid_utf8():
    """is_binary_content() returns True for invalid UTF-8 bytes."""
    data = b"\xff\xfe\x00\x01"

    result = is_binary_content(data)

    assert result is True


def test_is_binary_content_with_empty():
    """is_binary_content() returns False for empty bytes."""
    data = b""

    result = is_binary_content(data)

    assert result is False


# ============================================================================
# decode_file_content() tests
# ============================================================================

def test_decode_file_content_utf8():
    """decode_file_content() decodes UTF-8 content."""
    ctx_file = ContextFile(name="test.txt", content="Hello", encoding=ENCODING_UTF8)

    result = decode_file_content(ctx_file)

    assert result == b"Hello"


def test_decode_file_content_base64():
    """decode_file_content() decodes base64 content."""
    import base64
    original = b"binary data"
    encoded = base64.b64encode(original).decode("ascii")
    ctx_file = ContextFile(name="test.bin", content=encoded, encoding=ENCODING_BASE64)

    result = decode_file_content(ctx_file)

    assert result == original


def test_decode_file_content_utf8_unicode():
    """decode_file_content() handles unicode in UTF-8."""
    ctx_file = ContextFile(name="test.txt", content="こんにちは", encoding=ENCODING_UTF8)

    result = decode_file_content(ctx_file)

    assert result == "こんにちは".encode(ENCODING_UTF8)


# ============================================================================
# encode_file_content() tests
# ============================================================================

def test_encode_file_content_text():
    """encode_file_content() returns string for text content."""
    data = b"Hello, World!"

    result = encode_file_content(data)

    assert result == "Hello, World!"


def test_encode_file_content_binary():
    """encode_file_content() returns dict for binary content."""
    import base64
    data = b"\x00\x01\x02\x03"

    result = encode_file_content(data)

    assert isinstance(result, dict)
    assert result["encoding"] == ENCODING_BASE64
    assert result["content"] == base64.b64encode(data).decode("ascii")


def test_encode_file_content_unicode():
    """encode_file_content() returns string for unicode text."""
    data = "こんにちは".encode(ENCODING_UTF8)

    result = encode_file_content(data)

    assert result == "こんにちは"


# ============================================================================
# parse_context() tests
# ============================================================================

def test_parse_context_string_value():
    """parse_context() creates ContextFile from string value."""
    raw = {"data.csv": "a,b\n1,2"}

    result = parse_context(raw)

    assert isinstance(result, dict)
    assert "data.csv" in result
    assert result["data.csv"].name == "data.csv"
    assert result["data.csv"].content == "a,b\n1,2"
    assert result["data.csv"].encoding == ENCODING_UTF8


def test_parse_context_object_value_utf8():
    """parse_context() creates ContextFile from object with UTF-8 encoding."""
    raw = {"data.csv": {"content": "a,b\n1,2", "encoding": "utf-8"}}

    result = parse_context(raw)

    assert result["data.csv"].content == "a,b\n1,2"
    assert result["data.csv"].encoding == ENCODING_UTF8


def test_parse_context_object_value_base64():
    """parse_context() creates ContextFile from object with base64 encoding."""
    raw = {"image.png": {"content": "iVBORw0KGgo=", "encoding": "base64"}}

    result = parse_context(raw)

    assert result["image.png"].content == "iVBORw0KGgo="
    assert result["image.png"].encoding == ENCODING_BASE64


def test_parse_context_multiple_files():
    """parse_context() handles multiple files."""
    raw = {
        "data.csv": "a,b",
        "config.json": {"content": "{}", "encoding": "utf-8"}
    }

    result = parse_context(raw)

    assert len(result) == 2
    assert "data.csv" in result
    assert "config.json" in result


def test_parse_context_not_dict_error():
    """parse_context() returns error for non-dict context."""
    result = parse_context(["not", "a", "dict"])

    assert isinstance(result, func.HttpResponse)
    assert result.status_code == 400


def test_parse_context_invalid_encoding_error():
    """parse_context() returns error for invalid encoding."""
    raw = {"data.csv": {"content": "data", "encoding": "invalid"}}

    result = parse_context(raw)

    assert isinstance(result, func.HttpResponse)
    assert result.status_code == 400


def test_parse_context_missing_content_error():
    """parse_context() returns error when content is missing."""
    raw = {"data.csv": {"encoding": "utf-8"}}

    result = parse_context(raw)

    assert isinstance(result, func.HttpResponse)
    assert result.status_code == 400


def test_parse_context_non_string_content_error():
    """parse_context() returns error for non-string content."""
    raw = {"data.csv": {"content": 123, "encoding": "utf-8"}}

    result = parse_context(raw)

    assert isinstance(result, func.HttpResponse)
    assert result.status_code == 400


# ============================================================================
# validate_context() tests
# ============================================================================

def test_validate_context_valid():
    """validate_context() returns None for valid context."""
    context = {
        "data.csv": ContextFile(name="data.csv", content="a,b", encoding=ENCODING_UTF8)
    }

    result = validate_context(context)

    assert result is None


def test_validate_context_too_many_files():
    """validate_context() returns error when exceeding file count limit."""
    context = {
        f"file{i}.txt": ContextFile(name=f"file{i}.txt", content="data", encoding=ENCODING_UTF8)
        for i in range(MAX_CONTEXT_FILES + 1)
    }

    result = validate_context(context)

    assert isinstance(result, func.HttpResponse)
    assert result.status_code == 400


def test_validate_context_path_traversal_slash():
    """validate_context() returns error for filename with forward slash."""
    context = {
        "../secret.txt": ContextFile(name="../secret.txt", content="data", encoding=ENCODING_UTF8)
    }

    result = validate_context(context)

    assert isinstance(result, func.HttpResponse)
    assert result.status_code == 400


def test_validate_context_path_traversal_backslash():
    """validate_context() returns error for filename with backslash."""
    context = {
        "..\\secret.txt": ContextFile(name="..\\secret.txt", content="data", encoding=ENCODING_UTF8)
    }

    result = validate_context(context)

    assert isinstance(result, func.HttpResponse)
    assert result.status_code == 400


def test_validate_context_leading_dot():
    """validate_context() returns error for filename starting with dot."""
    context = {
        ".hidden": ContextFile(name=".hidden", content="data", encoding=ENCODING_UTF8)
    }

    result = validate_context(context)

    assert isinstance(result, func.HttpResponse)
    assert result.status_code == 400


def test_validate_context_single_file_too_large():
    """validate_context() returns 413 error for file exceeding size limit."""
    large_content = "x" * (MAX_SINGLE_FILE_BYTES + 1)
    context = {
        "large.txt": ContextFile(name="large.txt", content=large_content, encoding=ENCODING_UTF8)
    }

    result = validate_context(context)

    assert isinstance(result, func.HttpResponse)
    assert result.status_code == 413


def test_validate_context_total_too_large():
    """validate_context() returns 413 error when total size exceeds limit."""
    # Create multiple files that together exceed the limit
    file_size = MAX_CONTEXT_BYTES // 3
    content = "x" * file_size
    context = {
        f"file{i}.txt": ContextFile(name=f"file{i}.txt", content=content, encoding=ENCODING_UTF8)
        for i in range(4)
    }

    result = validate_context(context)

    assert isinstance(result, func.HttpResponse)
    assert result.status_code == 413


def test_validate_context_invalid_base64():
    """validate_context() returns error for invalid base64 content."""
    context = {
        "image.png": ContextFile(name="image.png", content="not-valid-base64!!!", encoding=ENCODING_BASE64)
    }

    result = validate_context(context)

    assert isinstance(result, func.HttpResponse)
    assert result.status_code == 400


# ============================================================================
# materialize_context() tests
# ============================================================================

def test_materialize_context_creates_directories():
    """materialize_context() creates input and output directories."""
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmpdir:
        exec_dir = Path(tmpdir)
        context = {}

        materialize_context(context, exec_dir)

        assert (exec_dir / INPUT_DIR).exists()
        assert (exec_dir / OUTPUT_DIR).exists()


def test_materialize_context_writes_files():
    """materialize_context() writes context files to input directory."""
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmpdir:
        exec_dir = Path(tmpdir)
        context = {
            "data.csv": ContextFile(name="data.csv", content="a,b\n1,2", encoding=ENCODING_UTF8)
        }

        materialize_context(context, exec_dir)

        input_file = exec_dir / INPUT_DIR / "data.csv"
        assert input_file.exists()
        assert input_file.read_text() == "a,b\n1,2"


def test_materialize_context_writes_binary():
    """materialize_context() writes binary files correctly."""
    import tempfile
    import base64
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmpdir:
        exec_dir = Path(tmpdir)
        binary_data = b"\x00\x01\x02\x03"
        encoded = base64.b64encode(binary_data).decode("ascii")
        context = {
            "data.bin": ContextFile(name="data.bin", content=encoded, encoding=ENCODING_BASE64)
        }

        materialize_context(context, exec_dir)

        input_file = exec_dir / INPUT_DIR / "data.bin"
        assert input_file.exists()
        assert input_file.read_bytes() == binary_data


# ============================================================================
# collect_artifacts() tests
# ============================================================================

def test_collect_artifacts_empty_output():
    """collect_artifacts() returns empty dict when output dir is empty."""
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmpdir:
        exec_dir = Path(tmpdir)
        (exec_dir / OUTPUT_DIR).mkdir()

        result = collect_artifacts(exec_dir)

        assert result == {}


def test_collect_artifacts_no_output_dir():
    """collect_artifacts() returns empty dict when output dir doesn't exist."""
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmpdir:
        exec_dir = Path(tmpdir)

        result = collect_artifacts(exec_dir)

        assert result == {}


def test_collect_artifacts_text_file():
    """collect_artifacts() collects text files as strings."""
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmpdir:
        exec_dir = Path(tmpdir)
        output_dir = exec_dir / OUTPUT_DIR
        output_dir.mkdir()
        (output_dir / "result.txt").write_text("output data")

        result = collect_artifacts(exec_dir)

        assert result == {"result.txt": "output data"}


def test_collect_artifacts_binary_file():
    """collect_artifacts() collects binary files with base64 encoding."""
    import tempfile
    import base64
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmpdir:
        exec_dir = Path(tmpdir)
        output_dir = exec_dir / OUTPUT_DIR
        output_dir.mkdir()
        binary_data = b"\x00\x01\x02\x03"
        (output_dir / "data.bin").write_bytes(binary_data)

        result = collect_artifacts(exec_dir)

        assert "data.bin" in result
        assert isinstance(result["data.bin"], dict)
        assert result["data.bin"]["encoding"] == ENCODING_BASE64
        assert result["data.bin"]["content"] == base64.b64encode(binary_data).decode("ascii")


def test_collect_artifacts_multiple_files():
    """collect_artifacts() collects multiple files."""
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmpdir:
        exec_dir = Path(tmpdir)
        output_dir = exec_dir / OUTPUT_DIR
        output_dir.mkdir()
        (output_dir / "result.txt").write_text("text data")
        (output_dir / "result.csv").write_text("a,b\n1,2")

        result = collect_artifacts(exec_dir)

        assert len(result) == 2
        assert result["result.txt"] == "text data"
        assert result["result.csv"] == "a,b\n1,2"


def test_collect_artifacts_too_large():
    """collect_artifacts() returns 500 error when artifacts exceed size limit."""
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmpdir:
        exec_dir = Path(tmpdir)
        output_dir = exec_dir / OUTPUT_DIR
        output_dir.mkdir()
        # Write a file larger than the limit
        large_data = "x" * (MAX_ARTIFACTS_BYTES + 1)
        (output_dir / "large.txt").write_text(large_data)

        result = collect_artifacts(exec_dir)

        assert isinstance(result, func.HttpResponse)
        assert result.status_code == 500


def test_collect_artifacts_skips_directories():
    """collect_artifacts() skips subdirectories in output."""
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmpdir:
        exec_dir = Path(tmpdir)
        output_dir = exec_dir / OUTPUT_DIR
        output_dir.mkdir()
        (output_dir / "result.txt").write_text("data")
        (output_dir / "subdir").mkdir()

        result = collect_artifacts(exec_dir)

        assert result == {"result.txt": "data"}


# ============================================================================
# run_script() integration tests with context
# ============================================================================

@patch('function_app.execute_script')
def test_run_script_with_context(mock_execute):
    """run_script() passes parsed context to execute_script."""
    req = Mock(spec=func.HttpRequest)
    req.headers.get.return_value = CONTENT_TYPE_JSON
    req.get_json.return_value = {
        "script": "print('hello')",
        "context": {"data.csv": "a,b\n1,2"}
    }
    mock_execute.return_value = ExecutionResult(0, "hello\n", "", {})

    run_script(req)

    call_args = mock_execute.call_args
    context_arg = call_args[0][2]
    assert "data.csv" in context_arg
    assert context_arg["data.csv"].content == "a,b\n1,2"


@patch('function_app.execute_script')
def test_run_script_context_validation_error(mock_execute):
    """run_script() returns error when context validation fails."""
    req = Mock(spec=func.HttpRequest)
    req.headers.get.return_value = CONTENT_TYPE_JSON
    req.get_json.return_value = {
        "script": "print('hello')",
        "context": {"../evil.txt": "data"}
    }

    response = run_script(req)

    assert response.status_code == 400
    assert not mock_execute.called


# =============================================================================
# Security Quick Wins Tests
# =============================================================================


def test_get_client_ip_from_forwarded_header():
    """get_client_ip() extracts IP from X-Forwarded-For header."""
    req = Mock(spec=func.HttpRequest)
    req.headers.get.side_effect = lambda h, d="": "1.2.3.4, 10.0.0.1" if h == "X-Forwarded-For" else d

    result = get_client_ip(req)

    assert result == "1.2.3.4"


def test_get_client_ip_from_client_ip_header():
    """get_client_ip() falls back to X-Client-IP when X-Forwarded-For is empty."""
    req = Mock(spec=func.HttpRequest)
    req.headers.get.side_effect = lambda h, d="": "5.6.7.8" if h == "X-Client-IP" else d

    result = get_client_ip(req)

    assert result == "5.6.7.8"


def test_get_client_ip_unknown():
    """get_client_ip() returns 'unknown' when no IP headers present."""
    req = Mock(spec=func.HttpRequest)
    # Simulate no headers by returning empty for X-Forwarded-For and "unknown" default for X-Client-IP
    def header_getter(name, default=""):
        if name == "X-Forwarded-For":
            return ""
        if name == "X-Client-IP":
            return default  # Returns the default which is "unknown"
        return default
    req.headers.get.side_effect = header_getter

    result = get_client_ip(req)

    assert result == "unknown"


def test_compute_script_hash_deterministic():
    """compute_script_hash() returns consistent hash for same script."""
    script = "print('hello')"

    hash1 = compute_script_hash(script)
    hash2 = compute_script_hash(script)

    assert hash1 == hash2
    assert len(hash1) == 16  # Truncated to 16 chars


def test_compute_script_hash_different_scripts():
    """compute_script_hash() returns different hashes for different scripts."""
    script1 = "print('hello')"
    script2 = "print('world')"

    hash1 = compute_script_hash(script1)
    hash2 = compute_script_hash(script2)

    assert hash1 != hash2


@patch('function_app.logging')
def test_log_audit_event_logs_json(mock_logging):
    """log_audit_event() logs structured JSON."""
    log_audit_event(
        "test_event", "req123", "1.2.3.4", "abc123",
        100, 30, 2, duration_ms=150.5, exit_code=0
    )

    mock_logging.info.assert_called_once()
    call_arg = mock_logging.info.call_args[0][0]
    assert "AUDIT:" in call_arg
    assert '"event": "test_event"' in call_arg
    assert '"request_id": "req123"' in call_arg
    assert '"exit_code": 0' in call_arg


def test_create_safe_environment_excludes_secrets():
    """_create_safe_environment() excludes sensitive variables."""
    import os
    # Set some dangerous env vars
    original_env = os.environ.copy()
    try:
        os.environ["AZURE_STORAGE_CONNECTION_STRING"] = "secret123"
        os.environ["API_KEY"] = "supersecret"
        os.environ["PATH"] = "/usr/bin"  # Safe var

        safe_env = _create_safe_environment()

        assert "AZURE_STORAGE_CONNECTION_STRING" not in safe_env
        assert "API_KEY" not in safe_env
        assert safe_env.get("PATH") == "/usr/bin"
        assert safe_env.get("PYTHONIOENCODING") == "utf-8"
    finally:
        os.environ.clear()
        os.environ.update(original_env)


def test_create_safe_environment_only_includes_safe_vars():
    """_create_safe_environment() only includes variables in SAFE_ENV_VARS."""
    import os
    original_env = os.environ.copy()
    try:
        os.environ.clear()
        os.environ["PATH"] = "/usr/bin"
        os.environ["HOME"] = "/home/user"
        os.environ["DANGEROUS_VAR"] = "should_not_appear"

        safe_env = _create_safe_environment()

        assert safe_env.get("PATH") == "/usr/bin"
        assert safe_env.get("HOME") == "/home/user"
        assert "DANGEROUS_VAR" not in safe_env
        # Always added
        assert "PYTHONIOENCODING" in safe_env
        assert "PYTHONUNBUFFERED" in safe_env
    finally:
        os.environ.clear()
        os.environ.update(original_env)


def test_safe_env_vars_is_frozen():
    """SAFE_ENV_VARS is immutable frozenset."""
    assert isinstance(SAFE_ENV_VARS, frozenset)
    with pytest.raises(AttributeError):
        SAFE_ENV_VARS.add("NEW_VAR")
