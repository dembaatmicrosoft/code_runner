"""
Comprehensive unit tests for CodeRunner Azure Function.

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
    _cleanup_script,
    ExecutionResult,
    MAX_SCRIPT_BYTES,
    MAX_TIMEOUT_S,
    DEFAULT_TIMEOUT_S,
    EXIT_CODE_TIMEOUT,
    EXIT_CODE_INTERNAL_ERROR,
    CONTENT_TYPE_JSON,
    CONTENT_TYPE_TEXT,
    ENCODING_UTF8,
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

    assert result == ("print('hello')", DEFAULT_TIMEOUT_S)


def test_parse_raw_request_with_valid_timeout():
    """_parse_raw_request() with valid timeout param returns parsed timeout."""
    req = Mock(spec=func.HttpRequest)
    req.get_body.return_value = b"print('hello')"
    req.params.get.return_value = "120"

    result = _parse_raw_request(req)

    assert result == ("print('hello')", 120)


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

    assert result == ("print('hello')", DEFAULT_TIMEOUT_S)


def test_parse_json_request_script_and_timeout():
    """_parse_json_request() with script and timeout returns both."""
    req = Mock(spec=func.HttpRequest)
    req.get_json.return_value = {"script": "print('hello')", "timeout_s": 120}

    result = _parse_json_request(req)

    assert result == ("print('hello')", 120)


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

    assert result == ("print('hello')", DEFAULT_TIMEOUT_S)


def test_parse_request_routes_application_json():
    """parse_request() routes application/json to _parse_json_request."""
    req = Mock(spec=func.HttpRequest)
    req.headers.get.return_value = CONTENT_TYPE_JSON
    req.get_json.return_value = {"script": "print('hello')"}

    result = parse_request(req)

    assert result == ("print('hello')", DEFAULT_TIMEOUT_S)


def test_parse_request_default_to_json():
    """parse_request() defaults to JSON parsing when no content-type header."""
    req = Mock(spec=func.HttpRequest)
    req.headers.get.return_value = ""
    req.get_json.return_value = {"script": "print('hello')"}

    result = parse_request(req)

    assert result == ("print('hello')", DEFAULT_TIMEOUT_S)


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
# _cleanup_script() tests
# ============================================================================

@patch('function_app.os.remove')
def test_cleanup_script_success(mock_remove):
    """_cleanup_script() calls os.remove with script path."""
    _cleanup_script("/tmp/test_script.py")

    mock_remove.assert_called_once_with("/tmp/test_script.py")


@patch('function_app.os.remove')
def test_cleanup_script_swallows_exceptions(mock_remove):
    """_cleanup_script() does not raise when os.remove fails."""
    mock_remove.side_effect = OSError("File not found")

    _cleanup_script("/tmp/test_script.py")

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

@patch('function_app._cleanup_script')
@patch('function_app._run_subprocess')
@patch('function_app.uuid.uuid4')
@patch('function_app.open', new_callable=mock_open)
@patch('function_app.tempfile.gettempdir')
def test_execute_script_writes_to_temp_file(mock_gettempdir, mock_file, mock_uuid, mock_run, mock_cleanup):
    """execute_script() writes script to temporary file."""
    mock_gettempdir.return_value = "/tmp"
    mock_uuid.return_value = Mock(hex="abc123")
    mock_run.return_value = ExecutionResult(0, "", "")

    execute_script("print('hello')", 60)

    mock_file.assert_called_once()
    handle = mock_file()
    handle.write.assert_called_once_with("print('hello')")


@patch('function_app._cleanup_script')
@patch('function_app._run_subprocess')
@patch('function_app.uuid.uuid4')
@patch('function_app.open', new_callable=mock_open)
@patch('function_app.tempfile.gettempdir')
def test_execute_script_calls_run_subprocess(mock_gettempdir, mock_file, mock_uuid, mock_run, mock_cleanup):
    """execute_script() invokes _run_subprocess with correct arguments."""
    mock_gettempdir.return_value = "/tmp"
    mock_uuid.return_value = "abc123"
    mock_run.return_value = ExecutionResult(0, "", "")

    execute_script("print('hello')", 60)

    assert mock_run.called
    call_args = mock_run.call_args[0]
    assert call_args[0].startswith("/tmp/user_script_")
    assert call_args[1] == "/tmp"
    assert call_args[2] == 60


@patch('function_app._cleanup_script')
@patch('function_app._run_subprocess')
@patch('function_app.uuid.uuid4')
@patch('function_app.open', new_callable=mock_open)
@patch('function_app.tempfile.gettempdir')
def test_execute_script_cleans_up_on_success(mock_gettempdir, mock_file, mock_uuid, mock_run, mock_cleanup):
    """execute_script() cleans up temporary file after successful execution."""
    mock_gettempdir.return_value = "/tmp"
    mock_uuid.return_value = "abc123"
    mock_run.return_value = ExecutionResult(0, "", "")

    execute_script("print('hello')", 60)

    assert mock_cleanup.called


@patch('function_app._cleanup_script')
@patch('function_app._run_subprocess')
@patch('function_app.uuid.uuid4')
@patch('function_app.open', new_callable=mock_open)
@patch('function_app.tempfile.gettempdir')
def test_execute_script_cleans_up_on_failure(mock_gettempdir, mock_file, mock_uuid, mock_run, mock_cleanup):
    """execute_script() cleans up temporary file even when execution fails."""
    mock_gettempdir.return_value = "/tmp"
    mock_uuid.return_value = "abc123"
    mock_run.side_effect = RuntimeError("Test error")

    try:
        execute_script("print('hello')", 60)
    except RuntimeError:
        pass

    assert mock_cleanup.called


@patch('function_app.uuid.uuid4')
@patch('function_app.open', new_callable=mock_open)
@patch('function_app.tempfile.gettempdir')
def test_execute_script_file_write_error(mock_gettempdir, mock_file, mock_uuid):
    """execute_script() returns 500 error when file write fails."""
    mock_gettempdir.return_value = "/tmp"
    mock_uuid.return_value = "abc123"
    mock_file.side_effect = OSError("Disk full")

    result = execute_script("print('hello')", 60)

    assert isinstance(result, func.HttpResponse)
    assert result.status_code == 500


@patch('function_app._cleanup_script')
@patch('function_app._run_subprocess')
@patch('function_app.uuid.uuid4')
@patch('function_app.open', new_callable=mock_open)
@patch('function_app.tempfile.gettempdir')
def test_execute_script_returns_execution_result(mock_gettempdir, mock_file, mock_uuid, mock_run, mock_cleanup):
    """execute_script() returns ExecutionResult from _run_subprocess."""
    mock_gettempdir.return_value = "/tmp"
    mock_uuid.return_value = "abc123"
    expected_result = ExecutionResult(0, "output", "")
    mock_run.return_value = expected_result

    result = execute_script("print('hello')", 60)

    assert result == expected_result


# ============================================================================
# run_script() integration tests
# ============================================================================

@patch('function_app.execute_script')
def test_run_script_success_flow(mock_execute):
    """run_script() returns 200 JSON response for successful execution."""
    req = Mock(spec=func.HttpRequest)
    req.headers.get.return_value = CONTENT_TYPE_JSON
    req.get_json.return_value = {"script": "print('hello')"}
    mock_execute.return_value = ExecutionResult(0, "hello\n", "")

    response = run_script(req)

    assert response.status_code == 200
    body = json.loads(response.get_body().decode(ENCODING_UTF8))
    assert body["exit_code"] == 0
    assert body["stdout"] == "hello\n"


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
    mock_execute.return_value = ExecutionResult(0, "hello\n", "")

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
    mock_execute.return_value = ExecutionResult(42, "out", "err")

    response = run_script(req)
    body = json.loads(response.get_body().decode(ENCODING_UTF8))

    assert "exit_code" in body
    assert "stdout" in body
    assert "stderr" in body
    assert body["exit_code"] == 42
    assert body["stdout"] == "out"
    assert body["stderr"] == "err"


@patch('function_app.execute_script')
def test_run_script_content_type(mock_execute):
    """run_script() returns application/json content type."""
    req = Mock(spec=func.HttpRequest)
    req.headers.get.return_value = CONTENT_TYPE_JSON
    req.get_json.return_value = {"script": "print('hello')"}
    mock_execute.return_value = ExecutionResult(0, "", "")

    response = run_script(req)

    assert response.mimetype == CONTENT_TYPE_JSON
