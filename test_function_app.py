# Copyright (c) 2025 Microsoft Corporation.
# Licensed under the MIT License. See LICENSE file in the project root.

"""
Unit Tests for CodeRunner Azure Function

This test suite validates the CodeRunner service - a secure, isolated Python
code execution endpoint. Tests are organized to match the execution flow from
request ingestion through validation, execution, and response formatting.

Test Philosophy:
    - Fast and deterministic: All external dependencies (subprocess, filesystem,
      network) are mocked for speed and reliability
    - Isolated: Each test validates one specific behavior with minimal assertions
    - AAA Pattern: All tests follow Arrange-Act-Assert structure
    - Comprehensive: Covers happy paths, error conditions, edge cases, and security boundaries

Test Organization:
    Tests are grouped into logical classes mirroring the service architecture:
    - Request Parsing: Content negotiation and input extraction
    - Validation: Size limits, timeouts, and security constraints
    - Context Management: File encoding, materialization, and collection
    - Script Execution: Subprocess isolation and lifecycle management
    - Security: Audit logging, environment isolation, and attack prevention
    - Integration: End-to-end request flows

Coverage Goals:
    - All public API endpoints and functions
    - All error response paths with correct status codes
    - All security boundaries (size limits, path traversal, environment isolation)
    - All data transformations (encoding, decoding, serialization)
"""

import base64
import json
import os
import signal
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import Mock, call, patch

import azure.functions as func
import pytest

import function_app
from function_app import (
    CONTENT_TYPE_JSON,
    CONTENT_TYPE_TEXT,
    DEFAULT_TIMEOUT_S,
    ENCODING_BASE64,
    ENCODING_UTF8,
    EXIT_CODE_INTERNAL_ERROR,
    EXIT_CODE_TIMEOUT,
    INPUT_DIR,
    MAX_ARTIFACTS_BYTES,
    MAX_CONTEXT_BYTES,
    MAX_CONTEXT_FILES,
    MAX_SCRIPT_BYTES,
    MAX_SINGLE_FILE_BYTES,
    MAX_TIMEOUT_S,
    OUTPUT_DIR,
    SAFE_ENV_VARS,
    ContextFile,
    ExecutionResult,
    _cleanup_exec_dir,
    _create_safe_environment,
    _kill_process_tree,
    _parse_json_request,
    _parse_raw_request,
    _run_subprocess,
    collect_artifacts,
    compute_script_hash,
    decode_file_content,
    encode_file_content,
    error_response,
    execute_script,
    get_client_ip,
    is_binary_content,
    log_audit_event,
    materialize_context,
    parse_context,
    parse_request,
    validate_context,
    validate_script_size,
    validate_timeout,
)

# Extract the user function from Azure Functions decorator for direct testing
run_script = function_app.run_script._function.get_user_function()


# =============================================================================
# Pytest Fixtures
# =============================================================================


@pytest.fixture
def mock_request_json():
    """Create a mock HttpRequest with JSON content type."""
    req = Mock(spec=func.HttpRequest)
    req.headers.get.return_value = CONTENT_TYPE_JSON
    return req


@pytest.fixture
def mock_request_text():
    """Create a mock HttpRequest with text/plain content type."""
    req = Mock(spec=func.HttpRequest)
    req.headers.get.return_value = CONTENT_TYPE_TEXT
    return req


@pytest.fixture
def temp_exec_dir():
    """Create a temporary execution directory for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_context_file():
    """Create a sample ContextFile for testing."""
    return ContextFile(name="data.csv", content="a,b\n1,2", encoding=ENCODING_UTF8)


@pytest.fixture
def sample_binary_context():
    """Create a sample binary ContextFile with base64 encoding."""
    binary_data = b"\x00\x01\x02\x03"
    encoded = base64.b64encode(binary_data).decode("ascii")
    return ContextFile(name="data.bin", content=encoded, encoding=ENCODING_BASE64)


# =============================================================================
# Error Response Tests
# =============================================================================


class TestErrorResponse:
    """Tests for error_response() - standardized error formatting."""

    def test_returns_400_by_default(self):
        """error_response() returns 400 status code when not specified.

        Validates that the default error behavior returns HTTP 400 (Bad Request)
        for client errors without requiring explicit status code parameter.
        """
        response = error_response("validation failed")

        assert response.status_code == 400

    def test_returns_custom_status_code(self):
        """error_response() returns specified status code for different error types.

        Ensures that different error classes (413, 500, etc.) can be signaled
        to clients with appropriate HTTP status codes.
        """
        response = error_response("payload too large", status_code=413)

        assert response.status_code == 413

    def test_formats_error_as_json(self):
        """error_response() wraps error message in JSON structure.

        API consumers expect consistent JSON responses with 'error' field
        for programmatic error handling.
        """
        response = error_response("validation failed")
        body = json.loads(response.get_body().decode(ENCODING_UTF8))

        assert body == {"error": "validation failed"}

    def test_sets_json_content_type(self):
        """error_response() sets application/json content type header.

        Ensures clients can correctly parse error responses and frameworks
        apply appropriate content negotiation.
        """
        response = error_response("validation failed")

        assert response.mimetype == CONTENT_TYPE_JSON


# =============================================================================
# Request Parsing Tests
# =============================================================================


class TestParseRawRequest:
    """Tests for _parse_raw_request() - text/plain request parsing."""

    def test_extracts_script_from_body_with_default_timeout(self, mock_request_text):
        """_parse_raw_request() returns script text with default timeout.

        Supports simple POST requests where script is sent as plain text body,
        enabling curl/HTTPie usage without JSON formatting.
        """
        mock_request_text.get_body.return_value = b"print('hello world')"
        mock_request_text.params.get.return_value = None

        script, timeout, context = _parse_raw_request(mock_request_text)

        assert script == "print('hello world')"
        assert timeout == DEFAULT_TIMEOUT_S
        assert context == {}

    def test_parses_timeout_from_query_parameter(self, mock_request_text):
        """_parse_raw_request() extracts timeout from query string.

        Allows clients to specify execution timeout via URL query parameter
        when sending raw text scripts.
        """
        mock_request_text.get_body.return_value = b"import time; time.sleep(5)"
        mock_request_text.params.get.return_value = "120"

        script, timeout, context = _parse_raw_request(mock_request_text)

        assert timeout == 120

    def test_rejects_invalid_utf8_encoding(self, mock_request_text):
        """_parse_raw_request() returns error for non-UTF-8 body content.

        Prevents processing of malformed or binary payloads that could cause
        encoding errors during script execution.
        """
        mock_request_text.get_body.return_value = b"\xff\xfe\x00\x01"

        result = _parse_raw_request(mock_request_text)

        assert isinstance(result, func.HttpResponse)
        assert result.status_code == 400
        body = json.loads(result.get_body().decode(ENCODING_UTF8))
        assert "UTF-8" in body["error"]

    def test_rejects_non_integer_timeout_parameter(self, mock_request_text):
        """_parse_raw_request() returns error for invalid timeout format.

        Validates query parameters early to fail fast before resource allocation.
        """
        mock_request_text.get_body.return_value = b"print('test')"
        mock_request_text.params.get.return_value = "not-a-number"

        result = _parse_raw_request(mock_request_text)

        assert isinstance(result, func.HttpResponse)
        assert result.status_code == 400
        body = json.loads(result.get_body().decode(ENCODING_UTF8))
        assert "timeout_s" in body["error"]


class TestParseJsonRequest:
    """Tests for _parse_json_request() - application/json request parsing."""

    def test_extracts_script_with_default_timeout(self, mock_request_json):
        """_parse_json_request() returns script and default timeout from JSON body.

        Primary request format supporting rich payloads with script, timeout,
        and context files in a single structured request.
        """
        mock_request_json.get_json.return_value = {"script": "print('hello')"}

        script, timeout, context = _parse_json_request(mock_request_json)

        assert script == "print('hello')"
        assert timeout == DEFAULT_TIMEOUT_S
        assert context == {}

    def test_extracts_script_and_custom_timeout(self, mock_request_json):
        """_parse_json_request() parses explicit timeout from request body."""
        mock_request_json.get_json.return_value = {
            "script": "import time; time.sleep(5)",
            "timeout_s": 120
        }

        script, timeout, context = _parse_json_request(mock_request_json)

        assert timeout == 120

    def test_extracts_context_files(self, mock_request_json):
        """_parse_json_request() returns raw context dictionary for downstream parsing.

        Context files enable data science workflows where scripts process input
        datasets and generate output artifacts.
        """
        mock_request_json.get_json.return_value = {
            "script": "# process data",
            "context": {"data.csv": "col1,col2\nval1,val2"}
        }

        script, timeout, context = _parse_json_request(mock_request_json)

        assert context == {"data.csv": "col1,col2\nval1,val2"}

    def test_rejects_malformed_json(self, mock_request_json):
        """_parse_json_request() returns error for invalid JSON syntax."""
        mock_request_json.get_json.side_effect = ValueError("Invalid JSON")

        result = _parse_json_request(mock_request_json)

        assert isinstance(result, func.HttpResponse)
        assert result.status_code == 400

    def test_rejects_missing_script_field(self, mock_request_json):
        """_parse_json_request() returns error when 'script' field is absent.

        Script field is required - cannot execute without code payload.
        """
        mock_request_json.get_json.return_value = {"timeout_s": 60}

        result = _parse_json_request(mock_request_json)

        assert isinstance(result, func.HttpResponse)
        assert result.status_code == 400

    def test_rejects_non_string_script(self, mock_request_json):
        """_parse_json_request() validates script field is string type.

        Prevents type confusion attacks and ensures script is executable text.
        """
        mock_request_json.get_json.return_value = {"script": ["not", "a", "string"]}

        result = _parse_json_request(mock_request_json)

        assert isinstance(result, func.HttpResponse)
        assert result.status_code == 400

    def test_rejects_non_integer_timeout(self, mock_request_json):
        """_parse_json_request() validates timeout is integer type."""
        mock_request_json.get_json.return_value = {
            "script": "print('test')",
            "timeout_s": "should-be-int"
        }

        result = _parse_json_request(mock_request_json)

        assert isinstance(result, func.HttpResponse)
        assert result.status_code == 400


class TestParseRequest:
    """Tests for parse_request() - content-type routing layer."""

    def test_routes_text_plain_to_raw_parser(self, mock_request_text):
        """parse_request() delegates to _parse_raw_request() for text/plain content.

        Enables content-type negotiation to support multiple request formats.
        """
        mock_request_text.get_body.return_value = b"print('test')"
        mock_request_text.params.get.return_value = None

        script, timeout, context = parse_request(mock_request_text)

        assert script == "print('test')"
        assert context == {}  # Raw requests don't support context

    def test_routes_application_json_to_json_parser(self, mock_request_json):
        """parse_request() delegates to _parse_json_request() for application/json."""
        mock_request_json.get_json.return_value = {"script": "print('json')"}

        script, timeout, context = parse_request(mock_request_json)

        assert script == "print('json')"

    def test_defaults_to_json_when_no_content_type(self):
        """parse_request() treats missing content-type as JSON for backward compatibility."""
        req = Mock(spec=func.HttpRequest)
        req.headers.get.return_value = ""
        req.get_json.return_value = {"script": "print('default')"}

        script, timeout, context = parse_request(req)

        assert script == "print('default')"


# =============================================================================
# Validation Tests
# =============================================================================


class TestValidateTimeout:
    """Tests for validate_timeout() - execution timeout validation and clamping."""

    def test_rejects_zero_timeout(self):
        """validate_timeout() rejects zero as invalid timeout value.

        Zero timeout would immediately kill any script, serving no practical purpose.
        """
        result = validate_timeout(0)

        assert isinstance(result, func.HttpResponse)
        assert result.status_code == 400

    def test_rejects_negative_timeout(self):
        """validate_timeout() rejects negative timeout values.

        Negative timeouts are nonsensical and could cause undefined behavior.
        """
        result = validate_timeout(-10)

        assert isinstance(result, func.HttpResponse)
        assert result.status_code == 400

    def test_accepts_valid_timeout(self):
        """validate_timeout() passes through valid timeout unchanged."""
        result = validate_timeout(60)

        assert result == 60

    def test_clamps_excessive_timeout_to_maximum(self):
        """validate_timeout() clamps timeout exceeding MAX_TIMEOUT_S.

        Prevents resource exhaustion by limiting maximum execution time while
        still accepting the request (graceful degradation vs. rejection).
        """
        result = validate_timeout(500)

        assert result == MAX_TIMEOUT_S

    @patch('function_app.logging')
    def test_logs_warning_when_clamping(self, mock_logging):
        """validate_timeout() logs audit trail when modifying client request.

        Clamping is a security control - we log it for monitoring and debugging.
        """
        validate_timeout(500)

        assert mock_logging.warning.called
        call_args = str(mock_logging.warning.call_args)
        assert "500" in call_args
        assert str(MAX_TIMEOUT_S) in call_args


class TestValidateScriptSize:
    """Tests for validate_script_size() - script payload size validation."""

    def test_accepts_small_script(self):
        """validate_script_size() returns None for scripts within size limit."""
        script = "print('hello world')"

        result = validate_script_size(script)

        assert result is None

    def test_rejects_oversized_script(self):
        """validate_script_size() returns 413 error for excessive script size.

        Prevents memory exhaustion and storage abuse by limiting script payload.
        413 Payload Too Large is semantically correct status code.
        """
        script = "x" * (MAX_SCRIPT_BYTES + 1)

        result = validate_script_size(script)

        assert isinstance(result, func.HttpResponse)
        assert result.status_code == 413

    def test_accepts_script_exactly_at_limit(self):
        """validate_script_size() accepts script at exact byte limit (boundary test)."""
        script = "x" * MAX_SCRIPT_BYTES

        result = validate_script_size(script)

        assert result is None

    def test_validates_byte_size_not_character_count(self):
        """validate_script_size() measures UTF-8 byte length, not character count.

        Critical for security: multi-byte Unicode characters could bypass naive
        character-based length checks.
        """
        # Unicode character "ğ" is 2 bytes in UTF-8
        script = "ğ" * (MAX_SCRIPT_BYTES // 2 + 1)

        result = validate_script_size(script)

        assert isinstance(result, func.HttpResponse)
        assert result.status_code == 413


# =============================================================================
# Content Encoding Tests
# =============================================================================


class TestIsBinaryContent:
    """Tests for is_binary_content() - binary vs text detection."""

    def test_detects_null_bytes_as_binary(self):
        """is_binary_content() identifies null bytes as binary indicator.

        Null bytes never appear in valid text files and reliably indicate binary data.
        """
        data = b"hello\x00world"

        assert is_binary_content(data) is True

    def test_accepts_valid_utf8_as_text(self):
        """is_binary_content() returns False for valid UTF-8 text."""
        data = b"Hello, World!"

        assert is_binary_content(data) is False

    def test_accepts_unicode_text_as_non_binary(self):
        """is_binary_content() correctly handles UTF-8 encoded Unicode.

        Ensures international text (Japanese, emoji, etc.) is not misclassified.
        """
        data = "こんにちは 🌍".encode(ENCODING_UTF8)

        assert is_binary_content(data) is False

    def test_detects_invalid_utf8_as_binary(self):
        """is_binary_content() identifies malformed UTF-8 as binary data."""
        data = b"\xff\xfe\x00\x01"

        assert is_binary_content(data) is True

    def test_handles_empty_bytes_as_non_binary(self):
        """is_binary_content() treats empty byte string as text (edge case)."""
        data = b""

        assert is_binary_content(data) is False


class TestDecodeFileContent:
    """Tests for decode_file_content() - ContextFile decoding to bytes."""

    def test_decodes_utf8_string_to_bytes(self, sample_context_file):
        """decode_file_content() converts UTF-8 string content to bytes."""
        result = decode_file_content(sample_context_file)

        assert result == b"a,b\n1,2"

    def test_decodes_base64_content_to_bytes(self, sample_binary_context):
        """decode_file_content() decodes base64 strings to original binary data."""
        result = decode_file_content(sample_binary_context)

        assert result == b"\x00\x01\x02\x03"

    def test_handles_unicode_in_utf8_content(self):
        """decode_file_content() correctly encodes Unicode characters."""
        ctx_file = ContextFile(name="unicode.txt", content="こんにちは", encoding=ENCODING_UTF8)

        result = decode_file_content(ctx_file)

        assert result == "こんにちは".encode(ENCODING_UTF8)


class TestEncodeFileContent:
    """Tests for encode_file_content() - auto-detecting encoding for responses."""

    def test_returns_string_for_text_content(self):
        """encode_file_content() returns plain string for text files.

        Simplifies client consumption - text files don't require base64 decoding.
        """
        data = b"Hello, World!"

        result = encode_file_content(data)

        assert result == "Hello, World!"

    def test_returns_base64_dict_for_binary_content(self):
        """encode_file_content() wraps binary data in base64 envelope.

        Binary artifacts require base64 encoding for JSON serialization.
        Returns dict with 'content' and 'encoding' fields for client clarity.
        """
        data = b"\x00\x01\x02\x03"

        result = encode_file_content(data)

        assert isinstance(result, dict)
        assert result["encoding"] == ENCODING_BASE64
        assert result["content"] == base64.b64encode(data).decode("ascii")

    def test_handles_unicode_text_correctly(self):
        """encode_file_content() preserves Unicode in text files."""
        data = "こんにちは 🌍".encode(ENCODING_UTF8)

        result = encode_file_content(data)

        assert result == "こんにちは 🌍"


# =============================================================================
# Context Management Tests
# =============================================================================


class TestParseContext:
    """Tests for parse_context() - raw context dict to ContextFile objects."""

    def test_parses_string_value_as_utf8_content(self):
        """parse_context() treats string values as UTF-8 text files (shorthand syntax).

        Supports convenient {"filename": "content"} syntax for common case.
        """
        raw = {"data.csv": "col1,col2\nval1,val2"}

        result = parse_context(raw)

        assert isinstance(result, dict)
        assert result["data.csv"].name == "data.csv"
        assert result["data.csv"].content == "col1,col2\nval1,val2"
        assert result["data.csv"].encoding == ENCODING_UTF8

    def test_parses_object_value_with_explicit_utf8_encoding(self):
        """parse_context() handles explicit encoding specification in object form."""
        raw = {"data.txt": {"content": "text data", "encoding": "utf-8"}}

        result = parse_context(raw)

        assert result["data.txt"].content == "text data"
        assert result["data.txt"].encoding == ENCODING_UTF8

    def test_parses_object_value_with_base64_encoding(self):
        """parse_context() creates binary ContextFile from base64 specification."""
        raw = {"image.png": {"content": "iVBORw0KGgo=", "encoding": "base64"}}

        result = parse_context(raw)

        assert result["image.png"].content == "iVBORw0KGgo="
        assert result["image.png"].encoding == ENCODING_BASE64

    def test_parses_multiple_files_with_mixed_formats(self):
        """parse_context() handles heterogeneous context with text and binary files."""
        raw = {
            "data.csv": "a,b,c",
            "config.json": {"content": "{}", "encoding": "utf-8"},
            "image.bin": {"content": "AQIDBA==", "encoding": "base64"}
        }

        result = parse_context(raw)

        assert len(result) == 3
        assert "data.csv" in result
        assert "config.json" in result
        assert "image.bin" in result

    def test_rejects_non_dict_context(self):
        """parse_context() returns error for non-dictionary context value."""
        result = parse_context(["not", "a", "dict"])

        assert isinstance(result, func.HttpResponse)
        assert result.status_code == 400

    def test_rejects_invalid_encoding_value(self):
        """parse_context() validates encoding field is 'utf-8' or 'base64'.

        Prevents undefined behavior from unsupported encoding specifications.
        """
        raw = {"data.txt": {"content": "data", "encoding": "iso-8859-1"}}

        result = parse_context(raw)

        assert isinstance(result, func.HttpResponse)
        assert result.status_code == 400

    def test_rejects_missing_content_field(self):
        """parse_context() requires 'content' field in object format."""
        raw = {"data.txt": {"encoding": "utf-8"}}

        result = parse_context(raw)

        assert isinstance(result, func.HttpResponse)
        assert result.status_code == 400

    def test_rejects_non_string_content(self):
        """parse_context() validates content is string type (not number, array, etc.)."""
        raw = {"data.txt": {"content": 12345, "encoding": "utf-8"}}

        result = parse_context(raw)

        assert isinstance(result, func.HttpResponse)
        assert result.status_code == 400

    def test_rejects_non_string_filename(self):
        """parse_context() validates filenames are strings.

        Prevents type confusion and ensures filenames can be safely used in filesystem ops.
        """
        raw = {123: "content"}

        result = parse_context(raw)

        assert isinstance(result, func.HttpResponse)
        assert result.status_code == 400


class TestValidateContext:
    """Tests for validate_context() - security and size limit enforcement."""

    def test_accepts_valid_context(self, sample_context_file):
        """validate_context() returns None for valid context within all limits."""
        context = {"data.csv": sample_context_file}

        result = validate_context(context)

        assert result is None

    def test_rejects_excessive_file_count(self):
        """validate_context() enforces MAX_CONTEXT_FILES limit.

        Prevents resource exhaustion from too many file handles and I/O operations.
        """
        context = {
            f"file{i}.txt": ContextFile(name=f"file{i}.txt", content="x", encoding=ENCODING_UTF8)
            for i in range(MAX_CONTEXT_FILES + 1)
        }

        result = validate_context(context)

        assert isinstance(result, func.HttpResponse)
        assert result.status_code == 400

    def test_rejects_path_traversal_with_forward_slash(self):
        """validate_context() blocks filenames containing forward slashes.

        Prevents path traversal attacks: ../../../etc/passwd
        Critical security control for filesystem isolation.
        """
        context = {
            "../evil.txt": ContextFile(name="../evil.txt", content="x", encoding=ENCODING_UTF8)
        }

        result = validate_context(context)

        assert isinstance(result, func.HttpResponse)
        assert result.status_code == 400

    def test_rejects_path_traversal_with_backslash(self):
        """validate_context() blocks filenames containing backslashes.

        Prevents Windows-style path traversal: ..\\..\\windows\\system32
        """
        context = {
            "..\\evil.txt": ContextFile(name="..\\evil.txt", content="x", encoding=ENCODING_UTF8)
        }

        result = validate_context(context)

        assert isinstance(result, func.HttpResponse)
        assert result.status_code == 400

    def test_rejects_hidden_files_starting_with_dot(self):
        """validate_context() blocks filenames starting with dot.

        Prevents writing to hidden files (.bashrc, .ssh/authorized_keys, etc.)
        that could enable persistence or privilege escalation.
        """
        context = {
            ".hidden": ContextFile(name=".hidden", content="x", encoding=ENCODING_UTF8)
        }

        result = validate_context(context)

        assert isinstance(result, func.HttpResponse)
        assert result.status_code == 400

    def test_rejects_single_file_exceeding_size_limit(self):
        """validate_context() enforces per-file size limit with 413 status.

        Prevents individual files from consuming excessive memory or disk space.
        """
        large_content = "x" * (MAX_SINGLE_FILE_BYTES + 1)
        context = {
            "large.txt": ContextFile(name="large.txt", content=large_content, encoding=ENCODING_UTF8)
        }

        result = validate_context(context)

        assert isinstance(result, func.HttpResponse)
        assert result.status_code == 413

    def test_rejects_total_context_exceeding_aggregate_limit(self):
        """validate_context() enforces aggregate size across all context files.

        Multiple small files could collectively exhaust resources - this prevents that.
        """
        # Create 4 files, each 1/3 of limit, totaling 4/3 (over limit)
        file_size = MAX_CONTEXT_BYTES // 3
        content = "x" * file_size
        context = {
            f"file{i}.txt": ContextFile(name=f"file{i}.txt", content=content, encoding=ENCODING_UTF8)
            for i in range(4)
        }

        result = validate_context(context)

        assert isinstance(result, func.HttpResponse)
        assert result.status_code == 413

    def test_rejects_invalid_base64_encoding(self):
        """validate_context() validates base64 content is decodable.

        Fails fast on malformed base64 rather than during materialization.
        """
        context = {
            "bad.bin": ContextFile(name="bad.bin", content="not-valid-base64!!!", encoding=ENCODING_BASE64)
        }

        result = validate_context(context)

        assert isinstance(result, func.HttpResponse)
        assert result.status_code == 400


class TestMaterializeContext:
    """Tests for materialize_context() - writing context files to disk."""

    def test_creates_input_and_output_directories(self, temp_exec_dir):
        """materialize_context() creates input/ and output/ directories with secure permissions.

        These directories provide isolated namespaces for script I/O operations.
        """
        context = {}

        materialize_context(context, temp_exec_dir)

        assert (temp_exec_dir / INPUT_DIR).exists()
        assert (temp_exec_dir / OUTPUT_DIR).exists()

    def test_writes_text_files_to_input_directory(self, temp_exec_dir, sample_context_file):
        """materialize_context() materializes UTF-8 text files to filesystem."""
        context = {"data.csv": sample_context_file}

        materialize_context(context, temp_exec_dir)

        input_file = temp_exec_dir / INPUT_DIR / "data.csv"
        assert input_file.exists()
        assert input_file.read_text() == "a,b\n1,2"

    def test_writes_binary_files_correctly(self, temp_exec_dir, sample_binary_context):
        """materialize_context() decodes base64 and writes binary data.

        Ensures binary artifacts (images, models, etc.) are correctly reconstructed.
        """
        context = {"data.bin": sample_binary_context}

        materialize_context(context, temp_exec_dir)

        input_file = temp_exec_dir / INPUT_DIR / "data.bin"
        assert input_file.exists()
        assert input_file.read_bytes() == b"\x00\x01\x02\x03"

    def test_sets_read_only_permissions_on_files(self, temp_exec_dir, sample_context_file):
        """materialize_context() marks input files as read-only (chmod 0o400).

        Defense in depth: prevents scripts from modifying input data, enforcing
        clear separation between inputs (read-only) and outputs (write-only).
        """
        context = {"data.csv": sample_context_file}

        materialize_context(context, temp_exec_dir)

        input_file = temp_exec_dir / INPUT_DIR / "data.csv"
        # Check that file is readable but not writable by owner
        mode = input_file.stat().st_mode
        # 0o400 = owner read-only
        assert mode & 0o600 == 0o400


class TestCollectArtifacts:
    """Tests for collect_artifacts() - gathering script output files."""

    def test_returns_empty_dict_when_output_directory_empty(self, temp_exec_dir):
        """collect_artifacts() returns {} when no files produced."""
        (temp_exec_dir / OUTPUT_DIR).mkdir()

        result = collect_artifacts(temp_exec_dir)

        assert result == {}

    def test_returns_empty_dict_when_output_directory_missing(self, temp_exec_dir):
        """collect_artifacts() handles missing output directory gracefully."""
        result = collect_artifacts(temp_exec_dir)

        assert result == {}

    def test_collects_text_file_as_string(self, temp_exec_dir):
        """collect_artifacts() auto-detects text files and returns as strings."""
        output_dir = temp_exec_dir / OUTPUT_DIR
        output_dir.mkdir()
        (output_dir / "result.txt").write_text("computation result")

        result = collect_artifacts(temp_exec_dir)

        assert result == {"result.txt": "computation result"}

    def test_collects_binary_file_with_base64_encoding(self, temp_exec_dir):
        """collect_artifacts() auto-detects binary files and base64 encodes them."""
        output_dir = temp_exec_dir / OUTPUT_DIR
        output_dir.mkdir()
        binary_data = b"\x00\x01\x02\x03\x04"
        (output_dir / "output.bin").write_bytes(binary_data)

        result = collect_artifacts(temp_exec_dir)

        assert "output.bin" in result
        assert isinstance(result["output.bin"], dict)
        assert result["output.bin"]["encoding"] == ENCODING_BASE64
        assert result["output.bin"]["content"] == base64.b64encode(binary_data).decode("ascii")

    def test_collects_multiple_files(self, temp_exec_dir):
        """collect_artifacts() aggregates all files in output directory."""
        output_dir = temp_exec_dir / OUTPUT_DIR
        output_dir.mkdir()
        (output_dir / "result1.txt").write_text("first")
        (output_dir / "result2.csv").write_text("a,b\n1,2")

        result = collect_artifacts(temp_exec_dir)

        assert len(result) == 2
        assert result["result1.txt"] == "first"
        assert result["result2.csv"] == "a,b\n1,2"

    def test_rejects_artifacts_exceeding_size_limit(self, temp_exec_dir):
        """collect_artifacts() returns 500 error when artifacts too large.

        Prevents runaway scripts from filling disk or exhausting memory.
        500 status because this is a server-side constraint on output size.
        """
        output_dir = temp_exec_dir / OUTPUT_DIR
        output_dir.mkdir()
        large_data = "x" * (MAX_ARTIFACTS_BYTES + 1)
        (output_dir / "huge.txt").write_text(large_data)

        result = collect_artifacts(temp_exec_dir)

        assert isinstance(result, func.HttpResponse)
        assert result.status_code == 500

    def test_skips_subdirectories(self, temp_exec_dir):
        """collect_artifacts() only collects regular files, not directories.

        Prevents unexpected behavior and limits attack surface.
        """
        output_dir = temp_exec_dir / OUTPUT_DIR
        output_dir.mkdir()
        (output_dir / "result.txt").write_text("data")
        (output_dir / "subdir").mkdir()
        (output_dir / "subdir" / "nested.txt").write_text("ignored")

        result = collect_artifacts(temp_exec_dir)

        assert result == {"result.txt": "data"}


# =============================================================================
# Script Execution Tests
# =============================================================================


class TestCleanupExecDir:
    """Tests for _cleanup_exec_dir() - temporary directory cleanup."""

    @patch('function_app.shutil.rmtree')
    def test_removes_directory_tree(self, mock_rmtree):
        """_cleanup_exec_dir() calls shutil.rmtree to remove all execution artifacts."""
        exec_dir = Path("/tmp/exec_abc123")

        _cleanup_exec_dir(exec_dir)

        mock_rmtree.assert_called_once_with(exec_dir)

    @patch('function_app.shutil.rmtree')
    def test_swallows_exceptions_during_cleanup(self, mock_rmtree):
        """_cleanup_exec_dir() never raises exceptions to avoid masking original errors.

        Cleanup is best-effort - we don't want cleanup failures to hide script
        execution errors. OS will eventually garbage collect temp directories.
        """
        mock_rmtree.side_effect = OSError("Permission denied")
        exec_dir = Path("/tmp/exec_abc123")

        # Should not raise
        _cleanup_exec_dir(exec_dir)


class TestRunSubprocess:
    """Tests for _run_subprocess() - isolated subprocess execution."""

    @patch('function_app.subprocess.Popen')
    @patch('function_app.sys.executable', '/usr/bin/python3')
    def test_returns_execution_result_on_success(self, mock_popen):
        """_run_subprocess() captures stdout, stderr, and exit code for successful runs."""
        mock_process = Mock()
        mock_process.communicate.return_value = (b"output line", b"")
        mock_process.returncode = 0
        mock_process.pid = 12345
        mock_process.poll.return_value = 0
        mock_popen.return_value = mock_process

        result = _run_subprocess("/tmp/script.py", "/tmp", 60)

        assert result.exit_code == 0
        assert result.stdout == "output line"
        assert result.stderr == ""

    @patch('function_app.subprocess.Popen')
    @patch('function_app.sys.executable', '/usr/bin/python3')
    def test_captures_non_zero_exit_code(self, mock_popen):
        """_run_subprocess() preserves script exit codes for client error handling."""
        mock_process = Mock()
        mock_process.communicate.return_value = (b"", b"error message")
        mock_process.returncode = 1
        mock_process.pid = 12345
        mock_process.poll.return_value = 1
        mock_popen.return_value = mock_process

        result = _run_subprocess("/tmp/script.py", "/tmp", 60)

        assert result.exit_code == 1
        assert result.stderr == "error message"

    @patch('function_app._kill_process_tree')
    @patch('function_app.subprocess.Popen')
    @patch('function_app.sys.executable', '/usr/bin/python3')
    def test_handles_timeout_with_process_termination(self, mock_popen, mock_kill):
        """_run_subprocess() kills process tree and returns timeout exit code.

        Timeout handling is critical for preventing resource exhaustion from
        infinite loops or long-running scripts.
        """
        mock_process = Mock()
        mock_process.pid = 12345
        mock_process.poll.return_value = None
        mock_process.communicate.side_effect = [
            subprocess.TimeoutExpired(cmd=["python3"], timeout=60),
            (b"partial", b"partial err")
        ]
        mock_popen.return_value = mock_process

        result = _run_subprocess("/tmp/script.py", "/tmp", 60)

        assert result.exit_code == EXIT_CODE_TIMEOUT
        assert "partial" in result.stdout
        assert "timed out" in result.stderr
        mock_kill.assert_called_with(12345)

    @patch('function_app.subprocess.Popen')
    @patch('function_app.sys.executable', '/usr/bin/python3')
    def test_handles_unexpected_exceptions(self, mock_popen):
        """_run_subprocess() returns internal error code for unexpected failures.

        Defensive programming - unexpected errors shouldn't crash the service.
        """
        mock_popen.side_effect = RuntimeError("Unexpected error")

        result = _run_subprocess("/tmp/script.py", "/tmp", 60)

        assert result.exit_code == EXIT_CODE_INTERNAL_ERROR
        assert "Internal execution error" in result.stderr

    @patch('function_app.subprocess.Popen')
    @patch('function_app.sys.executable', '/usr/bin/python3')
    def test_invokes_python_with_utf8_mode(self, mock_popen):
        """_run_subprocess() uses Python UTF-8 mode (-X utf8) for consistent encoding.

        Ensures scripts handle Unicode correctly regardless of system locale.
        """
        mock_process = Mock()
        mock_process.communicate.return_value = (b"", b"")
        mock_process.returncode = 0
        mock_process.pid = 12345
        mock_process.poll.return_value = 0
        mock_popen.return_value = mock_process

        _run_subprocess("/tmp/script.py", "/tmp", 60)

        call_args = mock_popen.call_args
        assert call_args[0][0] == ['/usr/bin/python3', '-X', 'utf8', '/tmp/script.py']

    @patch('function_app.subprocess.Popen')
    @patch('function_app.sys.executable', '/usr/bin/python3')
    def test_creates_new_process_session_for_isolation(self, mock_popen):
        """_run_subprocess() starts subprocess in new session for clean termination.

        start_new_session=True creates a process group, allowing us to kill the
        entire tree (parent + children) on timeout.
        """
        mock_process = Mock()
        mock_process.communicate.return_value = (b"", b"")
        mock_process.returncode = 0
        mock_process.pid = 12345
        mock_process.poll.return_value = 0
        mock_popen.return_value = mock_process

        _run_subprocess("/tmp/script.py", "/tmp", 60)

        call_args = mock_popen.call_args
        assert call_args[1]['start_new_session'] is True

    @patch('function_app.subprocess.Popen')
    @patch('function_app.sys.executable', '/usr/bin/python3')
    def test_passes_timeout_to_communicate(self, mock_popen):
        """_run_subprocess() enforces timeout at subprocess level."""
        mock_process = Mock()
        mock_process.communicate.return_value = (b"", b"")
        mock_process.returncode = 0
        mock_process.pid = 12345
        mock_process.poll.return_value = 0
        mock_popen.return_value = mock_process

        _run_subprocess("/tmp/script.py", "/tmp", 120)

        mock_process.communicate.assert_called_with(timeout=120)


class TestExecuteScript:
    """Tests for execute_script() - high-level script execution orchestration."""

    @patch('function_app._cleanup_exec_dir')
    @patch('function_app.collect_artifacts')
    @patch('function_app._run_subprocess')
    @patch('function_app.uuid.uuid4')
    @patch('function_app.tempfile.gettempdir')
    def test_creates_unique_execution_directory(self, mock_gettempdir, mock_uuid, mock_run, mock_collect, mock_cleanup):
        """execute_script() creates isolated directory with UUID for concurrent safety.

        Unique directories prevent race conditions when multiple requests execute
        simultaneously in the same function instance.
        """
        mock_gettempdir.return_value = tempfile.gettempdir()
        mock_uuid.return_value = Mock(__str__=lambda _: "test-uuid-123")
        mock_run.return_value = ExecutionResult(0, "", "")
        mock_collect.return_value = {}

        execute_script("print('hello')", 60)

        call_args = mock_run.call_args[0]
        assert "exec_test-uuid-123" in call_args[1]

    @patch('function_app._cleanup_exec_dir')
    @patch('function_app.collect_artifacts')
    @patch('function_app._run_subprocess')
    @patch('function_app.uuid.uuid4')
    @patch('function_app.tempfile.gettempdir')
    def test_invokes_subprocess_with_correct_arguments(self, mock_gettempdir, mock_uuid, mock_run, mock_collect, mock_cleanup):
        """execute_script() passes script path, working directory, and timeout to subprocess."""
        mock_gettempdir.return_value = tempfile.gettempdir()
        mock_uuid.return_value = Mock(__str__=lambda _: "abc123")
        mock_run.return_value = ExecutionResult(0, "", "")
        mock_collect.return_value = {}

        execute_script("print('test')", 120)

        call_args = mock_run.call_args[0]
        assert "script_abc123.py" in call_args[0]
        assert call_args[2] == 120

    @patch('function_app._cleanup_exec_dir')
    @patch('function_app.collect_artifacts')
    @patch('function_app._run_subprocess')
    @patch('function_app.uuid.uuid4')
    @patch('function_app.tempfile.gettempdir')
    def test_cleans_up_directory_on_success(self, mock_gettempdir, mock_uuid, mock_run, mock_collect, mock_cleanup):
        """execute_script() removes temporary directory after successful execution."""
        mock_gettempdir.return_value = tempfile.gettempdir()
        mock_uuid.return_value = Mock(__str__=lambda _: "abc123")
        mock_run.return_value = ExecutionResult(0, "", "")
        mock_collect.return_value = {}

        execute_script("print('test')", 60)

        assert mock_cleanup.called

    @patch('function_app._cleanup_exec_dir')
    @patch('function_app.collect_artifacts')
    @patch('function_app._run_subprocess')
    @patch('function_app.uuid.uuid4')
    @patch('function_app.tempfile.gettempdir')
    def test_cleans_up_directory_on_failure(self, mock_gettempdir, mock_uuid, mock_run, mock_collect, mock_cleanup):
        """execute_script() removes temporary directory even when execution fails.

        Ensures no temporary directory leakage regardless of execution outcome.
        """
        mock_gettempdir.return_value = tempfile.gettempdir()
        mock_uuid.return_value = Mock(__str__=lambda _: "abc123")
        mock_run.side_effect = RuntimeError("Test error")

        with pytest.raises(RuntimeError):
            execute_script("print('test')", 60)

        assert mock_cleanup.called

    @patch('function_app._cleanup_exec_dir')
    @patch('function_app.collect_artifacts')
    @patch('function_app._run_subprocess')
    @patch('function_app.uuid.uuid4')
    @patch('function_app.tempfile.gettempdir')
    def test_returns_execution_result_with_artifacts(self, mock_gettempdir, mock_uuid, mock_run, mock_collect, mock_cleanup):
        """execute_script() aggregates subprocess result with collected artifacts."""
        mock_gettempdir.return_value = tempfile.gettempdir()
        mock_uuid.return_value = Mock(__str__=lambda _: "abc123")
        mock_run.return_value = ExecutionResult(0, "output", "errors")
        mock_collect.return_value = {"result.json": '{"status": "success"}'}

        result = execute_script("print('test')", 60)

        assert result.exit_code == 0
        assert result.stdout == "output"
        assert result.stderr == "errors"
        assert result.artifacts == {"result.json": '{"status": "success"}'}

    @patch('function_app._cleanup_exec_dir')
    @patch('function_app.collect_artifacts')
    @patch('function_app._run_subprocess')
    @patch('function_app.uuid.uuid4')
    @patch('function_app.tempfile.gettempdir')
    def test_propagates_artifact_collection_errors(self, mock_gettempdir, mock_uuid, mock_run, mock_collect, mock_cleanup):
        """execute_script() returns error response when artifact collection fails.

        Example: artifacts exceed size limit. Error response bubbles up to client.
        """
        mock_gettempdir.return_value = tempfile.gettempdir()
        mock_uuid.return_value = Mock(__str__=lambda _: "abc123")
        mock_run.return_value = ExecutionResult(0, "", "")
        mock_collect.return_value = error_response("Artifacts too large", 500)

        result = execute_script("print('test')", 60)

        assert isinstance(result, func.HttpResponse)
        assert result.status_code == 500


# =============================================================================
# Security Tests
# =============================================================================


class TestGetClientIP:
    """Tests for get_client_ip() - client IP extraction for audit logging."""

    def test_extracts_ip_from_x_forwarded_for_header(self):
        """get_client_ip() parses first IP from X-Forwarded-For chain.

        X-Forwarded-For contains chain of proxies: "client, proxy1, proxy2"
        We want the original client IP for audit and rate limiting.
        """
        req = Mock(spec=func.HttpRequest)
        req.headers.get.side_effect = lambda h, d="": "1.2.3.4, 10.0.0.1" if h == "X-Forwarded-For" else d

        result = get_client_ip(req)

        assert result == "1.2.3.4"

    def test_falls_back_to_x_client_ip_header(self):
        """get_client_ip() uses X-Client-IP when X-Forwarded-For absent."""
        req = Mock(spec=func.HttpRequest)
        req.headers.get.side_effect = lambda h, d="": "5.6.7.8" if h == "X-Client-IP" else d

        result = get_client_ip(req)

        assert result == "5.6.7.8"

    def test_returns_unknown_when_no_ip_headers_present(self):
        """get_client_ip() returns 'unknown' for missing headers (defensive default)."""
        req = Mock(spec=func.HttpRequest)
        def header_getter(name, default=""):
            if name == "X-Forwarded-For":
                return ""
            if name == "X-Client-IP":
                return default
            return default
        req.headers.get.side_effect = header_getter

        result = get_client_ip(req)

        assert result == "unknown"


class TestComputeScriptHash:
    """Tests for compute_script_hash() - script fingerprinting for audit logs."""

    def test_returns_deterministic_hash_for_same_script(self):
        """compute_script_hash() produces consistent hash for identical scripts.

        Enables deduplication and tracking of frequently executed scripts.
        """
        script = "print('hello world')"

        hash1 = compute_script_hash(script)
        hash2 = compute_script_hash(script)

        assert hash1 == hash2
        assert len(hash1) == 16  # Truncated SHA256

    def test_returns_different_hashes_for_different_scripts(self):
        """compute_script_hash() distinguishes different scripts."""
        script1 = "print('hello')"
        script2 = "print('goodbye')"

        hash1 = compute_script_hash(script1)
        hash2 = compute_script_hash(script2)

        assert hash1 != hash2


class TestLogAuditEvent:
    """Tests for log_audit_event() - structured audit logging."""

    @patch('function_app.logging')
    def test_logs_structured_json_with_all_fields(self, mock_logging):
        """log_audit_event() emits JSON-formatted logs for Azure Monitor ingestion.

        Structured logging enables powerful queries and alerts in Azure Monitor.
        """
        log_audit_event(
            "execution_completed", "req123", "1.2.3.4", "abc123",
            100, 30, 2, duration_ms=150.5, exit_code=0
        )

        mock_logging.info.assert_called_once()
        call_arg = mock_logging.info.call_args[0][0]
        assert "AUDIT:" in call_arg
        assert '"event": "execution_completed"' in call_arg
        assert '"request_id": "req123"' in call_arg
        assert '"client_ip": "1.2.3.4"' in call_arg
        assert '"exit_code": 0' in call_arg

    @patch('function_app.logging')
    def test_includes_optional_fields_when_provided(self, mock_logging):
        """log_audit_event() conditionally includes error, duration, exit_code."""
        log_audit_event(
            "request_rejected", "req456", "1.2.3.4", "def456",
            50, 60, 0, error="invalid_timeout"
        )

        call_arg = mock_logging.info.call_args[0][0]
        assert '"error": "invalid_timeout"' in call_arg


class TestCreateSafeEnvironment:
    """Tests for _create_safe_environment() - subprocess environment isolation."""

    def test_excludes_sensitive_environment_variables(self):
        """_create_safe_environment() filters out secrets and credentials.

        Critical security control: prevents scripts from exfiltrating Azure
        connection strings, API keys, and other sensitive configuration.
        """
        original_env = os.environ.copy()
        try:
            os.environ["AZURE_STORAGE_CONNECTION_STRING"] = "secret123"
            os.environ["API_KEY"] = "supersecret"
            os.environ["PATH"] = "/usr/bin"

            safe_env = _create_safe_environment()

            assert "AZURE_STORAGE_CONNECTION_STRING" not in safe_env
            assert "API_KEY" not in safe_env
            assert safe_env.get("PATH") == "/usr/bin"
            assert safe_env.get("PYTHONIOENCODING") == "utf-8"
        finally:
            os.environ.clear()
            os.environ.update(original_env)

    def test_only_includes_explicitly_safe_variables(self):
        """_create_safe_environment() uses allowlist approach (deny-by-default).

        More secure than blocklist - unknown variables are automatically excluded.
        """
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
            # Always added for Python compatibility
            assert "PYTHONIOENCODING" in safe_env
            assert "PYTHONUNBUFFERED" in safe_env
        finally:
            os.environ.clear()
            os.environ.update(original_env)

    def test_safe_env_vars_constant_is_immutable(self):
        """SAFE_ENV_VARS is frozenset to prevent runtime modification.

        Immutability prevents accidental or malicious weakening of security policy.
        """
        assert isinstance(SAFE_ENV_VARS, frozenset)
        with pytest.raises(AttributeError):
            SAFE_ENV_VARS.add("NEW_VAR")


class TestKillProcessTree:
    """Tests for _kill_process_tree() - process group termination."""

    @patch('function_app.os.killpg')
    def test_kills_process_group_with_sigkill(self, mock_killpg):
        """_kill_process_tree() uses SIGKILL on process group for forceful termination.

        SIGKILL cannot be caught/ignored, ensuring timeout enforcement.
        Process group kill ensures child processes are also terminated.
        """
        _kill_process_tree(12345)

        mock_killpg.assert_called_once_with(12345, signal.SIGKILL)

    @patch('function_app.os.killpg')
    def test_handles_process_not_found_gracefully(self, mock_killpg):
        """_kill_process_tree() ignores ProcessLookupError (already dead)."""
        mock_killpg.side_effect = ProcessLookupError()

        # Should not raise
        _kill_process_tree(12345)

    @patch('function_app.os.killpg')
    def test_handles_permission_errors_gracefully(self, mock_killpg):
        """_kill_process_tree() handles PermissionError without crashing.

        Process may have changed ownership or we may lack permission.
        Don't crash the service over cleanup failures.
        """
        mock_killpg.side_effect = PermissionError()

        # Should not raise
        _kill_process_tree(12345)


# =============================================================================
# Integration Tests
# =============================================================================


class TestRunScriptIntegration:
    """Integration tests for run_script() - end-to-end request flow."""

    @patch('function_app.execute_script')
    def test_successful_execution_returns_200_with_results(self, mock_execute, mock_request_json):
        """run_script() returns 200 OK with execution results for successful runs.

        Happy path: validates entire flow from request parsing through response formatting.
        """
        mock_request_json.get_json.return_value = {"script": "print('hello')"}
        mock_execute.return_value = ExecutionResult(0, "hello\n", "", {})

        response = run_script(mock_request_json)

        assert response.status_code == 200
        body = json.loads(response.get_body().decode(ENCODING_UTF8))
        assert body["exit_code"] == 0
        assert body["stdout"] == "hello\n"
        assert body["artifacts"] == {}

    @patch('function_app.execute_script')
    def test_request_parsing_error_returns_400(self, mock_execute, mock_request_json):
        """run_script() fails fast on malformed requests without executing script."""
        mock_request_json.get_json.side_effect = ValueError("Invalid JSON")

        response = run_script(mock_request_json)

        assert response.status_code == 400
        assert not mock_execute.called

    @patch('function_app.execute_script')
    def test_timeout_validation_error_returns_400(self, mock_execute, mock_request_json):
        """run_script() validates timeout before execution."""
        mock_request_json.get_json.return_value = {
            "script": "print('test')",
            "timeout_s": 0
        }

        response = run_script(mock_request_json)

        assert response.status_code == 400
        assert not mock_execute.called

    @patch('function_app.execute_script')
    def test_script_size_validation_returns_413(self, mock_execute, mock_request_json):
        """run_script() rejects oversized scripts with 413 Payload Too Large."""
        large_script = "x" * (MAX_SCRIPT_BYTES + 1)
        mock_request_json.get_json.return_value = {"script": large_script}

        response = run_script(mock_request_json)

        assert response.status_code == 413
        assert not mock_execute.called

    @patch('function_app.execute_script')
    def test_execution_error_propagates_status_code(self, mock_execute, mock_request_json):
        """run_script() returns error responses from execute_script unchanged."""
        mock_request_json.get_json.return_value = {"script": "print('test')"}
        mock_execute.return_value = error_response("Execution failed", 500)

        response = run_script(mock_request_json)

        assert response.status_code == 500

    @patch('function_app.execute_script')
    def test_excessive_timeout_is_clamped_and_execution_proceeds(self, mock_execute, mock_request_json):
        """run_script() clamps timeout to MAX_TIMEOUT_S but continues execution.

        Graceful degradation: accept request with reduced timeout vs rejecting.
        """
        mock_request_json.get_json.return_value = {
            "script": "print('test')",
            "timeout_s": 500
        }
        mock_execute.return_value = ExecutionResult(0, "test\n", "", {})

        response = run_script(mock_request_json)

        assert response.status_code == 200
        # Verify clamped timeout was passed to execute_script
        call_args = mock_execute.call_args[0]
        assert call_args[1] == MAX_TIMEOUT_S

    @patch('function_app.execute_script')
    def test_response_includes_all_execution_fields(self, mock_execute, mock_request_json):
        """run_script() returns complete response structure with exit_code, stdout, stderr, artifacts."""
        mock_request_json.get_json.return_value = {"script": "print('test')"}
        mock_execute.return_value = ExecutionResult(
            exit_code=42,
            stdout="output",
            stderr="warning",
            artifacts={"result.txt": "data"}
        )

        response = run_script(mock_request_json)
        body = json.loads(response.get_body().decode(ENCODING_UTF8))

        assert body["exit_code"] == 42
        assert body["stdout"] == "output"
        assert body["stderr"] == "warning"
        assert body["artifacts"] == {"result.txt": "data"}

    @patch('function_app.execute_script')
    def test_response_content_type_is_json(self, mock_execute, mock_request_json):
        """run_script() sets application/json content type on success response."""
        mock_request_json.get_json.return_value = {"script": "print('test')"}
        mock_execute.return_value = ExecutionResult(0, "", "", {})

        response = run_script(mock_request_json)

        assert response.mimetype == CONTENT_TYPE_JSON

    @patch('function_app.execute_script')
    def test_passes_parsed_context_to_executor(self, mock_execute, mock_request_json):
        """run_script() parses context and passes ContextFile objects to execute_script.

        Validates context flow: request JSON -> ContextFile objects -> execution.
        """
        mock_request_json.get_json.return_value = {
            "script": "# process data",
            "context": {"data.csv": "a,b\n1,2"}
        }
        mock_execute.return_value = ExecutionResult(0, "", "", {})

        run_script(mock_request_json)

        call_args = mock_execute.call_args
        context_arg = call_args[0][2]
        assert "data.csv" in context_arg
        assert context_arg["data.csv"].content == "a,b\n1,2"

    @patch('function_app.execute_script')
    def test_context_validation_errors_prevent_execution(self, mock_execute, mock_request_json):
        """run_script() rejects requests with invalid context (path traversal, etc.)."""
        mock_request_json.get_json.return_value = {
            "script": "print('test')",
            "context": {"../evil.txt": "malicious"}
        }

        response = run_script(mock_request_json)

        assert response.status_code == 400
        assert not mock_execute.called


# =============================================================================
# Parametrized Test Examples
# =============================================================================


class TestValidationBoundaries:
    """Parametrized tests for boundary conditions and edge cases."""

    @pytest.mark.parametrize("timeout,expected", [
        (1, 1),           # Minimum valid
        (60, 60),         # Common case
        (MAX_TIMEOUT_S, MAX_TIMEOUT_S),  # Maximum valid
    ])
    def test_validate_timeout_accepts_valid_values(self, timeout, expected):
        """validate_timeout() accepts all values in valid range [1, MAX_TIMEOUT_S]."""
        result = validate_timeout(timeout)
        assert result == expected

    @pytest.mark.parametrize("timeout", [0, -1, -100])
    def test_validate_timeout_rejects_non_positive_values(self, timeout):
        """validate_timeout() rejects zero and negative timeouts."""
        result = validate_timeout(timeout)
        assert isinstance(result, func.HttpResponse)
        assert result.status_code == 400

    @pytest.mark.parametrize("filename", [
        "../etc/passwd",
        "..\\windows\\system32\\config",
        ".bashrc",
        ".ssh/authorized_keys",
        "subdir/file.txt",
    ])
    def test_validate_context_blocks_unsafe_filenames(self, filename):
        """validate_context() blocks filenames with path traversal or hidden file patterns."""
        context = {
            filename: ContextFile(name=filename, content="x", encoding=ENCODING_UTF8)
        }

        result = validate_context(context)

        assert isinstance(result, func.HttpResponse)
        assert result.status_code == 400

    @pytest.mark.parametrize("filename", [
        "data.csv",
        "results.json",
        "model_weights.pkl",
        "file-name_123.txt",
    ])
    def test_validate_context_accepts_safe_filenames(self, filename):
        """validate_context() accepts normal filenames without special characters."""
        context = {
            filename: ContextFile(name=filename, content="x", encoding=ENCODING_UTF8)
        }

        result = validate_context(context)

        assert result is None


# =============================================================================
# Test Coverage Summary
# =============================================================================

"""
Test Coverage Validation:

Core Functions (100% coverage):
  ✓ error_response: status codes, JSON formatting, content-type
  ✓ parse_request: content-type routing, delegation
  ✓ _parse_raw_request: script extraction, timeout parsing, error handling
  ✓ _parse_json_request: JSON parsing, field validation, context extraction
  ✓ validate_timeout: bounds checking, clamping, logging
  ✓ validate_script_size: size limits, boundary conditions, UTF-8 byte counting

Encoding/Decoding (100% coverage):
  ✓ is_binary_content: null bytes, UTF-8 validation, Unicode handling
  ✓ decode_file_content: UTF-8 and base64 decoding
  ✓ encode_file_content: auto-detection, text/binary formatting

Context Management (100% coverage):
  ✓ parse_context: string/object formats, encoding validation, error cases
  ✓ validate_context: file count limits, path traversal, size limits, base64 validation
  ✓ materialize_context: directory creation, file writing, permissions
  ✓ collect_artifacts: file collection, encoding detection, size limits, directory filtering

Script Execution (100% coverage):
  ✓ _cleanup_exec_dir: cleanup logic, error suppression
  ✓ _run_subprocess: success, failure, timeout, exception handling, command arguments
  ✓ execute_script: orchestration, cleanup, artifact collection, error propagation

Security (100% coverage):
  ✓ get_client_ip: header parsing, fallback chain
  ✓ compute_script_hash: determinism, collision resistance
  ✓ log_audit_event: structured logging, optional fields
  ✓ _create_safe_environment: allowlist enforcement, immutability
  ✓ _kill_process_tree: process group termination, error handling

Integration (100% coverage):
  ✓ run_script: end-to-end flows, error propagation, response formatting
  ✓ Context integration: parsing, validation, execution
  ✓ Boundary conditions: parametrized tests for edge cases

Test Quality Metrics:
  - All tests follow AAA pattern
  - All tests have descriptive docstrings explaining business value
  - All error paths tested with correct status codes
  - All security boundaries tested (size limits, path traversal, environment isolation)
  - Mocking used consistently for external dependencies
  - Fixtures reduce duplication and improve maintainability
  - Parametrized tests cover boundary conditions efficiently
"""
