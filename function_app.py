# Copyright (c) 2025 Microsoft Corporation.
# Licensed under the MIT License. See LICENSE file in the project root.
"""
CodeRunner Azure Function - Entry Point

A serverless endpoint for executing Python scripts in isolated subprocesses.
This is a thin entry point that delegates to src/ modules.

Usage:
    POST /api/run with JSON body: {"script": "...", "timeout_s": 60, "context": {...}}
    POST /api/run with JSON body: {"files": {...}, "entry_point": "main.py"}
    POST /api/run with text/plain body containing Python code

See README.md for full documentation.
"""
import logging
import threading
import time

import azure.functions as func

from src.config import CONTENT_TYPE_JSON, DEFAULT_TIMEOUT_S
from src.models import Result
from src import audit
from src import execution
from src import files as files_module
from src import http
from src import parsing
from src import validation

# Execution lock - ensures sequential processing within a single instance
_execution_lock = threading.Lock()

app = func.FunctionApp()


@app.function_name(name="Health")
@app.route(route="health", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def health(req: func.HttpRequest) -> func.HttpResponse:
    """Health check endpoint for container orchestration."""
    return func.HttpResponse("OK", status_code=200)


@app.function_name(name="RunPythonScript")
@app.route(route="run", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def run_script(req: func.HttpRequest) -> func.HttpResponse:
    """
    Execute Python code and return results.

    Supports two modes:
    - Legacy: script + optional context/dependencies
    - Files: files + entry_point + optional dependencies
    """
    request_id = audit.generate_request_id()
    client_ip = http.get_client_ip(req)
    logging.info(f"[{request_id}] Received script execution request from {client_ip}")

    # Parse request based on content type
    content_type = req.headers.get("content-type", "")

    if CONTENT_TYPE_JSON in content_type:
        try:
            body = req.get_json()
        except ValueError:
            return http.error_response("Invalid JSON in request body.")

        # Detect mode: files or legacy (mutually exclusive)
        has_files = "files" in body
        has_script = "script" in body

        if has_files and has_script:
            return http.error_response(
                "Cannot use both 'files' and 'script' in the same request."
            )

        if has_files:
            return _handle_files_mode(body, request_id, client_ip)
        else:
            return _handle_legacy_mode(body, request_id, client_ip)
    else:
        # Raw text mode - script in body
        return _handle_raw_mode(req, request_id, client_ip)


def _handle_raw_mode(
    req: func.HttpRequest,
    request_id: str,
    client_ip: str,
) -> func.HttpResponse:
    """Handle raw text mode - script in body, timeout in query param."""
    try:
        script = req.get_body().decode("utf-8")
    except UnicodeDecodeError:
        return http.error_response("Request body must be valid UTF-8 text.")

    if not script.strip():
        return http.error_response("Script cannot be empty.")

    timeout_param = req.params.get("timeout_s")
    if timeout_param is None:
        timeout_s = DEFAULT_TIMEOUT_S
    else:
        try:
            timeout_s = int(timeout_param)
        except ValueError:
            return http.error_response("`timeout_s` query parameter must be integer.")

    # Create legacy request and process
    body = {"script": script, "timeout_s": timeout_s}
    return _handle_legacy_mode(body, request_id, client_ip)


def _handle_legacy_mode(
    body: dict,
    request_id: str,
    client_ip: str,
) -> func.HttpResponse:
    """Handle legacy mode: script + context + dependencies."""
    # Parse request
    parse_result = parsing.parse_legacy_request(body)
    if parse_result.is_failure:
        return http.error_response(parse_result.error)

    req = parse_result.value

    # Validate timeout
    timeout_result = validation.validate_timeout(req.timeout_s)
    if timeout_result.is_failure:
        return http.error_response(timeout_result.error)
    validated_timeout = timeout_result.value

    # Validate script size
    size_result = validation.validate_script_size(req.script)
    if size_result.is_failure:
        return http.error_response(size_result.error, status_code=413)

    # Parse dependencies
    deps_result = parsing.parse_dependencies(req.raw_deps)
    if deps_result.is_failure:
        return http.error_response(deps_result.error)
    dependencies = deps_result.value
    dep_strings = [str(d) for d in dependencies]

    # Parse context
    context_result = parsing.parse_context(req.raw_context)
    if context_result.is_failure:
        return http.error_response(context_result.error)
    context = context_result.value

    # Validate context
    def get_context_size(cf):
        return len(files_module.decode_context_file(cf))

    context_validation = validation.validate_context_files(context, get_context_size)
    if context_validation.is_failure:
        return http.error_response(context_validation.error)

    # Create audit context
    audit_ctx = audit.create_audit_context(
        client_ip=client_ip,
        script=req.script,
        timeout_s=validated_timeout,
        context_files=len(context),
        dependencies=dep_strings,
    )
    audit_ctx._request_id = request_id  # Use the existing request ID

    # Execute with lock
    with _execution_lock:
        audit_ctx.log_started()
        start_time = time.time()

        result = execution.execute_script(
            script=req.script,
            timeout_s=validated_timeout,
            context=context,
            dependencies=dependencies,
        )

        duration_ms = (time.time() - start_time) * 1000

        # Check for setup errors
        if isinstance(result, Result):
            audit_ctx.log_failed(result.error)
            return http.error_response(result.error, status_code=500)

        audit_ctx.log_completed(result.exit_code, duration_ms)
        return http.success_response(result)


def _handle_files_mode(
    body: dict,
    request_id: str,
    client_ip: str,
) -> func.HttpResponse:
    """Handle files mode: files + entry_point + dependencies."""
    # Parse request
    parse_result = parsing.parse_files_request(body)
    if parse_result.is_failure:
        return http.error_response(parse_result.error)

    req = parse_result.value

    # Parse files
    files_result = parsing.parse_files(req.files)
    if files_result.is_failure:
        return http.error_response(files_result.error)
    parsed_files = files_result.value

    # Validate timeout
    timeout_result = validation.validate_timeout(req.timeout_s)
    if timeout_result.is_failure:
        return http.error_response(timeout_result.error)
    validated_timeout = timeout_result.value

    # Validate entry point
    entry_point_result = validation.validate_entry_point(
        req.entry_point, set(parsed_files.keys())
    )
    if entry_point_result.is_failure:
        return http.error_response(entry_point_result.error)

    # Validate files collection
    def get_file_size(fe):
        return len(files_module.decode_file_entry(fe))

    files_validation = validation.validate_files_api(parsed_files, get_file_size)
    if files_validation.is_failure:
        return http.error_response(files_validation.error)

    # Parse dependencies
    deps_result = parsing.parse_dependencies(req.raw_deps)
    if deps_result.is_failure:
        return http.error_response(deps_result.error)
    dependencies = deps_result.value
    dep_strings = [str(d) for d in dependencies]

    # Create audit context (use entry point content as "script" for hash)
    entry_content = parsed_files[req.entry_point].content
    audit_ctx = audit.create_audit_context(
        client_ip=client_ip,
        script=entry_content,
        timeout_s=validated_timeout,
        context_files=len(parsed_files),
        dependencies=dep_strings,
    )
    audit_ctx._request_id = request_id

    # Execute with lock
    with _execution_lock:
        audit_ctx.log_started()
        start_time = time.time()

        result = execution.execute_files(
            files=parsed_files,
            entry_point=req.entry_point,
            timeout_s=validated_timeout,
            dependencies=dependencies,
        )

        duration_ms = (time.time() - start_time) * 1000

        # Check for setup errors
        if isinstance(result, Result):
            audit_ctx.log_failed(result.error)
            return http.error_response(result.error, status_code=500)

        audit_ctx.log_completed(result.exit_code, duration_ms)
        return http.success_response(result)
