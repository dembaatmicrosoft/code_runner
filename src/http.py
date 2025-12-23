# Copyright (c) 2025 Microsoft Corporation.
# Licensed under the MIT License. See LICENSE file in the project root.
"""
HTTP utilities for CodeRunner.

Contains functions for creating HTTP responses and extracting request information.
This is the only module that should know about azure.functions types.
"""
import json
from typing import Callable, TypeVar

import azure.functions as func

from src.config import CONTENT_TYPE_JSON
from src.models import ExecutionResult, Result

T = TypeVar("T")


def error_response(message: str, status_code: int = 400) -> func.HttpResponse:
    """Create a standardized error response."""
    return func.HttpResponse(
        json.dumps({"error": message}),
        status_code=status_code,
        mimetype=CONTENT_TYPE_JSON,
    )


def success_response(result: ExecutionResult) -> func.HttpResponse:
    """Create a success response from execution result."""
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


def get_client_ip(req: func.HttpRequest) -> str:
    """Extract client IP from request headers (handles proxies)."""
    forwarded_for = req.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return req.headers.get("X-Client-IP", "unknown")


def result_to_response(
    result: Result[T],
    on_success: Callable[[T], func.HttpResponse],
    status_code: int = 400,
) -> func.HttpResponse:
    """
    Convert a Result to an HttpResponse.

    If the result is a success, calls on_success with the value.
    If the result is a failure, returns an error response.
    """
    if result.is_success:
        return on_success(result.value)
    return error_response(result.error, status_code=status_code)
