# Copyright (c) 2025 Microsoft Corporation.
# Licensed under the MIT License. See LICENSE file in the project root.
"""
Validation logic for CodeRunner.

All boundary conditions and security validations are centralized here.
This module enforces constraints without knowing about HTTP.
"""
import logging
from typing import Callable, Dict, Optional

from src.config import (
    MAX_CONTEXT_BYTES,
    MAX_CONTEXT_FILES,
    MAX_SCRIPT_BYTES,
    MAX_SINGLE_FILE_BYTES,
    MAX_TIMEOUT_S,
)
from src.models import Result


def validate_path_security(path: str) -> Result[str]:
    """
    Validate path against traversal attacks and normalize separators.

    Returns the normalized path on success, or an error message on failure.
    """
    if not path:
        return Result.failure("Path cannot be empty.")

    normalized = path.replace("\\", "/")

    if normalized.startswith("/"):
        return Result.failure(f"Absolute paths not allowed: '{path}'")

    if len(normalized) >= 2 and normalized[1] == ":":
        return Result.failure(f"Windows absolute paths not allowed: '{path}'")

    segments = normalized.split("/")
    for segment in segments:
        if not segment:
            continue
        if segment == "..":
            return Result.failure(f"Path traversal not allowed: '{path}'")
        if segment.startswith("."):
            return Result.failure(f"Hidden files/directories not allowed: '{path}'")

    return Result.success(normalized)


def validate_filename(name: str) -> Result[str]:
    """
    Validate a simple filename (no directories).

    Used for legacy context file validation.
    """
    if not name:
        return Result.failure("Filename cannot be empty.")

    if "/" in name or "\\" in name:
        return Result.failure(f"Filename cannot contain path separators: '{name}'")

    if name.startswith("."):
        return Result.failure(f"Hidden files not allowed: '{name}'")

    return Result.success(name)


def validate_timeout(timeout_s: int) -> Result[int]:
    """
    Validate and clamp timeout value.

    Returns the validated (possibly clamped) timeout.
    """
    if timeout_s <= 0:
        return Result.failure("`timeout_s` must be > 0.")

    if timeout_s > MAX_TIMEOUT_S:
        logging.warning(f"Clamping timeout {timeout_s}s to {MAX_TIMEOUT_S}s.")
        return Result.success(MAX_TIMEOUT_S)

    return Result.success(timeout_s)


def validate_script_size(script: str) -> Result[None]:
    """Validate script doesn't exceed size limit."""
    size = len(script.encode("utf-8"))
    if size > MAX_SCRIPT_BYTES:
        return Result.failure(
            f"Script too large: {size} bytes exceeds {MAX_SCRIPT_BYTES} bytes."
        )
    return Result.success(None)


def validate_entry_point(entry_point: str, file_paths: set) -> Result[str]:
    """
    Validate entry point exists and is a Python file.

    Args:
        entry_point: The entry point path
        file_paths: Set of valid file paths in the request

    Returns:
        Validated entry point path or error.
    """
    if not entry_point.endswith(".py"):
        return Result.failure(
            f"Entry point must be a .py file, got: '{entry_point}'"
        )

    if entry_point not in file_paths:
        return Result.failure(
            f"Entry point '{entry_point}' not found in files."
        )

    return Result.success(entry_point)


def validate_file_collection(
    files: Dict[str, object],
    get_size: Callable[[object], int],
    max_count: int,
    max_total_bytes: int,
    max_single_file_bytes: int,
    validate_path: Callable[[str], Result[str]],
) -> Result[None]:
    """
    Generic validator for file collections.

    This unified validator works for both context files and files API,
    avoiding code duplication.

    Args:
        files: Dictionary mapping paths/names to file objects
        get_size: Function to get size of a file object
        max_count: Maximum number of files allowed
        max_total_bytes: Maximum total size in bytes
        max_single_file_bytes: Maximum size of single file
        validate_path: Function to validate each path/name

    Returns:
        Success or error result.
    """
    if len(files) > max_count:
        return Result.failure(
            f"Too many files: {len(files)} exceeds limit of {max_count}."
        )

    total_bytes = 0

    for path, file_obj in files.items():
        path_result = validate_path(path)
        if path_result.is_failure:
            return path_result

        file_size = get_size(file_obj)
        total_bytes += file_size

        if file_size > max_single_file_bytes:
            return Result.failure(
                f"File too large: '{path}' is {file_size} bytes, "
                f"exceeds {max_single_file_bytes} bytes."
            )

    if total_bytes > max_total_bytes:
        return Result.failure(
            f"Total size too large: {total_bytes} bytes exceeds {max_total_bytes} bytes."
        )

    return Result.success(None)


def validate_context_files(
    context: Dict[str, object],
    get_size: Callable[[object], int],
) -> Result[None]:
    """Validate context files using standard limits."""
    return validate_file_collection(
        files=context,
        get_size=get_size,
        max_count=MAX_CONTEXT_FILES,
        max_total_bytes=MAX_CONTEXT_BYTES,
        max_single_file_bytes=MAX_SINGLE_FILE_BYTES,
        validate_path=validate_filename,
    )


def validate_files_api(
    files: Dict[str, object],
    get_size: Callable[[object], int],
) -> Result[None]:
    """Validate files API collection using standard limits."""
    return validate_file_collection(
        files=files,
        get_size=get_size,
        max_count=MAX_CONTEXT_FILES,
        max_total_bytes=MAX_CONTEXT_BYTES,
        max_single_file_bytes=MAX_SINGLE_FILE_BYTES,
        validate_path=validate_path_security,
    )
