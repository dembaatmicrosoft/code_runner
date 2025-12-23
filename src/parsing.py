# Copyright (c) 2025 Microsoft Corporation.
# Licensed under the MIT License. See LICENSE file in the project root.
"""
Request parsing for CodeRunner.

Pure parsing logic that transforms raw request data into domain objects.
Returns Result types, not HTTP responses.
"""
from typing import Dict, List, Union

from src.config import (
    DEFAULT_TIMEOUT_S,
    DEPENDENCY_NAME_PATTERN,
    ENCODING_BASE64,
    ENCODING_UTF8,
    MAX_DEPENDENCIES,
    VERSION_SPEC_PATTERN,
)
from src.models import (
    ContextFile,
    Dependency,
    FileEntry,
    FilesRequest,
    LegacyRequest,
    Result,
)
from src.validation import validate_path_security


def parse_context_file(name: str, value: Union[str, dict]) -> Result[ContextFile]:
    """Parse a single context file entry."""
    if isinstance(value, str):
        return Result.success(ContextFile(name=name, content=value))

    if not isinstance(value, dict):
        return Result.failure(
            f"Context file '{name}' must be a string or object with 'content' field."
        )

    content = value.get("content")
    if not isinstance(content, str):
        return Result.failure(
            f"Context file '{name}' must have a 'content' string field."
        )

    encoding = value.get("encoding", ENCODING_UTF8)
    if encoding not in (ENCODING_UTF8, ENCODING_BASE64):
        return Result.failure(
            f"Invalid encoding '{encoding}' for '{name}'. Use '{ENCODING_UTF8}' or '{ENCODING_BASE64}'."
        )

    return Result.success(ContextFile(name=name, content=content, encoding=encoding))


def parse_context(raw_context: dict) -> Result[Dict[str, ContextFile]]:
    """Parse raw context dict into ContextFile objects."""
    if not isinstance(raw_context, dict):
        return Result.failure("`context` must be an object.")

    context = {}
    for name, value in raw_context.items():
        result = parse_context_file(name, value)
        if result.is_failure:
            return result
        context[name] = result.value

    return Result.success(context)


def parse_file_entry(path: str, value: Union[str, dict]) -> Result[FileEntry]:
    """Parse a single file entry for the files API."""
    path_result = validate_path_security(path)
    if path_result.is_failure:
        return Result.failure(path_result.error)

    normalized_path = path_result.value

    if isinstance(value, str):
        return Result.success(FileEntry(content=value))

    if not isinstance(value, dict):
        return Result.failure(
            f"File '{path}' must be a string or object with 'content' field."
        )

    content = value.get("content")
    if not isinstance(content, str):
        return Result.failure(
            f"File '{path}' must have a 'content' string field."
        )

    encoding = value.get("encoding", ENCODING_UTF8)
    if encoding not in (ENCODING_UTF8, ENCODING_BASE64):
        return Result.failure(
            f"Invalid encoding '{encoding}' for '{path}'. Use '{ENCODING_UTF8}' or '{ENCODING_BASE64}'."
        )

    return Result.success(FileEntry(content=content, encoding=encoding))


def parse_files(raw_files: dict) -> Result[Dict[str, FileEntry]]:
    """Parse raw files dict into FileEntry objects with normalized paths."""
    if not isinstance(raw_files, dict):
        return Result.failure("`files` must be an object.")

    if not raw_files:
        return Result.failure("`files` cannot be empty.")

    files = {}
    for path, value in raw_files.items():
        if not isinstance(path, str):
            return Result.failure("File path must be a string.")

        path_result = validate_path_security(path)
        if path_result.is_failure:
            return Result.failure(path_result.error)

        normalized_path = path_result.value
        entry_result = parse_file_entry(path, value)
        if entry_result.is_failure:
            return entry_result

        files[normalized_path] = entry_result.value

    return Result.success(files)


def parse_dependency(dep_str: str) -> Result[Dependency]:
    """Parse a single dependency string like 'requests' or 'requests>=2.0'."""
    if not isinstance(dep_str, str):
        return Result.failure("Dependency must be a string.")

    dep_str = dep_str.strip()
    if not dep_str:
        return Result.failure("Dependency cannot be empty.")

    # Find version specifier
    version_start = None
    for i, char in enumerate(dep_str):
        if char in "=<>!~":
            version_start = i
            break

    if version_start is None:
        name = dep_str
        version_spec = None
    else:
        name = dep_str[:version_start]
        version_spec = dep_str[version_start:]

    if not DEPENDENCY_NAME_PATTERN.match(name):
        return Result.failure(f"Invalid package name: '{name}'")

    if version_spec and not VERSION_SPEC_PATTERN.match(version_spec):
        return Result.failure(f"Invalid version specifier: '{version_spec}'")

    return Result.success(Dependency(name=name, version_spec=version_spec))


def parse_dependencies(raw_deps: list) -> Result[List[Dependency]]:
    """Parse a list of dependency strings."""
    if not isinstance(raw_deps, list):
        return Result.failure("`dependencies` must be an array.")

    if len(raw_deps) > MAX_DEPENDENCIES:
        return Result.failure(
            f"Too many dependencies: {len(raw_deps)} exceeds limit of {MAX_DEPENDENCIES}."
        )

    dependencies = []
    seen_names = set()

    for dep_str in raw_deps:
        result = parse_dependency(dep_str)
        if result.is_failure:
            return result

        dep = result.value
        if dep.name.lower() in seen_names:
            return Result.failure(f"Duplicate dependency: '{dep.name}'")

        seen_names.add(dep.name.lower())
        dependencies.append(dep)

    return Result.success(dependencies)


def parse_timeout(raw_timeout: object) -> Result[int]:
    """Parse timeout value from request."""
    if raw_timeout is None:
        return Result.success(DEFAULT_TIMEOUT_S)

    try:
        timeout_s = int(raw_timeout)
        return Result.success(timeout_s)
    except (ValueError, TypeError):
        return Result.failure("`timeout_s` must be an integer.")


def parse_files_request(body: dict) -> Result[FilesRequest]:
    """Parse a files mode request body."""
    files = body.get("files")
    if not isinstance(files, dict):
        return Result.failure("`files` is required and must be an object.")

    entry_point = body.get("entry_point")
    if not isinstance(entry_point, str):
        return Result.failure("`entry_point` is required and must be a string.")

    entry_point = entry_point.replace("\\", "/")

    timeout_result = parse_timeout(body.get("timeout_s"))
    if timeout_result.is_failure:
        return timeout_result

    raw_deps = body.get("dependencies", [])

    return Result.success(FilesRequest(
        files=files,
        entry_point=entry_point,
        timeout_s=timeout_result.value,
        raw_deps=raw_deps,
    ))


def parse_legacy_request(body: dict) -> Result[LegacyRequest]:
    """Parse a legacy mode request body."""
    script = body.get("script")
    if not isinstance(script, str):
        return Result.failure("`script` is required and must be a string.")

    timeout_result = parse_timeout(body.get("timeout_s"))
    if timeout_result.is_failure:
        return timeout_result

    raw_context = body.get("context", {})
    raw_deps = body.get("dependencies", [])

    return Result.success(LegacyRequest(
        script=script,
        timeout_s=timeout_result.value,
        raw_context=raw_context,
        raw_deps=raw_deps,
    ))
