# Copyright (c) 2025 Microsoft Corporation.
# Licensed under the MIT License. See LICENSE file in the project root.
"""
File I/O operations for CodeRunner.

Handles file materialization (writing to disk) and artifact collection.
"""
import base64
from pathlib import Path
from typing import Dict, Union

from src.config import (
    ENCODING_BASE64,
    ENCODING_UTF8,
    INPUT_DIR,
    MAX_ARTIFACTS_BYTES,
    OUTPUT_DIR,
)
from src.models import ContextFile, FileEntry, Result


def is_binary_content(data: bytes) -> bool:
    """
    Detect if content is binary.

    Binary content contains null bytes or cannot be decoded as UTF-8.
    """
    if b"\x00" in data:
        return True
    try:
        data.decode(ENCODING_UTF8)
        return False
    except UnicodeDecodeError:
        return True


def decode_content(content: str, encoding: str) -> bytes:
    """Decode file content from request format to bytes."""
    if encoding == ENCODING_BASE64:
        return base64.b64decode(content)
    return content.encode(ENCODING_UTF8)


def decode_context_file(context_file: ContextFile) -> bytes:
    """Decode a ContextFile to bytes."""
    return decode_content(context_file.content, context_file.encoding)


def decode_file_entry(file_entry: FileEntry) -> bytes:
    """Decode a FileEntry to bytes."""
    return decode_content(file_entry.content, file_entry.encoding)


def encode_content(data: bytes) -> Union[str, dict]:
    """
    Encode file content for response.

    Text files are returned as plain strings.
    Binary files are returned as {"content": "...", "encoding": "base64"}.
    """
    if is_binary_content(data):
        return {
            "content": base64.b64encode(data).decode("ascii"),
            "encoding": ENCODING_BASE64,
        }
    return data.decode(ENCODING_UTF8)


def materialize_context(context: Dict[str, ContextFile], exec_dir: Path) -> None:
    """
    Write context files to input/ directory.

    Creates the input directory and writes each file with read-only permissions.
    """
    input_dir = exec_dir / INPUT_DIR
    input_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    for name, context_file in context.items():
        file_path = input_dir / name
        file_bytes = decode_context_file(context_file)
        file_path.write_bytes(file_bytes)
        file_path.chmod(0o400)


def materialize_files(files: Dict[str, FileEntry], exec_dir: Path) -> None:
    """
    Write files to execution directory.

    Creates parent directories as needed and sets read-only permissions.
    """
    for path, file_entry in files.items():
        file_path = exec_dir / path
        file_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

        file_bytes = decode_file_entry(file_entry)
        file_path.write_bytes(file_bytes)
        file_path.chmod(0o400)


def collect_artifacts_flat(exec_dir: Path) -> Result[dict]:
    """
    Collect top-level files from output directory.

    Used by legacy mode for backward compatibility.
    Does not recurse into subdirectories.
    """
    output_dir = exec_dir / OUTPUT_DIR

    if not output_dir.exists():
        return Result.success({})

    artifacts = {}
    total_bytes = 0

    for path in output_dir.iterdir():
        if not path.is_file():
            continue

        file_bytes = path.read_bytes()
        file_size = len(file_bytes)
        total_bytes += file_size

        if total_bytes > MAX_ARTIFACTS_BYTES:
            return Result.failure(
                f"Total artifacts too large: exceeds {MAX_ARTIFACTS_BYTES} bytes."
            )

        artifacts[path.name] = encode_content(file_bytes)

    return Result.success(artifacts)


def collect_artifacts_recursive(exec_dir: Path) -> Result[dict]:
    """
    Collect all files from output directory recursively.

    Used by files mode to support nested output directories.
    """
    output_dir = exec_dir / OUTPUT_DIR

    if not output_dir.exists():
        return Result.success({})

    artifacts = {}
    total_bytes = 0

    for path in output_dir.rglob("*"):
        if not path.is_file():
            continue

        file_bytes = path.read_bytes()
        file_size = len(file_bytes)
        total_bytes += file_size

        if total_bytes > MAX_ARTIFACTS_BYTES:
            return Result.failure(
                f"Total artifacts too large: exceeds {MAX_ARTIFACTS_BYTES} bytes."
            )

        relative_path = path.relative_to(output_dir)
        artifact_key = str(relative_path).replace("\\", "/")
        artifacts[artifact_key] = encode_content(file_bytes)

    return Result.success(artifacts)
