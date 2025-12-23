# Copyright (c) 2025 Microsoft Corporation.
# Licensed under the MIT License. See LICENSE file in the project root.
"""
Data models for CodeRunner.

Contains all domain objects and the Result type for error handling
without coupling to HTTP concerns.
"""
from dataclasses import dataclass, field
from typing import Dict, Generic, List, Optional, TypeVar

from src.config import ENCODING_UTF8, PRE_INSTALLED_PACKAGES

T = TypeVar("T")


@dataclass
class Result(Generic[T]):
    """
    Represents success or failure without HTTP coupling.

    Use this instead of Union[T, HttpResponse] to keep business logic
    separate from HTTP concerns.
    """
    value: Optional[T] = None
    error: Optional[str] = None

    @property
    def is_success(self) -> bool:
        return self.error is None

    @property
    def is_failure(self) -> bool:
        return self.error is not None

    @classmethod
    def success(cls, value: T) -> "Result[T]":
        return cls(value=value)

    @classmethod
    def failure(cls, error: str) -> "Result[T]":
        return cls(error=error)

    def unwrap(self) -> T:
        """Get the value, raising ValueError if this is a failure."""
        if self.is_failure:
            raise ValueError(f"Cannot unwrap failure: {self.error}")
        return self.value


@dataclass
class ContextFile:
    """Represents a file in the execution context (legacy mode)."""
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
    files: dict
    entry_point: str
    timeout_s: int
    raw_deps: list = field(default_factory=list)


@dataclass
class LegacyRequest:
    """Request using the legacy API (script + context mode)."""
    script: str
    timeout_s: int
    raw_context: dict = field(default_factory=dict)
    raw_deps: list = field(default_factory=list)
