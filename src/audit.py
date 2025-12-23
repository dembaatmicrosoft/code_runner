# Copyright (c) 2025 Microsoft Corporation.
# Licensed under the MIT License. See LICENSE file in the project root.
"""
Audit logging for CodeRunner.

Provides structured audit logging with a builder pattern to replace
the 11-parameter log_audit_event function.
"""
import hashlib
import json
import logging
import uuid
from dataclasses import dataclass, field
from typing import List, Optional

from src.config import ENCODING_UTF8


def compute_script_hash(script: str) -> str:
    """Compute SHA256 hash of script for audit logging (not storage)."""
    return hashlib.sha256(script.encode(ENCODING_UTF8)).hexdigest()[:16]


def generate_request_id() -> str:
    """Generate a unique request ID for audit correlation."""
    return str(uuid.uuid4())[:8]


@dataclass
class AuditContext:
    """
    Immutable context for audit logging.

    Created once at request start, passed through the request lifecycle.
    """
    request_id: str
    client_ip: str
    script_hash: str
    script_size: int
    timeout_s: int
    context_files: int
    dependencies: List[str] = field(default_factory=list)

    def log_started(self) -> None:
        """Log execution started event."""
        self._log("execution_started")

    def log_completed(self, exit_code: int, duration_ms: float) -> None:
        """Log execution completed event."""
        self._log(
            "execution_completed",
            exit_code=exit_code,
            duration_ms=round(duration_ms, 2),
        )

    def log_failed(self, error: str) -> None:
        """Log execution failed event."""
        self._log("execution_failed", error=error)

    def log_rejected(self, error: str) -> None:
        """Log request rejected event (validation failure)."""
        self._log("request_rejected", error=error)

    def _log(
        self,
        event_type: str,
        exit_code: Optional[int] = None,
        duration_ms: Optional[float] = None,
        error: Optional[str] = None,
    ) -> None:
        """Emit structured audit log."""
        audit_data = {
            "audit": True,
            "event": event_type,
            "request_id": self.request_id,
            "client_ip": self.client_ip,
            "script_hash": self.script_hash,
            "script_size_bytes": self.script_size,
            "timeout_s": self.timeout_s,
            "context_files": self.context_files,
            "dependencies": self.dependencies,
            "dependency_count": len(self.dependencies),
        }

        if exit_code is not None:
            audit_data["exit_code"] = exit_code
        if duration_ms is not None:
            audit_data["duration_ms"] = duration_ms
        if error is not None:
            audit_data["error"] = error

        logging.info(f"AUDIT: {json.dumps(audit_data)}")


class AuditContextBuilder:
    """
    Builder for creating AuditContext.

    Collects request information incrementally and builds the context.
    """

    def __init__(self, request_id: str, client_ip: str):
        self._request_id = request_id
        self._client_ip = client_ip
        self._script_hash = ""
        self._script_size = 0
        self._timeout_s = 0
        self._context_files = 0
        self._dependencies: List[str] = []

    def with_script(self, script: str) -> "AuditContextBuilder":
        """Set script information."""
        self._script_hash = compute_script_hash(script)
        self._script_size = len(script.encode(ENCODING_UTF8))
        return self

    def with_script_hash(self, script_hash: str, script_size: int) -> "AuditContextBuilder":
        """Set pre-computed script hash and size."""
        self._script_hash = script_hash
        self._script_size = script_size
        return self

    def with_timeout(self, timeout_s: int) -> "AuditContextBuilder":
        """Set timeout."""
        self._timeout_s = timeout_s
        return self

    def with_context_files(self, count: int) -> "AuditContextBuilder":
        """Set context file count."""
        self._context_files = count
        return self

    def with_dependencies(self, deps: List[str]) -> "AuditContextBuilder":
        """Set dependencies list."""
        self._dependencies = deps
        return self

    def build(self) -> AuditContext:
        """Build the AuditContext."""
        return AuditContext(
            request_id=self._request_id,
            client_ip=self._client_ip,
            script_hash=self._script_hash,
            script_size=self._script_size,
            timeout_s=self._timeout_s,
            context_files=self._context_files,
            dependencies=self._dependencies,
        )


def create_audit_context(
    client_ip: str,
    script: str,
    timeout_s: int,
    context_files: int = 0,
    dependencies: Optional[List[str]] = None,
) -> AuditContext:
    """
    Convenience function to create an AuditContext.

    For simple cases where builder pattern is overkill.
    """
    return AuditContext(
        request_id=generate_request_id(),
        client_ip=client_ip,
        script_hash=compute_script_hash(script),
        script_size=len(script.encode(ENCODING_UTF8)),
        timeout_s=timeout_s,
        context_files=context_files,
        dependencies=dependencies or [],
    )
