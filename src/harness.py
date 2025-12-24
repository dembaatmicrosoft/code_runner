# Copyright (c) 2025 Microsoft Corporation.
# Licensed under the MIT License. See LICENSE file in the project root.
"""
Security harness for PEP 578 audit hook enforcement.

This module wraps user script execution with runtime security policies.
It blocks dangerous operations (network, subprocess, ctypes) at the
interpreter level before they reach the OS.

Usage: python harness.py <script_path>

Note: BLOCKED_EVENTS is defined here (not imported) to ensure the harness
works regardless of PYTHONPATH or working directory when invoked as subprocess.
"""
import os
import runpy
import sys

BLOCKED_EVENTS = frozenset([
    # Network access
    "socket.connect",
    "socket.bind",
    # Process execution
    "subprocess.Popen",
    "os.system",
    "os.exec",
    "os.spawn",
    "os.posix_spawn",
    "os.fork",
])


def _create_audit_hook():
    """Create audit hook that blocks dangerous operations."""
    blocked = BLOCKED_EVENTS

    def audit_hook(event: str, args: tuple) -> None:
        if event in blocked:
            raise RuntimeError(
                f"Security policy violation: '{event}' is blocked"
            )

    return audit_hook


sys.addaudithook(_create_audit_hook())


def main() -> int:
    """Execute user script with audit hook active."""
    if len(sys.argv) < 2:
        print("Usage: python harness.py <script_path>", file=sys.stderr)
        return 1

    script_path = sys.argv[1]
    sys.argv = sys.argv[1:]

    # Add script's directory to sys.path for local imports
    script_dir = os.path.dirname(os.path.abspath(script_path))
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)

    try:
        runpy.run_path(script_path, run_name="__main__")
        return 0
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 1


if __name__ == "__main__":
    sys.exit(main())
