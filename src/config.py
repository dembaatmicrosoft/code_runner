# Copyright (c) 2025 Microsoft Corporation.
# Licensed under the MIT License. See LICENSE file in the project root.
"""
Configuration constants for CodeRunner.

All magic numbers, limits, and configuration values are centralized here.
This is the single source of truth for all configurable parameters.
"""
import re

# =============================================================================
# Timeout Configuration
# =============================================================================
MAX_TIMEOUT_S = 300
DEFAULT_TIMEOUT_S = 60
DEPENDENCY_TIMEOUT_S = 30

# =============================================================================
# Size Limits
# =============================================================================
MAX_SCRIPT_BYTES = 256 * 1024  # 256 KB
MAX_CONTEXT_BYTES = 10 * 1024 * 1024  # 10 MB
MAX_ARTIFACTS_BYTES = 10 * 1024 * 1024  # 10 MB
MAX_SINGLE_FILE_BYTES = 5 * 1024 * 1024  # 5 MB
MAX_CONTEXT_FILES = 20
MAX_DEPENDENCIES = 15

# =============================================================================
# Directory Names
# =============================================================================
INPUT_DIR = "input"
OUTPUT_DIR = "output"

# =============================================================================
# Content Types
# =============================================================================
CONTENT_TYPE_JSON = "application/json"
CONTENT_TYPE_TEXT = "text/plain"

# =============================================================================
# Encodings
# =============================================================================
ENCODING_UTF8 = "utf-8"
ENCODING_BASE64 = "base64"

# =============================================================================
# Exit Codes
# =============================================================================
EXIT_CODE_TIMEOUT = 124
EXIT_CODE_INTERNAL_ERROR = -1

# =============================================================================
# Validation Patterns
# =============================================================================
DEPENDENCY_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$')
VERSION_SPEC_PATTERN = re.compile(
    r'^(==|>=|<=|~=|!=|<|>)[0-9]+(\.[0-9]+)*([ab][0-9]+)?(\.post[0-9]+)?(\.dev[0-9]+)?$'
)

# =============================================================================
# Pre-installed Packages
# =============================================================================
PRE_INSTALLED_PACKAGES: frozenset = frozenset([
    "azure-functions",
    "numpy", "pandas", "scipy", "scikit-learn", "matplotlib",
    "requests", "httpx", "beautifulsoup4",
    "pyyaml", "toml", "python-dateutil",
    "tqdm", "pillow",
])

# =============================================================================
# Environment Variables Safe to Pass to Subprocess
# =============================================================================
SAFE_ENV_VARS = frozenset([
    "PATH",
    "HOME",
    "USER",
    "LANG",
    "LC_ALL",
    "TERM",
    "TZ",
    "PYTHONIOENCODING",
])

# =============================================================================
# Blocked Audit Events (PEP 578 Runtime Security)
# Note: These are duplicated in src/harness.py for subprocess isolation.
# Keep both lists in sync when modifying.
# =============================================================================
BLOCKED_AUDIT_EVENTS: frozenset = frozenset([
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
    # Low-level memory access
    "ctypes.dlopen",
    "ctypes.dlsym",
    "ctypes.cdata",
])
