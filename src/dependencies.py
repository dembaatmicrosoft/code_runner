# Copyright (c) 2025 Microsoft Corporation.
# Licensed under the MIT License. See LICENSE file in the project root.
"""
Dependency management for CodeRunner.

Handles filtering pre-installed packages and installing new dependencies.
"""
import shutil
import subprocess
from pathlib import Path
from typing import List

from src.config import DEPENDENCY_TIMEOUT_S, ENCODING_UTF8, SAFE_ENV_VARS
from src.models import Dependency, Result
import os


def filter_pre_installed(deps: List[Dependency]) -> List[Dependency]:
    """Remove pre-installed packages from dependency list."""
    return [dep for dep in deps if not dep.is_pre_installed()]


def _create_install_environment() -> dict:
    """Create a minimal safe environment for dependency installation."""
    env = {}
    for var in SAFE_ENV_VARS:
        if var in os.environ:
            env[var] = os.environ[var]
    env["PYTHONIOENCODING"] = ENCODING_UTF8
    return env


def install(
    deps: List[Dependency],
    target_dir: Path,
    timeout_s: int = DEPENDENCY_TIMEOUT_S,
) -> Result[None]:
    """
    Install dependencies to target directory.

    Uses UV if available, falls back to pip.
    Returns success or error result.
    """
    if not deps:
        return Result.success(None)

    package_list = [str(dep) for dep in deps]
    packages_dir = target_dir / ".packages"
    packages_dir.mkdir(parents=True, exist_ok=True)

    has_uv = shutil.which("uv") is not None

    if has_uv:
        cmd = [
            "uv", "pip", "install",
            "--target", str(packages_dir),
            "--no-cache",
            "--quiet",
            *package_list,
        ]
    else:
        cmd = [
            "pip", "install",
            "--target", str(packages_dir),
            "--no-cache-dir",
            "--disable-pip-version-check",
            "--no-warn-script-location",
            "--quiet",
            *package_list,
        ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout_s,
            env=_create_install_environment(),
            cwd=str(target_dir),
        )

        if result.returncode != 0:
            stderr = result.stderr.decode(ENCODING_UTF8, errors="replace")
            if len(stderr) > 500:
                stderr = stderr[:500] + "..."
            return Result.failure(f"Dependency installation failed: {stderr}")

        return Result.success(None)

    except subprocess.TimeoutExpired:
        return Result.failure(
            f"Dependency installation timed out after {timeout_s}s"
        )
    except Exception as e:
        return Result.failure(f"Dependency installation error: {str(e)}")
