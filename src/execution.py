# Copyright (c) 2025 Microsoft Corporation.
# Licensed under the MIT License. See LICENSE file in the project root.
"""
Script execution for CodeRunner.

Handles subprocess execution with timeout, environment isolation, and cleanup.
"""
import logging
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Union

from src.config import (
    ENCODING_UTF8,
    EXIT_CODE_INTERNAL_ERROR,
    EXIT_CODE_TIMEOUT,
    OUTPUT_DIR,
    SAFE_ENV_VARS,
)
from src.models import ContextFile, Dependency, ExecutionResult, FileEntry, Result
from src import dependencies as deps_module
from src import files as files_module

HARNESS_PATH = Path(__file__).parent / "harness.py"

# Bundled packages directory (relative to app root, not working dir)
# This is where packages are installed in the deploy.zip
APP_ROOT = Path(__file__).parent.parent
BUNDLED_PACKAGES_DIR = APP_ROOT / ".python_packages" / "lib" / "site-packages"


def create_safe_environment() -> dict:
    """
    Build minimal safe environment for subprocess.

    Only passes through safe environment variables and sets Python-specific
    encoding and buffering settings.
    """
    env = {}
    for var in SAFE_ENV_VARS:
        if var in os.environ:
            env[var] = os.environ[var]
    env["PYTHONIOENCODING"] = ENCODING_UTF8
    env["PYTHONUNBUFFERED"] = "1"  # Ensure stdout/stderr are unbuffered
    return env


def kill_process_tree(pid: int) -> None:
    """Kill process and all children using process group."""
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError) as e:
        logging.warning(f"Failed to kill process tree {pid}: {e}")


def run_subprocess(
    script_path: str,
    working_dir: str,
    timeout_s: int,
) -> ExecutionResult:
    """
    Execute a Python script in a subprocess with timeout.

    Returns ExecutionResult with exit_code, stdout, stderr.
    """
    env = create_safe_environment()
    on_demand_packages_dir = Path(working_dir) / ".packages"

    pythonpath_parts = []
    if BUNDLED_PACKAGES_DIR.exists():
        pythonpath_parts.append(str(BUNDLED_PACKAGES_DIR))
    if on_demand_packages_dir.exists():
        pythonpath_parts.append(str(on_demand_packages_dir))

    if pythonpath_parts:
        env["PYTHONPATH"] = os.pathsep.join(pythonpath_parts)

    process = subprocess.Popen(
        [sys.executable, str(HARNESS_PATH), script_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=working_dir,
        env=env,
        start_new_session=True,
    )

    try:
        stdout, stderr = process.communicate(timeout=timeout_s)
        return ExecutionResult(
            exit_code=process.returncode,
            stdout=stdout.decode(ENCODING_UTF8, errors="replace"),
            stderr=stderr.decode(ENCODING_UTF8, errors="replace"),
        )
    except subprocess.TimeoutExpired:
        kill_process_tree(process.pid)
        stdout, stderr = process.communicate()
        timeout_stderr = stderr.decode(ENCODING_UTF8, errors="replace") if stderr else ""
        timeout_stderr += "\n[Error: Script timed out]"
        return ExecutionResult(
            exit_code=EXIT_CODE_TIMEOUT,
            stdout=stdout.decode(ENCODING_UTF8, errors="replace") if stdout else "",
            stderr=timeout_stderr,
        )
    finally:
        if process.poll() is None:
            kill_process_tree(process.pid)
            process.wait()


def cleanup_exec_dir(exec_dir: Path) -> None:
    """Remove execution directory and all contents."""
    try:
        shutil.rmtree(exec_dir)
    except Exception as e:
        logging.warning(f"Failed to cleanup {exec_dir}: {e}")


def execute_script(
    script: str,
    timeout_s: int,
    context: Optional[Dict[str, ContextFile]] = None,
    dependencies: Optional[List[Dependency]] = None,
) -> Union[ExecutionResult, Result[None]]:
    """
    Execute a script with optional context and dependencies.

    This is the legacy mode execution flow.
    Returns ExecutionResult on success, Result.failure on setup errors.
    """
    context = context or {}
    dependencies = dependencies or []
    exec_id = str(uuid.uuid4())
    exec_dir = Path(tempfile.gettempdir()) / f"exec_{exec_id}"

    try:
        exec_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        (exec_dir / OUTPUT_DIR).mkdir(mode=0o700)

        deps_to_install = deps_module.filter_pre_installed(dependencies)
        if deps_to_install:
            install_result = deps_module.install(deps_to_install, exec_dir)
            if install_result.is_failure:
                return Result.failure(install_result.error)

        if context:
            files_module.materialize_context(context, exec_dir)

        script_path = exec_dir / "script.py"
        try:
            script_path.write_text(script, encoding=ENCODING_UTF8)
            script_path.chmod(0o400)
        except Exception as e:
            logging.error(f"Failed to write script to disk: {e}")
            return Result.failure("Internal error writing script to disk.")

        result = run_subprocess(str(script_path), str(exec_dir), timeout_s)

        artifacts_result = files_module.collect_artifacts_flat(exec_dir)
        if artifacts_result.is_failure:
            return Result.failure(artifacts_result.error)

        return ExecutionResult(
            exit_code=result.exit_code,
            stdout=result.stdout,
            stderr=result.stderr,
            artifacts=artifacts_result.value,
        )

    finally:
        cleanup_exec_dir(exec_dir)


def execute_files(
    files: Dict[str, FileEntry],
    entry_point: str,
    timeout_s: int,
    dependencies: Optional[List[Dependency]] = None,
) -> Union[ExecutionResult, Result[None]]:
    """
    Execute files mode: materialize all files and run entry_point.

    Returns ExecutionResult on success, Result.failure on setup errors.
    """
    dependencies = dependencies or []
    exec_id = str(uuid.uuid4())
    exec_dir = Path(tempfile.gettempdir()) / f"exec_{exec_id}"

    try:
        exec_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        (exec_dir / OUTPUT_DIR).mkdir(mode=0o700)

        deps_to_install = deps_module.filter_pre_installed(dependencies)
        if deps_to_install:
            install_result = deps_module.install(deps_to_install, exec_dir)
            if install_result.is_failure:
                return Result.failure(install_result.error)

        files_module.materialize_files(files, exec_dir)

        entry_point_path = exec_dir / entry_point
        result = run_subprocess(str(entry_point_path), str(exec_dir), timeout_s)

        artifacts_result = files_module.collect_artifacts_recursive(exec_dir)
        if artifacts_result.is_failure:
            return Result.failure(artifacts_result.error)

        return ExecutionResult(
            exit_code=result.exit_code,
            stdout=result.stdout,
            stderr=result.stderr,
            artifacts=artifacts_result.value,
        )

    finally:
        cleanup_exec_dir(exec_dir)
