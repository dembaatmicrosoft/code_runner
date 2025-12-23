"""
Integration tests for dependency installation.

Tests the package installation functionality including:
- Pre-installed packages (numpy, pandas, etc.)
- On-demand package installation
- Version specifier support
- Installation error handling
"""

import pytest


class TestPreInstalledPackages:
    """Tests for pre-installed packages that should work without installation."""

    def test_numpy_available(self, run_script):
        """numpy should be pre-installed and importable."""
        script = """
import numpy as np
print(f"numpy {np.__version__}")
"""
        response = run_script(script)
        data = response.json()

        assert data["exit_code"] == 0
        assert "numpy" in data["stdout"]

    def test_pandas_available(self, run_script):
        """pandas should be pre-installed and importable."""
        script = """
import pandas as pd
print(f"pandas {pd.__version__}")
"""
        response = run_script(script)
        data = response.json()

        assert data["exit_code"] == 0
        assert "pandas" in data["stdout"]

    def test_scipy_available(self, run_script):
        """scipy should be pre-installed and importable."""
        script = """
import scipy
print(f"scipy {scipy.__version__}")
"""
        response = run_script(script)
        data = response.json()

        assert data["exit_code"] == 0
        assert "scipy" in data["stdout"]

    def test_requests_available(self, run_script):
        """requests should be pre-installed and importable."""
        script = """
import requests
print(f"requests {requests.__version__}")
"""
        response = run_script(script)
        data = response.json()

        assert data["exit_code"] == 0
        assert "requests" in data["stdout"]


class TestOnDemandInstallation:
    """Tests for on-demand package installation."""

    def test_install_simple_package(self, run_script):
        """Simple packages should install and be usable."""
        script = """
import cowsay
print(cowsay.get_output_string('cow', 'test'))
"""
        response = run_script(script, dependencies=["cowsay"])
        data = response.json()

        assert data["exit_code"] == 0
        assert "test" in data["stdout"]

    def test_install_with_version_specifier(self, run_script):
        """Packages with version specifiers should install correctly."""
        script = """
import emoji
print(emoji.emojize(':thumbs_up:'))
"""
        response = run_script(script, dependencies=["emoji>=2.0.0"])
        data = response.json()

        assert data["exit_code"] == 0

    def test_pre_installed_in_dependencies_skipped(self, run_script):
        """Pre-installed packages in dependencies list should be skipped."""
        script = """
import numpy as np
print(np.__version__)
"""
        # numpy is pre-installed, so this should work without delay
        response = run_script(script, dependencies=["numpy"])
        data = response.json()

        assert data["exit_code"] == 0

    def test_missing_package_without_dependency_fails(self, run_script):
        """Importing unavailable package without dependency should fail."""
        script = 'import nonexistent_package_xyz'
        response = run_script(script)
        data = response.json()

        assert data["exit_code"] != 0
        assert "ModuleNotFoundError" in data["stderr"]

    @pytest.mark.timeout(120)
    def test_multiple_dependencies(self, run_script):
        """Multiple dependencies should all be installed."""
        script = """
import cowsay
import pyjokes
print("success")
"""
        response = run_script(script, dependencies=["cowsay", "pyjokes"])
        data = response.json()

        assert data["exit_code"] == 0
        assert "success" in data["stdout"]
