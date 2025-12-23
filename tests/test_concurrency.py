"""
Integration tests for concurrency and execution isolation.

Tests the sequential execution behavior including:
- Execution lock prevents interference
- Cleanup between requests
- Multiple rapid requests handled correctly
"""

import concurrent.futures

import pytest


class TestConcurrency:
    """Tests for concurrent request handling."""

    def test_sequential_requests_succeed(self, run_script):
        """Multiple sequential requests should all succeed."""
        results = []
        for i in range(3):
            response = run_script(f'print({i})')
            results.append(response.json())

        for i, result in enumerate(results):
            assert result["exit_code"] == 0
            assert str(i) in result["stdout"]

    def test_execution_produces_isolated_results(self, run_script, unique_id):
        """Each execution should have isolated state."""
        # First request creates a variable
        script1 = f"""
test_var_{unique_id} = "should not persist"
print("first")
"""
        response1 = run_script(script1)
        assert response1.json()["exit_code"] == 0

        # Second request should not see the variable
        script2 = f"""
try:
    print(test_var_{unique_id})
except NameError:
    print("isolated")
"""
        response2 = run_script(script2)
        data2 = response2.json()

        assert data2["exit_code"] == 0
        assert "isolated" in data2["stdout"]

    def test_temp_files_cleaned_between_requests(self, run_script):
        """Temporary files should be cleaned up between requests."""
        # First request creates output
        script1 = """
import os
os.makedirs('output', exist_ok=True)
with open('output/temp.txt', 'w') as f:
    f.write('temp')
print("created")
"""
        response1 = run_script(script1)
        assert response1.json()["exit_code"] == 0
        assert "temp.txt" in response1.json()["artifacts"]

        # Second request should not see the previous output
        script2 = """
import os
if os.path.exists('output/temp.txt'):
    print("found")
else:
    print("clean")
"""
        response2 = run_script(script2)
        data2 = response2.json()

        assert data2["exit_code"] == 0
        assert "clean" in data2["stdout"]

    @pytest.mark.timeout(60)
    def test_rapid_sequential_requests(self, run_script):
        """Many rapid requests should all complete successfully."""
        success_count = 0
        for i in range(10):
            response = run_script(f'print("request_{i}")')
            if response.json()["exit_code"] == 0:
                success_count += 1

        assert success_count == 10
