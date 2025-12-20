# Contributing to CodeRunner

Thank you for your interest in contributing to CodeRunner! This document provides guidelines and information for contributors.

## Code of Conduct

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## How to Contribute

### Reporting Issues

- Check if the issue already exists in the [issue tracker](https://github.com/dembaatmicrosoft/code_runner/issues)
- If not, create a new issue with a clear title and description
- Include steps to reproduce, expected behavior, and actual behavior
- Add relevant labels (bug, enhancement, documentation, etc.)

### Submitting Changes

1. **Fork the repository** and create a feature branch from `main`
2. **Make your changes** following the coding standards below
3. **Add or update tests** for your changes
4. **Run the test suite** to ensure all tests pass
5. **Submit a pull request** with a clear description of the changes

### Pull Request Process

1. Ensure your PR description clearly describes the problem and solution
2. Reference any related issues using GitHub keywords (e.g., "Fixes #123")
3. Update documentation if you're changing functionality
4. Ensure all CI checks pass
5. Request review from maintainers

## Development Setup

### Prerequisites

- Python 3.10 or later
- Azure Functions Core Tools v4
- Git

### Local Development

```bash
# Clone your fork
git clone https://github.com/<your-username>/code_runner.git
cd code_runner

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install pytest pytest-cov

# Run tests
pytest test_function_app.py -v

# Run locally
func start
```

## Coding Standards

### Python Style

- Follow [PEP 8](https://pep8.org/) style guidelines
- Use type hints for function signatures
- Maximum line length: 100 characters
- Use descriptive variable and function names

### Code Organization

- Keep functions small and focused (single responsibility)
- Use constants for magic numbers and strings
- Encapsulate boundary conditions in dedicated functions
- Prefer explicit over implicit

### Testing

- Write tests for all new functionality
- Follow the AAA pattern (Arrange, Act, Assert)
- One assertion per test when practical
- Mock external dependencies for unit tests
- Aim for high test coverage

### Documentation

- Add docstrings to all public functions
- Update README.md for user-facing changes
- Update OpenAPI spec for API changes
- Keep comments focused on "why", not "what"

## Commit Messages

- Use clear, descriptive commit messages
- Start with a verb in imperative mood (e.g., "Add", "Fix", "Update")
- Keep the first line under 72 characters
- Reference issues when applicable

Example:
```
Add timeout validation for negative values

- Return 400 error for timeout_s <= 0
- Add unit tests for edge cases
- Update API documentation

Fixes #42
```

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
