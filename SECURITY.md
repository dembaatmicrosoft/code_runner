# Security Policy

## Reporting Security Issues

**Please do not report security vulnerabilities through public GitHub issues.**

If you believe you have found a security vulnerability in this project, please report it to us through coordinated disclosure.

Please include the following information in your report:
- Type of issue (e.g., buffer overflow, SQL injection, cross-site scripting, etc.)
- Full paths of source file(s) related to the issue
- Location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

## Security Considerations

### Intended Use

This Azure Function is designed for executing Python code in **trusted environments only**. It is suitable for:
- Development and testing workflows
- Internal tooling with authenticated users
- Controlled automation pipelines

### Not Suitable For

This function is **not hardened for untrusted code execution**. Do not use it for:
- Public-facing code execution services
- Processing untrusted user input as executable code
- Multi-tenant environments without additional isolation

### Security Measures

The following security measures are implemented:

| Measure | Description |
|---------|-------------|
| **Authentication** | Function-level key required for access (not anonymous) |
| **Audit logging** | Structured JSON logging with request ID, client IP, script hash, and execution metrics |
| **Environment sanitization** | Subprocess receives minimal safe environment (no secrets exposed) |
| **Timeout enforcement** | Scripts are terminated after the configured timeout (max 300s) |
| **Size limits** | Script size capped at 256 KiB; context/artifacts at 10 MB |
| **Path traversal prevention** | Context filenames are validated to prevent directory escape |
| **Temporary isolation** | Each execution uses a unique directory with restrictive permissions (0700) |
| **Subprocess isolation** | Scripts run in a subprocess, not in the function host |
| **Read-only input files** | Context files are written with read-only permissions (0400) |

### Recommended Deployment Practices

1. **Network isolation**: Deploy within a VNet with restricted ingress
2. **Monitoring**: Enable Application Insights for audit logging analysis
3. **Rate limiting**: Configure API Management or Azure Front Door for rate limiting
4. **Key rotation**: Regularly rotate function access keys

### Known Limitations

- The function runs within the Azure Functions sandbox, which provides OS-level isolation but is not equivalent to container or VM isolation
- Scripts have access to the Python standard library and any packages installed in the function app
- Memory limits are enforced by the Azure Functions host (~1.5 GB before OOM)

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.x     | :white_check_mark: |
| 1.x     | :x:                |
