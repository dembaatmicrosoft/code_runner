# CodeRunner Azure Function

A serverless endpoint to execute arbitrary Python scripts in a sandboxed subprocess. Supports two modes:

* **Raw mode** (`text/plain`): POST raw Python code, specify `timeout_s` as query parameter.
* **JSON mode** (`application/json`): POST `{ script: string, timeout_s?: number }`.

## Live Endpoint

```
https://coderunner-fn.azurewebsites.net/api/run
```

## Features

* **Timeout control** (clamped to 300 s)
* **Script size limit**: 256 KiB
* **UTF-8 I/O** in child process
* **Exit code**, **stdout**, **stderr** returned as JSON

## Prerequisites

* [Python 3.10+](https://www.python.org/downloads/)
* [Azure Functions Core Tools v4](https://learn.microsoft.com/azure/azure-functions/functions-run-local)
* An Azure subscription (for deployment)

## Local Setup

1. **Clone** this repo:

   ```bash
   git clone https://github.com/dembaatmicrosoft/code_runner.git
   cd code_runner
   ```

2. **Install** Python dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. **Run locally**:

   ```bash
   func start
   ```

   The function will be available at `http://localhost:7071/api/run`

## Testing

### Run unit tests

```bash
pytest test_function_app.py -v
```

### Manual testing - Raw mode

```bash
curl -X POST "http://localhost:7071/api/run?timeout_s=5" \
  -H "Content-Type: text/plain" \
  -d "print('Hello, World!')"
```

### Manual testing - JSON mode

```bash
curl -X POST "http://localhost:7071/api/run" \
  -H "Content-Type: application/json" \
  -d '{"script": "print(\"Hello, World!\")", "timeout_s": 5}'
```

## Deployment

### Using Azure Functions Core Tools

```bash
func azure functionapp publish <your-function-app-name> --python
```

### Using Azure CLI

```bash
# Create resources
az group create --name <resource-group> --location <location>
az storage account create --name <storage-name> --resource-group <resource-group>
az functionapp create --name <app-name> --resource-group <resource-group> \
  --storage-account <storage-name> --consumption-plan-location <location> \
  --runtime python --runtime-version 3.10 --functions-version 4 --os-type Linux

# Deploy
func azure functionapp publish <app-name> --python
```

## Usage

### Endpoint

* **Local**: `http://localhost:7071/api/run`
* **Azure**: `https://coderunner-fn.azurewebsites.net/api/run`

### Request formats

**JSON mode** (`Content-Type: application/json`):
```json
{
  "script": "print('Hello')",
  "timeout_s": 30
}
```

**Raw mode** (`Content-Type: text/plain`):
- Body: raw Python script
- Query param: `?timeout_s=30`

### Response format

```json
{
  "exit_code": 0,
  "stdout": "Hello\n",
  "stderr": ""
}
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1+ | Script error |
| 124 | Timeout |
| 137 | Out of memory |
| -1 | Internal error |

## Limits

* Timeout: max 300 seconds (values > 300 are clamped)
* Script size: max 256 KiB (UTF-8 bytes)
* Memory: ~1.5 GB before OOM kill

## Security

This function runs code in a subprocess within the Azure Functions sandbox. It is **not hardened for untrusted code**. Use only in trusted scenarios or for development/testing purposes.

## License

MIT
