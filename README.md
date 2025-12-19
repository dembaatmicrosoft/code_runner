# CodeRunner Azure Function

A serverless endpoint to execute arbitrary Python scripts in a sandboxed subprocess. Supports two modes:

* **Raw mode** (`text/plain`): POST raw Python code, specify `timeout_s` as query parameter.
* **JSON mode** (`application/json`): POST `{ script, timeout_s?, context? }`.

## Live Endpoint

```
https://coderunner-fn.azurewebsites.net/api/run
```

## Features

* **Timeout control** (clamped to 300 s)
* **Script size limit**: 256 KiB
* **Context files**: Provide input files to scripts (up to 10 MB total)
* **Artifacts**: Collect output files from scripts (up to 10 MB total)
* **Binary support**: Auto-detected, base64 encoded
* **UTF-8 I/O** in child process
* **Exit code**, **stdout**, **stderr**, **artifacts** returned as JSON

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

### Manual testing - With context files

```bash
curl -X POST "http://localhost:7071/api/run" \
  -H "Content-Type: application/json" \
  -d '{
    "script": "import csv\nwith open(\"./input/data.csv\") as f:\n    print(f.read())",
    "context": {"data.csv": "a,b\n1,2\n3,4"}
  }'
```

### Manual testing - With artifacts

```bash
curl -X POST "http://localhost:7071/api/run" \
  -H "Content-Type: application/json" \
  -d '{
    "script": "import os\nos.makedirs(\"./output\", exist_ok=True)\nwith open(\"./output/result.txt\", \"w\") as f:\n    f.write(\"Hello!\")"
  }'
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
  "timeout_s": 30,
  "context": {
    "data.csv": "col1,col2\n1,2",
    "image.png": {"content": "iVBORw0KGgo...", "encoding": "base64"}
  }
}
```

**Raw mode** (`Content-Type: text/plain`):
- Body: raw Python script
- Query param: `?timeout_s=30`
- Note: Context files not supported in raw mode

### Context files

Scripts can read input files from the `./input/` directory:

```python
# Read a text file
with open("./input/data.csv") as f:
    data = f.read()

# Read a binary file
with open("./input/image.png", "rb") as f:
    image = f.read()
```

Context can be provided as:
- **String**: Treated as UTF-8 text
- **Object**: `{"content": "...", "encoding": "utf-8|base64"}`

### Artifacts

Scripts can write output files to the `./output/` directory:

```python
import os
os.makedirs("./output", exist_ok=True)

# Write a text file
with open("./output/result.csv", "w") as f:
    f.write("result,data\n1,2")

# Write a binary file
with open("./output/plot.png", "wb") as f:
    f.write(png_bytes)
```

Artifacts are returned in the response with auto-detected encoding:
- **Text files**: Returned as strings
- **Binary files**: Returned as `{"content": "...", "encoding": "base64"}`

### Response format

```json
{
  "exit_code": 0,
  "stdout": "Hello\n",
  "stderr": "",
  "artifacts": {
    "result.csv": "result,data\n1,2",
    "plot.png": {"content": "iVBORw0KGgo...", "encoding": "base64"}
  }
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

| Resource | Limit |
|----------|-------|
| Timeout | 300 seconds max (clamped) |
| Script size | 256 KiB (UTF-8 bytes) |
| Context files | 20 files max |
| Single context file | 5 MB |
| Total context | 10 MB |
| Total artifacts | 10 MB |
| Memory | ~1.5 GB before OOM kill |

## Security

This function runs code in a subprocess within the Azure Functions sandbox. It is **not hardened for untrusted code**. Use only in trusted scenarios or for development/testing purposes.

### Security measures

- **Filename validation**: Context filenames cannot contain `/`, `\`, or start with `.`
- **Size limits**: Enforced on scripts, context, and artifacts
- **Timeout**: Scripts are killed after the specified timeout
- **Isolation**: Each execution uses a unique temporary directory

## License

MIT
