# CodeRunner Azure Function

A serverless endpoint to execute arbitrary Python scripts in a sandboxed subprocess. Supports two modes:

* **Raw mode** (`text/plain`): POST raw Python code, specify `timeout_s` as query parameter.
* **JSON mode** (`application/json`): POST `{ script: string, timeout_s?: number }`.

## Features

* **Timeout control** (clamped to 300 s)
* **Script size limit**: 256 KiB
* **UTF‑8 I/O** in child process
* **Exit code**, **stdout**, **stderr** returned as JSON

## Prerequisites

* [Python 3.9+](https://www.python.org/downloads/)
* [Azure Functions Core Tools](https://learn.microsoft.com/azure/azure-functions/functions-run-local)
* [VS Code](https://code.visualstudio.com/) + Azure Functions extension
* An Azure subscription (for deployment)

## Local Setup

1. **Clone** this repo:

   ```bash
   git clone <repo-url> && cd <repo-dir>
   ```
2. **Install** Python dependencies:

   ```bash
   pip install -r requirements.txt
   ```
3. **Configure** local settings (copy sample and fill storage/key):

   ```bash
   cp local.settings.json.sample local.settings.json
   # Edit AzureWebJobsStorage and FUNCTIONS_WORKER_RUNTIME
   ```
4. **Run locally**:

   ```bash
   func host start
   ```

## Testing

### Raw mode

```powershell
curl.exe -X POST "http://localhost:7071/api/run?timeout_s=5" \
  -H "Content-Type: text/plain" \
  --data-binary @"path/to/script.py"   
```

### JSON mode

```powershell
curl.exe -X POST "http://localhost:7071/api/run" \
  -H "Content-Type: application/json" \
  -d '{ "script": "print(\"Hello\")\n", "timeout_s": 5 }'
```

## Deployment

1. Open in VS Code and sign in to Azure.
2. Run `Azure Functions: Deploy to Function App`.
3. Confirm your Function App and wait for deployment.

## Usage

* **Endpoint**: `https://<your-app>.azurewebsites.net/api/run`
* **Raw**: `Content-Type: text/plain`, `?timeout_s=<N>`
* **JSON**: `Content-Type: application/json`, body `{ script, timeout_s }`

Responses:

```json
{
  "exit_code": 0,
  "stdout": "…",
  "stderr": "…"
}
```

## Limits & Notes

* Timeout ≤ 300 s (longer values clamped)
* Script ≤ 256 KiB UTF‑8 bytes
* Not hardened for untrusted code; use only in trusted scenarios.

---

Licensed under MIT.
