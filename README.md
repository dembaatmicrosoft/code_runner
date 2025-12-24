# CodeRunner

![CodeRunner](docs/images/architecture.png)

A Python execution API designed for AI agents.

One endpoint. JSON in, JSON out. Deploy to Azure in one click.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fdembaatmicrosoft%2Fcode_runner%2Fmain%2Finfra%2Fazuredeploy.json)

## The Contract

```
POST /api/run
```

```json
{"script": "print(2 + 2)"}
```

```json
{"exit_code": 0, "stdout": "4\n", "stderr": "", "artifacts": {}}
```

That's it. An LLM reading this understands immediately.

## Why CodeRunner

AI agents need to run code. Most execution APIs weren't designed with agents in mind - they require complex authentication flows, return unstructured output, or demand configuration that adds cognitive load to the agent.

CodeRunner's API mirrors the tool-call patterns LLMs see in training data. The request/response contract is predictable: structured JSON in, structured JSON out. No parsing stdout for structure, no special error formats to learn. An agent can use this API without fighting its own intuitions.

## What You Get

- **Pre-installed packages** - numpy, pandas, scipy, scikit-learn, matplotlib, requests ready to use
- **File support** - Send files as base64, receive generated artifacts the same way
- **Multi-file projects** - Not just scripts; full project structures with imports
- **On-demand dependencies** - Request any PyPI package with binary wheels
- **Timeout control** - Up to 300 seconds per execution
- **Zero configuration** - One-click Azure deployment, runs on free tier

## Quick Start

**After deploying**, test with curl:

```bash
curl -X POST "https://<your-app>.azurewebsites.net/api/run" \
  -H "Content-Type: application/json" \
  -d '{"script": "print(1 + 1)"}'
```

**From Python** (how an agent might call it):

```python
import requests

response = requests.post(
    "https://<your-app>.azurewebsites.net/api/run",
    json={
        "script": "import pandas as pd; print(pd.__version__)"
    }
)
result = response.json()
print(result["stdout"])  # "2.0.0\n"
```

**With files** (agent generating a chart):

```python
response = requests.post(
    "https://<your-app>.azurewebsites.net/api/run",
    json={
        "script": """
import matplotlib.pyplot as plt
plt.plot([1, 2, 3], [1, 4, 9])
plt.savefig('./output/chart.png')
print('done')
""",
        "timeout_s": 30
    }
)
result = response.json()
chart_base64 = result["artifacts"]["chart.png"]["content"]
```

## Request Formats

### Script Mode

For inline code with optional input files:

```json
{
  "script": "import json\nwith open('./input/data.json') as f:\n    print(json.load(f))",
  "timeout_s": 30,
  "dependencies": ["requests"],
  "context": {
    "data.json": "{\"key\": \"value\"}"
  }
}
```

Context files go to `./input/`. Write output to `./output/` to return artifacts.

### Files Mode

For multi-file projects:

```json
{
  "files": {
    "main.py": "from utils import process\nprocess()",
    "utils.py": "def process():\n    print('hello')",
    "data.csv": "a,b\n1,2"
  },
  "entry_point": "main.py",
  "timeout_s": 60
}
```

All files at execution root. Imports work naturally.

### Binary Files

Base64 encoding for images, data files, or any binary content:

```json
{
  "script": "from PIL import Image\nimg = Image.open('./input/photo.png')\nprint(img.size)",
  "context": {
    "photo.png": {
      "content": "iVBORw0KGgoAAAANSUhEUgAA...",
      "encoding": "base64"
    }
  }
}
```

Artifacts return in the same format:

```json
{
  "artifacts": {
    "output.png": {
      "content": "iVBORw0KGgoAAAANSUhEUgAA...",
      "encoding": "base64"
    }
  }
}
```

## Response Format

Every response follows the same structure:

```json
{
  "exit_code": 0,
  "stdout": "...",
  "stderr": "...",
  "artifacts": {}
}
```

| Field | Description |
|-------|-------------|
| `exit_code` | 0 = success, 1+ = script error, 124 = timeout |
| `stdout` | Script's standard output |
| `stderr` | Script's standard error |
| `artifacts` | Files written to `./output/`, text or base64-encoded |

## Limits

| Resource | Limit |
|----------|-------|
| Timeout | 300 seconds max |
| Script size | 256 KB |
| Context/artifacts | 10 MB total |
| Single file | 5 MB |
| Dependencies | 15 packages |

## Pre-installed Packages

Available with zero latency:

**Data Science**: numpy, pandas, scipy, scikit-learn, matplotlib
**Web**: requests, httpx, beautifulsoup4
**Formats**: pyyaml, toml, python-dateutil
**Utilities**: tqdm, pillow

Other packages install on-demand (~2-5s).

## Local Development

```bash
git clone https://github.com/dembaatmicrosoft/code_runner.git
cd code_runner
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
func start
```

Available at `http://localhost:7071/api/run`

## Deployment Options

<details>
<summary>Azure Developer CLI</summary>

```bash
azd auth login
azd up
```

</details>

<details>
<summary>Azure CLI</summary>

```bash
az group create --name coderunner-rg --location eastus
az functionapp create \
  --name my-coderunner \
  --resource-group coderunner-rg \
  --consumption-plan-location eastus \
  --runtime python \
  --runtime-version 3.11 \
  --functions-version 4 \
  --os-type Linux
func azure functionapp publish my-coderunner
```

</details>

## Security

CodeRunner follows security best practices for code execution:

- Process isolation with clean environment
- Timeout enforcement with process tree cleanup
- Path traversal prevention on file operations
- Size limits on all inputs and outputs
- Audit logging with request tracing

See [SECURITY.md](SECURITY.md) for details and deployment recommendations.

## Contributing

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT - see [LICENSE](LICENSE).
