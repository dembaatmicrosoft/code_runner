# CodeRunner

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fdembaatmicrosoft%2Fcode_runner%2Fmain%2Finfra%2Fazuredeploy.json)

![CodeRunner](code_runner_app_lite.png)

A blazing-fast serverless Python execution API. One-click deploy to Azure, zero configuration required.

## Overview

CodeRunner provides a simple HTTP API for running Python code on-demand. It supports:

- **Script execution** with configurable timeout (up to 300 seconds)
- **Context files** for providing input data to scripts
- **Artifacts** for collecting output files from scripts
- **Binary support** with automatic base64 encoding detection

## Quick Start

### Prerequisites

- [Python 3.10+](https://www.python.org/downloads/)
- [Azure Functions Core Tools v4](https://learn.microsoft.com/azure/azure-functions/functions-run-local)

### Local Development

```bash
# Clone the repository
git clone <repository-url>
cd code_runner

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run locally
func start
```

The function will be available at `http://localhost:7071/api/run`

### Run Tests

```bash
pip install pytest
pytest test_function_app.py -v
```

## API Reference

### Endpoint

```
POST /api/run
```

### Request Formats

**JSON mode** (`Content-Type: application/json`):

```json
{
  "script": "print('Hello, World!')",
  "timeout_s": 30,
  "context": {
    "data.csv": "col1,col2\n1,2",
    "image.png": {"content": "<base64>", "encoding": "base64"}
  }
}
```

**Raw mode** (`Content-Type: text/plain`):

- Body: Python script text
- Query parameter: `?timeout_s=30`

### Response Format

```json
{
  "exit_code": 0,
  "stdout": "Hello, World!\n",
  "stderr": "",
  "artifacts": {
    "result.csv": "output,data\n1,2",
    "plot.png": {"content": "<base64>", "encoding": "base64"}
  }
}
```

### Context Files

Scripts can read input files from the `./input/` directory:

```python
with open("./input/data.csv") as f:
    data = f.read()
```

### Artifacts

Scripts can write output files to the `./output/` directory:

```python
import os
os.makedirs("./output", exist_ok=True)
with open("./output/result.csv", "w") as f:
    f.write("output,data\n1,2")
```

### Exit Codes

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
| Timeout | 300 seconds (max) |
| Script size | 256 KiB |
| Context files | 20 files |
| Single file | 5 MB |
| Total context | 10 MB |
| Total artifacts | 10 MB |
| Memory | ~1.5 GB |

## Deployment

### One-Click Deployment

Click the button below to deploy CodeRunner to your Azure subscription:

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fdembaatmicrosoft%2Fcode_runner%2Fmain%2Finfra%2Fazuredeploy.json)

**That's it!** No CLI tools, no additional steps. The deployment will:
1. Create all required resources (Storage, Function App, monitoring)
2. Deploy the code automatically
3. Show you the API endpoint when complete

Your API will be ready at: `https://<function-app-name>.azurewebsites.net/api/run`

**Cost**: $0/month within Azure Functions free tier (1M executions/month free)

### Alternative Deployment Options

<details>
<summary>Azure Developer CLI</summary>

```bash
# Install Azure Developer CLI
curl -fsSL https://aka.ms/install-azd.sh | bash

# Login and deploy
azd auth login
azd up
```

</details>

<details>
<summary>Azure Functions Core Tools</summary>

```bash
func azure functionapp publish <your-function-app-name> --python
```

</details>

<details>
<summary>Azure CLI (Manual)</summary>

```bash
# Create resources
az group create --name <resource-group> --location <location>
az storage account create --name <storage-name> --resource-group <resource-group>
az functionapp create \
  --name <app-name> \
  --resource-group <resource-group> \
  --storage-account <storage-name> \
  --consumption-plan-location <location> \
  --runtime python \
  --runtime-version 3.11 \
  --functions-version 4 \
  --os-type Linux

# Deploy code
func azure functionapp publish <app-name> --python
```

</details>

### Managing Your Deployment

```bash
# View logs
az functionapp log tail --name <function-app-name> --resource-group <resource-group>

# Restart function app
az functionapp restart --name <function-app-name> --resource-group <resource-group>

# Delete all resources
az group delete --name <resource-group>
```

## Security

This function executes arbitrary code and is intended for **trusted environments only**. See [SECURITY.md](SECURITY.md) for:

- Security considerations and limitations
- Recommended deployment practices
- How to report security issues

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for:

- Code of Conduct
- Development setup
- Coding standards
- Pull request process

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft trademarks or logos is subject to and must follow [Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general). Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
