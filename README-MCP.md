# malhaus MCP Server

malhaus exposes a [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server so that AI agents — Claude, Cursor, Continue, and any other MCP-compatible client — can submit files or URLs for triage and reason over the results natively, without leaving the agent session.

A live instance is available at **https://grothendieck.ff2.nl** — you can point an MCP client there to try it before deploying your own.

> **Implementation note:** The MCP server and its OAuth 2.0 layer are built on top of the REST API described in `README-API.md`. Set up the REST API first.

---

## How it works

The agent has access to a single tool: **`analyze`**.

- The agent calls `analyze` with a file path or URL
- The MCP server submits to the REST API, polls internally until done, and returns the full structured result to the agent
- The agent reasons over verdict, reasons, tool outputs, and optionally images or the PCA 2D projection
- Every submission appears in the malhaus web index at `/report/<sha256>` like any other report

The agent decides what to do with the result — it is not prompted or steered by the server.

---

## Authentication — OAuth 2.0 client credentials

Remote MCP uses **OAuth 2.0 `client_credentials` grant** (machine-to-machine). This is the same key store as the REST API, wrapped in a standard token exchange.

### Creating credentials (server-side, admin only)

```bash
python manage_keys.py create --label "Claude Desktop — Alice" --rate-limit 60
```

This prints a `mh_` token. That token is your **client secret**. The `key_id` is your **client ID**.

```
  Token  : mh_<your-64-hex-token>
  Key ID : 227e520f-6020-498a-9954-c48c461b3a33
```

Keep both values — you will need them to configure each MCP client.

### Token exchange endpoint

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_id=227e520f-6020-498a-9954-c48c461b3a33
&client_secret=mh_<your-64-hex-token>
```

Response:

```json
{
  "access_token": "<short-lived JWT or opaque token>",
  "token_type":   "Bearer",
  "expires_in":   3600
}
```

MCP clients that support OAuth handle this exchange automatically — you only provide the `client_id` and `client_secret` in the client config.

### Revoking credentials

```bash
python manage_keys.py revoke 227e520f-6020-498a-9954-c48c461b3a33
```

Takes effect immediately on the next request.

---

## Sending local files to the MCP tool

MCP tool parameters are JSON — there is no binary streaming in the protocol. The `analyze` tool therefore accepts three input modes:

| Mode | When to use |
|------|-------------|
| `url` | File is reachable via HTTP/HTTPS — the server downloads it. Simplest. |
| `file_path` | File already exists on the malhaus server's filesystem. |
| `file_id` | File is local to the agent's machine. Upload first, then analyze. |

For the `file_id` pattern the agent makes two calls:

```
1. POST https://<your-domain>/api/v1/upload   (multipart, Bearer token)
   → {"file_id": "abc-123", "expires_in": 3600}

2. analyze(file_id="abc-123")                        (MCP tool call, JSON)
   → verdict, reasons, tool outputs
```

The staged file is consumed on first use and expires after 1 hour if unused.

See [`api_examples/mcp_analyze_file.sh`](api_examples/mcp_analyze_file.sh) and [`api_examples/analyze_file.py`](api_examples/analyze_file.py) for working examples of this pattern.

---

## The `analyze` tool

### Input schema

```json
{
  "name": "analyze",
  "description": "Submit a file or URL to the malhaus malware triage pipeline. Returns verdict, confidence, reasoning, and detailed tool outputs. Optionally includes entropy/bigram/compression images and a PCA 2D projection of the byte trigram cloud.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "file_path": {
        "type": "string",
        "description": "Absolute path to a local file to analyze"
      },
      "url": {
        "type": "string",
        "description": "HTTP/HTTPS URL to download and analyze"
      },
      "file_id": {
        "type": "string",
        "description": "ID returned by POST /api/v1/upload — use when the agent has a local file. Upload the file first via the REST upload endpoint, then pass the file_id here. Expires after 1 hour."
      },
      "use_ghidra": {
        "type": "boolean",
        "description": "Run Ghidra headless analysis (slower, deeper — PE/ELF only)",
        "default": false
      },
      "archive_password": {
        "type": "string",
        "description": "Password for encrypted ZIP/RAR archives"
      },
      "include_images": {
        "type": "boolean",
        "description": "Include entropy profile, compression curve, and bigram matrix images",
        "default": false
      },
      "include_takens2d": {
        "type": "boolean",
        "description": "Include PCA 2D projection of the byte trigram point cloud",
        "default": false
      }
    },
    "oneOf": [
      { "required": ["file_path"] },
      { "required": ["url"] },
      { "required": ["file_id"] }
    ]
  }
}
```

### Output — always returned

```json
{
  "sha256":   "e3b0c442...",
  "report_url": "http://your-server/report/e3b0c442...",
  "verdict": {
    "risk_level": "likely_malware",
    "confidence": 92,
    "file_type":  "PE32 executable"
  },
  "heuristic_score": 74,
  "top_reasons": [
    "High entropy sections consistent with packing",
    "Imports VirtualAlloc, WriteProcessMemory",
    "No valid authenticode signature"
  ],
  "tools_used": ["mandatory_authenticode_verify", "mandatory_objdump_pe_headers", "..."],
  "tool_outputs": {
    "mandatory_objdump_pe_headers": {
      "stdout": "...",
      "stderr": "",
      "error": null
    }
  }
}
```

### Output — with `include_images: true`

Adds an `images` object with base64 PNG + interpretation for:
- `entropy_profile` — Shannon entropy per 256-byte block across the file
- `compression_curve` — Kolmogorov complexity approximation (zlib/bz2/lzma)
- `bigram_matrix` — 256×256 byte transition heatmap (log scale)

### Output — with `include_takens2d: true`

Adds `takens2d`:
- `b64` — PCA 2D projection of the byte trigram (ℝ³) point cloud, rendered as PNG
- `interpretation` — text description of the scatter pattern

---

## Configuring MCP clients

Replace `YOUR_SERVER` with your malhaus hostname (e.g. `https://malhaus.example.com`), `YOUR_CLIENT_ID` with the `key_id`, and `YOUR_CLIENT_SECRET` with the `mh_` token.

---

### Claude Desktop

Config file location:
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "malhaus": {
      "transport": "sse",
      "url": "YOUR_SERVER/mcp/sse",
      "oauth": {
        "clientId":     "YOUR_CLIENT_ID",
        "clientSecret": "YOUR_CLIENT_SECRET",
        "tokenUrl":     "YOUR_SERVER/oauth/token",
        "grantType":    "client_credentials"
      }
    }
  }
}
```

After saving, restart Claude Desktop. You will see **malhaus** in the tools panel. Ask Claude:

> "Analyze the file at /tmp/suspicious.exe and tell me if it's malware."
> "Submit https://example.com/payload.bin to malhaus and summarize the findings."

---

### Claude Code (CLI)

**One-time setup:**

```bash
claude mcp add malhaus \
  --transport sse \
  --url YOUR_SERVER/mcp/sse \
  --oauth-client-id YOUR_CLIENT_ID \
  --oauth-client-secret YOUR_CLIENT_SECRET \
  --oauth-token-url YOUR_SERVER/oauth/token
```

Or manually in `.claude/settings.json` (project) or `~/.claude/settings.json` (global):

```json
{
  "mcpServers": {
    "malhaus": {
      "transport": "sse",
      "url": "YOUR_SERVER/mcp/sse",
      "oauth": {
        "clientId":     "YOUR_CLIENT_ID",
        "clientSecret": "YOUR_CLIENT_SECRET",
        "tokenUrl":     "YOUR_SERVER/oauth/token",
        "grantType":    "client_credentials"
      }
    }
  }
}
```

**Usage in a Claude Code session:**

```
/mcp maltriage analyze file_path=/tmp/ransomware.exe include_images=true
```

Or just talk to Claude naturally — it will call the tool when needed:

> "Use malhaus to analyze this file: /home/user/downloads/invoice.doc"

---

### Cursor

In Cursor settings → MCP, or directly in `~/.cursor/mcp.json`:

```json
{
  "servers": {
    "malhaus": {
      "transport": "sse",
      "url": "YOUR_SERVER/mcp/sse",
      "auth": {
        "type":         "oauth2",
        "clientId":     "YOUR_CLIENT_ID",
        "clientSecret": "YOUR_CLIENT_SECRET",
        "tokenUrl":     "YOUR_SERVER/oauth/token",
        "grantType":    "client_credentials"
      }
    }
  }
}
```

Cursor will use the `analyze` tool automatically when you ask the agent to examine a suspicious file.

---

### Continue (VS Code / JetBrains)

In `~/.continue/config.json`:

```json
{
  "experimental": {
    "modelContextProtocolServers": [
      {
        "transport": {
          "type": "sse",
          "url":  "YOUR_SERVER/mcp/sse"
        },
        "auth": {
          "type":         "oauth2",
          "clientId":     "YOUR_CLIENT_ID",
          "clientSecret": "YOUR_CLIENT_SECRET",
          "tokenUrl":     "YOUR_SERVER/oauth/token"
        }
      }
    ]
  }
}
```

---

### GitHub Copilot in VS Code

Create `.vscode/mcp.json` in your workspace (or add to user `settings.json` under `mcp.servers`):

```json
{
  "servers": {
    "malhaus": {
      "type": "sse",
      "url": "YOUR_SERVER/mcp/sse",
      "auth": {
        "type":         "oauth2",
        "clientId":     "YOUR_CLIENT_ID",
        "clientSecret": "YOUR_CLIENT_SECRET",
        "tokenUrl":     "YOUR_SERVER/oauth/token",
        "grantType":    "client_credentials"
      }
    }
  }
}
```

Commit `.vscode/mcp.json` to share the server config with your team — each developer supplies their own credentials via environment variables rather than plaintext:

```json
"clientSecret": "${env:MALTRIAGE_CLIENT_SECRET}"
```

After VS Code reloads, switch Copilot Chat to **Agent** mode and ask:

> "Use malhaus to analyze `/tmp/suspicious.exe` and explain what it does."

---

### Azure AI Foundry Agent Service

Azure AI Foundry agents support external MCP servers as tool sources via the **Azure AI Projects SDK**:

```python
import os
import requests as http_req
from azure.ai.projects import AIProjectClient
from azure.ai.projects.models import McpTool
from azure.identity import DefaultAzureCredential

# Connect to your Azure AI Foundry project
client = AIProjectClient.from_connection_string(
    conn_str=os.environ["AIPROJECT_CONNECTION_STRING"],
    credential=DefaultAzureCredential(),
)

# Acquire a malhaus access token
def get_access_token() -> str:
    resp = http_req.post(
        "YOUR_SERVER/oauth/token",
        data={
            "grant_type":    "client_credentials",
            "client_id":     os.environ["MALTRIAGE_CLIENT_ID"],
            "client_secret": os.environ["MALTRIAGE_CLIENT_SECRET"],
        },
    )
    resp.raise_for_status()
    return resp.json()["access_token"]

# Create an agent with maltriage wired in as an MCP tool
agent = client.agents.create_agent(
    model="gpt-4o",
    name="malware-triage-agent",
    instructions=(
        "You are a malware analyst. When given a file path or URL, "
        "use the maltriage analyze tool and summarise the findings clearly."
    ),
    tools=[
        McpTool(
            server_url="YOUR_SERVER/mcp/sse",
            server_label="malhaus",
            allowed_tools=["analyze"],
            headers={"Authorization": f"Bearer {get_access_token()}"},
        )
    ],
)

# Run a conversation thread
thread = client.agents.create_thread()
client.agents.create_message(
    thread_id=thread.id,
    role="user",
    content="Analyze https://example.com/payload.exe and tell me if it is malware.",
)
run = client.agents.create_and_process_run(
    thread_id=thread.id,
    agent_id=agent.id,
)
messages = client.agents.list_messages(thread_id=thread.id)
print(messages.get_last_text_message_by_role("assistant").text.value)
```

**Store credentials in Azure Key Vault** (recommended):

```python
from azure.keyvault.secrets import SecretClient

kv = SecretClient(
    vault_url=f"https://{os.environ['KEYVAULT_NAME']}.vault.azure.net",
    credential=DefaultAzureCredential(),
)
client_id     = kv.get_secret("malhaus-client-id").value
client_secret = kv.get_secret("malhaus-client-secret").value
```

You can also configure the MCP server via the **Foundry portal**: Agents → Tools → Add tool → MCP server → enter your SSE URL and `Authorization` header.

---

### Semantic Kernel (Python)

Semantic Kernel's MCP connector wraps any MCP SSE server as a native SK plugin:

```python
import asyncio, os
import requests as http_req
from semantic_kernel import Kernel
from semantic_kernel.connectors.mcp import MCPSsePlugin
from semantic_kernel.connectors.ai.open_ai import AzureChatCompletion
from semantic_kernel.connectors.ai.function_choice_behavior import FunctionChoiceBehavior
from semantic_kernel.contents import ChatHistory

def get_access_token() -> str:
    resp = http_req.post(
        "YOUR_SERVER/oauth/token",
        data={
            "grant_type":    "client_credentials",
            "client_id":     os.environ["MALTRIAGE_CLIENT_ID"],
            "client_secret": os.environ["MALTRIAGE_CLIENT_SECRET"],
        },
    )
    resp.raise_for_status()
    return resp.json()["access_token"]

async def main():
    kernel = Kernel()
    kernel.add_service(
        AzureChatCompletion(
            deployment_name=os.environ["AZURE_OPENAI_DEPLOYMENT"],
            endpoint=os.environ["AZURE_OPENAI_ENDPOINT"],
            api_key=os.environ["AZURE_OPENAI_API_KEY"],
        )
    )

    async with MCPSsePlugin(
        name="malhaus",
        url="YOUR_SERVER/mcp/sse",
        headers={"Authorization": f"Bearer {get_access_token()}"},
    ) as mcp_plugin:
        kernel.add_plugin(mcp_plugin)

        chat = ChatHistory()
        chat.add_user_message(
            "Use malhaus to analyze /tmp/suspicious.exe and explain what it does."
        )
        response = await kernel.invoke_prompt(
            prompt="{{$history}}",
            arguments={"history": chat},
            function_choice_behavior=FunctionChoiceBehavior.Auto(),
        )
        print(response)

asyncio.run(main())
```

```bash
pip install semantic-kernel azure-identity azure-keyvault-secrets
```

---

### Azure Functions (Python) — automated triage on blob upload

This pattern triggers triage automatically whenever a file lands in an Azure Blob Storage container, then writes the result to a second container and optionally sends an alert.

```python
# function_app.py
import json, logging, os, time
import azure.functions as func
import requests as http_req

app = func.FunctionApp()

MALTRIAGE_HOST   = os.environ["MALTRIAGE_HOST"]          # e.g. https://malhaus.example.com
MALTRIAGE_ID     = os.environ["MALTRIAGE_CLIENT_ID"]
MALTRIAGE_SECRET = os.environ["MALTRIAGE_CLIENT_SECRET"]
POLL_INTERVAL    = 8    # seconds between status checks
POLL_TIMEOUT     = 300  # give up after 5 minutes


def _get_token() -> str:
    resp = http_req.post(
        f"{MALTRIAGE_HOST}/oauth/token",
        data={
            "grant_type":    "client_credentials",
            "client_id":     MALTRIAGE_ID,
            "client_secret": MALTRIAGE_SECRET,
        },
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def _submit_url(url: str, token: str) -> str:
    resp = http_req.post(
        f"{MALTRIAGE_HOST}/api/v1/analyze",
        headers={"Authorization": f"Bearer {token}"},
        json={"url": url},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["job_id"]


def _poll(job_id: str, token: str, include: str = "") -> dict:
    deadline = time.time() + POLL_TIMEOUT
    params   = {"include": include} if include else {}
    while time.time() < deadline:
        r = http_req.get(
            f"{MALTRIAGE_HOST}/api/v1/jobs/{job_id}",
            headers={"Authorization": f"Bearer {token}"},
            params=params,
            timeout=15,
        )
        r.raise_for_status()
        data = r.json()
        if data["status"] == "done":
            return data
        if data["status"] == "failed":
            raise RuntimeError(data.get("error", "analysis failed"))
        time.sleep(POLL_INTERVAL)
    raise TimeoutError(f"Job {job_id} did not complete within {POLL_TIMEOUT}s")


@app.blob_trigger(
    arg_name="blob",
    path="samples-incoming/{name}",
    connection="AzureWebJobsStorage",
)
@app.blob_output(
    arg_name="report",
    path="triage-reports/{name}.json",
    connection="AzureWebJobsStorage",
)
def triage_on_upload(blob: func.InputStream, report: func.Out[str]):
    """Triggered when a file is dropped in the samples-incoming container."""
    logging.info("Triaging: %s (%d bytes)", blob.name, blob.length)

    # Build a SAS URL or use a pre-signed URL — malhaus downloads it directly
    # Here we assume blob is publicly readable or you generate a SAS URL externally
    blob_url = os.environ.get("BLOB_SAS_URL_TEMPLATE", "").format(name=blob.name)
    if not blob_url:
        raise ValueError("BLOB_SAS_URL_TEMPLATE not configured")

    token  = _get_token()
    job_id = _submit_url(blob_url, token)
    logging.info("Job submitted: %s", job_id)

    result = _poll(job_id, token, include="images")
    logging.info(
        "Done: %s — risk=%s confidence=%s",
        blob.name, result["verdict"]["risk_level"], result["verdict"]["confidence"],
    )

    # Write structured report to output container
    report.set(json.dumps(result, indent=2))

    # Optional: alert on high-risk findings via Teams webhook
    risk = result["verdict"]["risk_level"]
    if risk in ("likely_malware", "suspicious"):
        webhook = os.environ.get("TEAMS_WEBHOOK_URL")
        if webhook:
            http_req.post(webhook, json={
                "text": (
                    f"⚠️ **{risk.upper()}** detected\n"
                    f"File: `{blob.name}`\n"
                    f"Confidence: {result['verdict']['confidence']}%\n"
                    f"Report: {MALTRIAGE_HOST}{result['report_url']}\n\n"
                    + "\n".join(f"- {r}" for r in result["top_reasons"])
                )
            }, timeout=10)
```

**`host.json`**
```json
{ "version": "2.0", "logging": { "logLevel": { "default": "Information" } } }
```

**`requirements.txt`**
```
azure-functions
requests
```

**Deploy:**
```bash
func azure functionapp publish <YOUR_FUNCTION_APP_NAME>

# Required app settings
az functionapp config appsettings set \
  --name <YOUR_FUNCTION_APP_NAME> \
  --resource-group <RG> \
  --settings \
    MALTRIAGE_HOST="https://malhaus.example.com" \
    MALTRIAGE_CLIENT_ID="227e520f-..." \
    MALTRIAGE_CLIENT_SECRET="@Microsoft.KeyVault(SecretUri=https://...)" \
    TEAMS_WEBHOOK_URL="https://..."
```

Note: `@Microsoft.KeyVault(...)` syntax pulls the secret from Key Vault at runtime — the function never sees it in plaintext.

---

### Azure Logic Apps — no-code triage pipeline

Logic Apps lets you wire malhaus triage into broader workflows (SIEM, ticketing, email) without writing code.

**Workflow: HTTP trigger → analyze → wait for result → notify**

Below is the key Actions section of the Logic App ARM definition. Import it via the Logic Apps Designer or deploy with `az deployment group create`.

```json
{
  "actions": {

    "Submit_to_malhaus": {
      "type": "Http",
      "inputs": {
        "method": "POST",
        "uri":    "YOUR_SERVER/api/v1/analyze",
        "headers": {
          "Authorization": "Bearer @{variables('MalthausToken')}",
          "Content-Type":  "application/json"
        },
        "body": {
          "url": "@triggerBody()?['file_url']"
        }
      }
    },

    "Extract_job_id": {
      "type": "ParseJson",
      "inputs": {
        "content": "@body('Submit_to_malhaus')",
        "schema": {
          "type": "object",
          "properties": {
            "job_id":     { "type": "string" },
            "status_url": { "type": "string" }
          }
        }
      },
      "runAfter": { "Submit_to_malhaus": ["Succeeded"] }
    },

    "Poll_until_done": {
      "type": "Until",
      "expression": "@not(equals(variables('JobStatus'), 'running'))",
      "limit": { "count": 60, "timeout": "PT10M" },
      "actions": {
        "Check_job": {
          "type": "Http",
          "inputs": {
            "method": "GET",
            "uri": "YOUR_SERVER/api/v1/jobs/@{body('Extract_job_id')?['job_id']}?include=images",
            "headers": { "Authorization": "Bearer @{variables('MalthausToken')}" }
          }
        },
        "Set_status": {
          "type": "SetVariable",
          "inputs": {
            "name":  "JobStatus",
            "value": "@body('Check_job')?['status']"
          },
          "runAfter": { "Check_job": ["Succeeded"] }
        },
        "Wait_before_retry": {
          "type": "Wait",
          "inputs": { "interval": { "count": 10, "unit": "Second" } },
          "runAfter": { "Set_status": ["Succeeded"] }
        }
      },
      "runAfter": { "Extract_job_id": ["Succeeded"] }
    },

    "Parse_result": {
      "type": "ParseJson",
      "inputs": {
        "content": "@body('Check_job')",
        "schema": {
          "type": "object",
          "properties": {
            "verdict":    { "type": "object" },
            "top_reasons":{ "type": "array", "items": { "type": "string" } },
            "report_url": { "type": "string" }
          }
        }
      },
      "runAfter": { "Poll_until_done": ["Succeeded"] }
    },

    "Notify_Teams": {
      "type": "Http",
      "inputs": {
        "method": "POST",
        "uri":    "@parameters('TeamsWebhookUrl')",
        "headers": { "Content-Type": "application/json" },
        "body": {
          "text": "Triage result: **@{body('Parse_result')?['verdict']?['risk_level']}** — @{body('Parse_result')?['report_url']}"
        }
      },
      "runAfter": { "Parse_result": ["Succeeded"] }
    }

  }
}
```

**Token initialisation step** — add a preceding action to fetch the OAuth token before `Submit_to_malhaus`:

```json
"Get_maltriage_token": {
  "type": "Http",
  "inputs": {
    "method": "POST",
    "uri":    "YOUR_SERVER/oauth/token",
    "headers": { "Content-Type": "application/x-www-form-urlencoded" },
    "body":    "grant_type=client_credentials&client_id=@{parameters('MalthausClientId')}&client_secret=@{parameters('MalthausClientSecret')}"
  }
}
```

Store `MalthausClientSecret` as a **Logic App parameter backed by Key Vault** — never hardcode it in the workflow definition.

**Typical trigger options:**
- **HTTP Request** — call from a SIEM, SOAR, or email rule
- **Azure Blob Storage — When a blob is added** — automatic triage on upload
- **Recurrence** — scheduled batch triage of a watchlist of URLs

---

### Any MCP client — manual OAuth token

If your client does not support OAuth natively, obtain a token manually and pass it as a Bearer header:

```bash
# Exchange credentials for an access token
TOKEN=$(curl -s -X POST YOUR_SERVER/oauth/token \
  -d "grant_type=client_credentials" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Connect to the MCP SSE endpoint
curl -H "Authorization: Bearer $TOKEN" \
     -H "Accept: text/event-stream" \
     YOUR_SERVER/mcp/sse
```

---

## Example agent sessions

### Basic triage

**User:** Use malhaus to check `/tmp/invoice.exe`. Is it safe to open?

**Agent (calls `analyze`):**
```json
{ "file_path": "/tmp/invoice.exe" }
```

**Agent (after result):**
> The file is classified as **likely_malware** with 89% confidence. The triage engine found:
> - Packed with UPX (high-entropy sections)
> - Imports `CreateRemoteThread` and `VirtualAllocEx` — classic process injection
> - No valid digital signature
>
> Do not open this file. Full report: http://malhaus.local/report/e3b0c4…

---

### Deep analysis with images

**User:** Analyze this sample and show me the entropy graph. I want to understand the structure.

**Agent (calls `analyze`):**
```json
{
  "file_path": "/tmp/sample.bin",
  "include_images": true,
  "include_takens2d": true
}
```

**Agent (after result):**
> The entropy profile shows a flat red plateau from offset 0x1000 to 0x8000 — entropy ≥ 7.5 bits/byte, consistent with an AES-encrypted payload. The first section (0x0–0x1000) has normal structured-code entropy, which is the loader stub. The PCA 2D projection is nearly isotropic — no clustering — confirming the encrypted region dominates the byte statistics.

---

### Batch triage in a security workflow

**User:** I have three samples in `/tmp/samples/`. Check all of them and give me a risk summary table.

**Agent:** *(calls `analyze` three times in sequence, then synthesizes)*

| File           | Risk           | Confidence | Key reason                        |
|----------------|----------------|------------|-----------------------------------|
| dropper.exe    | likely_malware | 94%        | Process injection imports, packed |
| document.docx  | suspicious     | 61%        | Macro present, external OLE links |
| installer.msi  | benign         | 88%        | Signed, no suspicious imports     |

---

## Security notes

- MCP credentials (`client_id` + `client_secret`) should be stored in your client's secret store, not in plaintext config files checked into source control
- Access tokens are short-lived (1 hour); the client handles renewal automatically
- Revoke a credential immediately if a workstation is compromised: `python manage_keys.py revoke <key_id>`
- The MCP server runs on the same Flask process as the web app — no additional port needed
- File paths passed to `analyze` are resolved on the **server**, not the client; only submit paths that exist on the malhaus host, or use the `url` parameter for remote files
