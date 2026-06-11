# malhaus MCP Server

malhaus exposes a [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server so that AI
agents — Claude Code, Claude Desktop, Cursor, Continue, and any other MCP-compatible client — can
submit files or URLs for malware triage and reason over the results natively, without leaving the
agent session.

The MCP server runs on **port 8001** inside the same container as the web app. It uses the
**Streamable HTTP** transport. Nothing needs to be installed on the client machine — you only need
the server URL.

---

## Prerequisites

1. malhaus must be running (`docker compose up -d --build`)
2. You need an API key issued by the admin panel (Admin → API Keys → Create key)
3. The key must be set in `.env` as `MALHAUS_MCP_API_KEY` before the container starts

---

## Server setup (one-time)

```bash
# 1. Log in to the malhaus admin panel
#    Admin → API Keys → Create key
#    Label it e.g. "mcp-internal"
#    Copy the generated key — it looks like: mh_a3f9c2...

# 2. Open .env and fill in the placeholder that is already there
#    Find this line:
#      MALHAUS_MCP_API_KEY=mh_REPLACE_WITH_YOUR_KEY_FROM_ADMIN_PANEL
#    Replace the placeholder with the real key:
#      MALHAUS_MCP_API_KEY=mh_a3f9c2e1...
nano ~/malhaus/.env

# 3. Rebuild and restart the container
cd ~/malhaus
docker compose up --build -d

# 4. Verify the MCP server is up
curl http://localhost:8001/mcp
# Expected output: {"jsonrpc":"2.0","error":{"message":"Not Acceptable..."}}
# That error is normal — curl does not send the SSE Accept header.
# Any response at all means the server is running.
```

The key is used **only inside the container** — the MCP server uses it to submit jobs to the REST
API on your behalf. It is **not** exposed to MCP clients and never leaves the server.

---

## Available tools

| Tool | Parameters | What it does |
|------|------------|--------------|
| `analyze_file` | `file_b64` (required), `filename` (optional) | Analyze a file from base64-encoded content. The client reads the file and encodes it. |
| `analyze_url` | `url` (required) | Tell the server to download a file from an HTTP/HTTPS URL and analyze it. |
| `analyze_sha256` | `sha256` (required) | Retrieve a cached result for a previously analyzed file. Instant if found. |

All three tools return a plain-text summary:

```
Verdict: LIKELY_MALWARE  (confidence 91%)
File type: pe
SHA-256: 4d4a8de9f4...
Heuristic score: 74/100

Top reasons:
  - High entropy in .text section consistent with packing or encryption
  - Imports VirtualAllocEx and WriteProcessMemory (process injection pattern)
  - No valid Authenticode signature
  - Mutex name matches known AgentTesla variant

Full report: https://your-malhaus-instance.example.com/report/4d4a8de9f4...
```

---

## How file analysis works

### Analyzing a local file (on the client machine)

The MCP server runs on your server — it cannot access files on the machine where the AI agent is
running. When you ask the agent to analyze a local file, the **client** reads the file, encodes it
as base64, and passes the bytes to `analyze_file`. The server never touches your filesystem.

**Flow:**
```
Your machine has:  /home/analyst/samples/suspicious.exe   (Linux)
                   C:\Users\analyst\Downloads\invoice.exe  (Windows)

1. AI agent reads the file from disk
2. AI agent base64-encodes the raw bytes
3. AI agent calls analyze_file(file_b64="TVqQAAMA...", filename="suspicious.exe")
4. MCP server receives the bytes, writes a temp file, runs the full analysis pipeline
5. MCP server returns verdict + top reasons + report URL
```

### Analyzing a remote file (by URL)

When the file is already reachable over HTTP/HTTPS, the flow is simpler:

```
1. AI agent calls analyze_url(url="https://cdn.example.com/payload.ps1")
2. MCP server downloads the file from that URL
3. MCP server runs the full analysis pipeline
4. MCP server returns verdict + top reasons + report URL
```

### Checking a cached result

If you already know the SHA-256 of a file that was analyzed before, you can skip re-uploading:

```
1. AI agent calls analyze_sha256(sha256="4d4a8de9f4...")
2. If previously analyzed: instant cached result
3. If not found: message asking you to submit via analyze_file or analyze_url
```

---

## Client configuration

**MCP endpoint URL:**

| Setup | URL | Notes |
|-------|-----|-------|
| Docker + nginx (recommended) | `https://your-domain.com/mcp` | TLS, port 443, no extra ports needed |
| Direct / dev / no nginx | `http://your-server:8001/mcp` | Plain HTTP, port 8001 must be open |

With a standard Docker deployment nginx is already running and proxying `/mcp` to the internal port
8001. Clients connect to `https://your-domain.com/mcp` — same hostname and port as the web UI,
no firewall changes needed.

---

### Claude Code (CLI)

**One-time setup:**

```bash
# With nginx (recommended — same domain as the web UI, TLS)
claude mcp add --transport http malhaus https://your-domain.com/mcp

# Without nginx (direct, plain HTTP)
claude mcp add --transport http malhaus http://your-server:8001/mcp
```

Or add permanently to `~/.claude/settings.json` (global) or `.claude/settings.json` (project):

```json
{
  "mcpServers": {
    "malhaus": {
      "url": "https://your-domain.com/mcp"
    }
  }
}
```

**Usage — analyze a local file:**

```
You: Analyze /home/analyst/samples/suspicious.exe for malware
```

Claude will read `/home/analyst/samples/suspicious.exe` from the filesystem, base64-encode it, call
`analyze_file`, and explain the result.

```
You: Check if C:\Users\analyst\Downloads\invoice.exe is safe to open
```

Same flow on Windows — Claude reads the file from that path.

**Usage — analyze a remote URL:**

```
You: Use malhaus to check https://cdn.example.com/updater.ps1
```

Claude calls `analyze_url(url="https://cdn.example.com/updater.ps1")` — the server downloads and
analyzes it.

**Usage — check a cached result:**

```
You: Has malhaus already analyzed SHA-256 4d4a8de9f4c07e6b8b23c2a1e0f6d3a9...?
```

Claude calls `analyze_sha256` with the hash and returns the cached verdict if it exists.

**Usage — batch analysis:**

```
You: Analyze all .exe files in /home/analyst/samples/ and give me a risk summary table
```

Claude will call `analyze_file` for each file in sequence and build a results table.

---

### Claude Desktop

Config file location:
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "malhaus": {
      "url": "https://your-domain.com/mcp"
    }
  }
}
```

Restart Claude Desktop after saving. The **malhaus** tool will appear in the tools panel.

Example prompts after connecting:

```
Analyze /tmp/suspicious.exe and tell me if it is malware
Check https://example.com/payload.bin using malhaus and summarize the findings
Is the file at C:\malware\dropper.exe safe? Use malhaus to analyze it
```

---

### Cursor

In Cursor settings → MCP, or directly in `~/.cursor/mcp.json`:

```json
{
  "servers": {
    "malhaus": {
      "transport": "http",
      "url": "https://your-domain.com/mcp"
    }
  }
}
```

Example prompt in Cursor agent mode:

```
Use malhaus to analyze /home/user/projects/suspicious_lib.so before I import it
```

---

### Continue (VS Code / JetBrains)

In `~/.continue/config.json`:

```json
{
  "experimental": {
    "modelContextProtocolServers": [
      {
        "transport": {
          "type": "http",
          "url": "https://your-domain.com/mcp"
        }
      }
    ]
  }
}
```

---

### Python client (any platform)

Install the MCP library: `pip install mcp`

```python
#!/usr/bin/env python3
"""
malhaus MCP client — analyze files and URLs via the malhaus MCP server.

Usage:
  python malhaus_mcp.py file /home/analyst/samples/suspicious.exe
  python malhaus_mcp.py file C:\\Users\\analyst\\Downloads\\invoice.exe
  python malhaus_mcp.py url  https://cdn.example.com/payload.ps1
  python malhaus_mcp.py sha256 4d4a8de9f4c07e6b8b23c2a1e0f6d3a9...

Requirements:
  pip install mcp
"""
import asyncio
import base64
import os
import sys
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

# Set MALHAUS_MCP_URL env var or replace the default below
SERVER_URL = os.environ.get("MALHAUS_MCP_URL", "https://your-domain.com/mcp")


async def _call(tool: str, args: dict) -> str:
    async with streamablehttp_client(SERVER_URL) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(tool, args)
            return result.content[0].text


async def analyze_local_file(path: str) -> str:
    """
    Read a file from the local filesystem, base64-encode it,
    and submit it to the malhaus MCP server for analysis.

    The file is read on THIS machine (the client), not on the server.
    The server receives only the encoded bytes and the filename — it
    never accesses the client filesystem directly.

    Examples:
      await analyze_local_file("/home/analyst/samples/dropper.exe")
      await analyze_local_file("C:\\\\Users\\\\analyst\\\\Downloads\\\\invoice.doc")
      await analyze_local_file("/mnt/evidence/2024-01-15/payload.ps1")
    """
    with open(path, "rb") as fh:
        file_b64 = base64.b64encode(fh.read()).decode()
    filename = os.path.basename(path)
    print(f"[*] Submitting local file: {path} ({filename})", flush=True)
    return await _call("analyze_file", {"file_b64": file_b64, "filename": filename})


async def analyze_remote_url(url: str) -> str:
    """
    Tell the malhaus server to download the file at the given URL
    and analyze it. The server fetches the file — the client does not.

    Examples:
      await analyze_remote_url("https://cdn.example.com/updater.ps1")
      await analyze_remote_url("https://dl.malware-sample-db.com/eicar.com")
      await analyze_remote_url("http://192.168.1.100/share/suspicious.exe")
    """
    print(f"[*] Submitting URL: {url}", flush=True)
    return await _call("analyze_url", {"url": url})


async def check_sha256(sha256: str) -> str:
    """
    Retrieve a cached analysis result by SHA-256 hash.
    Returns instantly if the file was previously analyzed.

    Example:
      await check_sha256("4d4a8de9f4c07e6b8b23c2a1e0f6d3a9b5e2c8d1f7a0...")
    """
    print(f"[*] Checking cache for SHA-256: {sha256}", flush=True)
    return await _call("analyze_sha256", {"sha256": sha256})


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage:")
        print("  malhaus_mcp.py file   /path/to/local/file.exe")
        print("  malhaus_mcp.py url    https://example.com/remote-file.ps1")
        print("  malhaus_mcp.py sha256 4d4a8de9f4c07e6b...")
        sys.exit(1)

    mode, value = sys.argv[1], sys.argv[2]

    if mode == "file":
        print(asyncio.run(analyze_local_file(value)))
    elif mode == "url":
        print(asyncio.run(analyze_remote_url(value)))
    elif mode == "sha256":
        print(asyncio.run(check_sha256(value)))
    else:
        print(f"Unknown mode '{mode}'. Use: file, url, or sha256")
        sys.exit(1)
```

---

### OpenCode (terminal AI agent)

[OpenCode](https://opencode.ai) is an open-source terminal-based AI coding assistant that supports
MCP servers. Config file: `~/.config/opencode/config.json` (Linux/macOS) or
`%APPDATA%\opencode\config.json` (Windows).

```json
{
  "mcp": {
    "servers": {
      "malhaus": {
        "type": "remote",
        "url": "https://your-domain.com/mcp"
      }
    }
  }
}
```

Restart OpenCode after saving. Then use it naturally in your terminal session:

```
> Analyze /home/analyst/samples/suspicious.elf before I run it
> Use malhaus to check https://cdn.example.com/payload.sh
```

---

### Databricks (Mosaic AI / notebook)

Use the malhaus MCP tools directly from a Databricks notebook or AI Agent via the MCP Python SDK.

**Install in your cluster or notebook:**

```bash
%pip install mcp
```

**Example: analyze a file stored in DBFS or a UC Volume**

```python
import asyncio
import base64
import os
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

MALHAUS_MCP_URL = "https://your-domain.com/mcp"   # or internal IP if VPC-peered


async def analyze_dbfs_file(dbfs_path: str) -> str:
    """
    Read a file from DBFS (e.g. /dbfs/FileStore/samples/suspicious.exe)
    or a Unity Catalog Volume (e.g. /Volumes/main/samples/incoming/malware.exe),
    encode it, and submit to malhaus for analysis.

    Parameters
    ----------
    dbfs_path : str
        Absolute POSIX path as seen from the driver node, e.g.:
          /dbfs/FileStore/malware-samples/dropper.exe
          /Volumes/main/security/incoming/suspicious.ps1
    """
    with open(dbfs_path, "rb") as fh:
        file_b64 = base64.b64encode(fh.read()).decode()
    filename = os.path.basename(dbfs_path)

    async with streamablehttp_client(MALHAUS_MCP_URL) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(
                "analyze_file",
                {"file_b64": file_b64, "filename": filename},
            )
            return result.content[0].text


async def analyze_url(url: str) -> str:
    """
    Tell malhaus to download a file from a URL and analyze it.
    Useful for files stored in Azure Blob Storage, S3, or any HTTP endpoint.

    Parameters
    ----------
    url : str
        Publicly reachable URL, e.g.:
          https://storage.googleapis.com/my-bucket/samples/payload.exe
          https://myaccount.blob.core.windows.net/container/file.ps1?<SAS_TOKEN>
    """
    async with streamablehttp_client(MALHAUS_MCP_URL) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("analyze_url", {"url": url})
            return result.content[0].text


# ── Run in a notebook cell ────────────────────────────────────────────────────

# Analyze a file from a Unity Catalog Volume:
result = asyncio.run(analyze_dbfs_file(
    "/Volumes/main/security/incoming/suspicious_dropper.exe"
))
print(result)

# Analyze a file from a presigned S3/Azure Blob URL:
result = asyncio.run(analyze_url(
    "https://myaccount.blob.core.windows.net/samples/invoice.doc?sv=2023-01-03&..."
))
print(result)
```

**Example: batch triage of all files in a Delta table**

```python
import asyncio, base64, os
from pyspark.sql import functions as F
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

MALHAUS_MCP_URL = "https://your-domain.com/mcp"


async def _triage_one(dbfs_path: str) -> dict:
    with open(dbfs_path, "rb") as fh:
        file_b64 = base64.b64encode(fh.read()).decode()
    filename = os.path.basename(dbfs_path)
    async with streamablehttp_client(MALHAUS_MCP_URL) as (r, w, _):
        async with ClientSession(r, w) as s:
            await s.initialize()
            res = await s.call_tool(
                "analyze_file", {"file_b64": file_b64, "filename": filename}
            )
            return {"path": dbfs_path, "result": res.content[0].text}


# Load file paths from a Delta table
paths = (
    spark.table("security.malware_queue")
    .where("status = 'pending'")
    .select("file_path")
    .limit(20)
    .toPandas()["file_path"]
    .tolist()
)

# Triage all files (sequential — adjust for your rate limits)
results = [asyncio.run(_triage_one(p)) for p in paths]
for r in results:
    print(r["path"], "->", r["result"][:120], "...")
```

---

### Generic Python agent (any LLM)

If you want to build your own agent loop using any LLM (OpenAI, Anthropic, Gemini, local Ollama…),
wire the MCP tools manually:

```python
#!/usr/bin/env python3
"""
malhaus-agent — minimal Python agent that uses malhaus MCP tools
with any OpenAI-compatible LLM.

pip install mcp openai
"""
import asyncio
import base64
import json
import os
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from openai import OpenAI   # or any compatible client

MALHAUS_MCP_URL = os.environ.get("MALHAUS_MCP_URL", "https://your-domain.com/mcp")
LLM_BASE_URL    = os.environ.get("LLM_BASE_URL",    "https://api.openai.com/v1")
LLM_API_KEY     = os.environ.get("LLM_API_KEY",     "sk-...")
LLM_MODEL       = os.environ.get("LLM_MODEL",       "gpt-4o")


async def call_mcp(tool: str, args: dict) -> str:
    async with streamablehttp_client(MALHAUS_MCP_URL) as (r, w, _):
        async with ClientSession(r, w) as s:
            await s.initialize()
            result = await s.call_tool(tool, args)
            return result.content[0].text


def triage_file(local_path: str) -> str:
    """Read a local file and submit it to malhaus for analysis."""
    with open(local_path, "rb") as fh:
        b64 = base64.b64encode(fh.read()).decode()
    filename = os.path.basename(local_path)
    return asyncio.run(call_mcp("analyze_file", {"file_b64": b64, "filename": filename}))


def triage_url(url: str) -> str:
    """Tell malhaus to download a URL and analyze it."""
    return asyncio.run(call_mcp("analyze_url", {"url": url}))


def triage_sha256(sha256: str) -> str:
    """Check the malhaus cache for a previously analyzed file."""
    return asyncio.run(call_mcp("analyze_sha256", {"sha256": sha256}))


# Expose as OpenAI-style function definitions for the LLM
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "analyze_local_file",
            "description": (
                "Analyze a local file for malware using malhaus. "
                "Pass the absolute path on the local machine. "
                "Returns verdict, confidence, heuristic score, top reasons, IOCs."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": (
                            "Absolute path to the file on this machine, e.g.: "
                            "/home/analyst/samples/suspicious.exe  or  "
                            "C:\\\\Users\\\\analyst\\\\Downloads\\\\invoice.doc"
                        ),
                    }
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_remote_url",
            "description": (
                "Download a file from an HTTP/HTTPS URL and analyze it with malhaus. "
                "Use this when the file is already reachable over the internet."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": (
                            "Publicly reachable URL of the file, e.g.: "
                            "https://cdn.example.com/updater.ps1"
                        ),
                    }
                },
                "required": ["url"],
            },
        },
    },
]

# Dispatch LLM tool calls to malhaus
DISPATCH = {
    "analyze_local_file": lambda args: triage_file(args["path"]),
    "analyze_remote_url": lambda args: triage_url(args["url"]),
}


def run_agent(user_message: str) -> str:
    client = OpenAI(base_url=LLM_BASE_URL, api_key=LLM_API_KEY)
    messages = [
        {
            "role": "system",
            "content": (
                "You are a malware analyst. When asked to check a file or URL, "
                "use the malhaus tools and explain the result clearly. "
                "Always include the verdict, confidence, and top reasons."
            ),
        },
        {"role": "user", "content": user_message},
    ]

    while True:
        response = client.chat.completions.create(
            model=LLM_MODEL, messages=messages, tools=TOOLS
        )
        msg = response.choices[0].message
        messages.append(msg)

        if not msg.tool_calls:
            return msg.content    # final answer

        for tc in msg.tool_calls:
            args = json.loads(tc.function.arguments)
            result = DISPATCH[tc.function.name](args)
            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": result,
            })


if __name__ == "__main__":
    import sys
    query = " ".join(sys.argv[1:]) or (
        "Analyze /home/analyst/samples/suspicious.exe and tell me if it is safe"
    )
    print(run_agent(query))
```

---

## Example agent sessions

### Analyzing a local file (Linux)

**User:** Use malhaus to check `/home/analyst/samples/invoice_march.exe`. Is it safe?

**Agent:** calls `analyze_file` with the base64 content of `/home/analyst/samples/invoice_march.exe`

**Agent (response):**
> The file is classified as **LIKELY_MALWARE** with 91% confidence.
>
> Top reasons:
> - High entropy in all sections — consistent with a packer or crypter
> - Imports `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread` (process injection)
> - No valid digital signature
> - Overlay data after the PE end — possible encrypted payload appended
>
> Do not open this file. Full report: https://malhaus.example.com/report/4d4a8de9f4...

---

### Analyzing a local file (Windows)

**User:** Analyze `C:\Users\analyst\Downloads\free_software_installer.exe`

**Agent:** reads `C:\Users\analyst\Downloads\free_software_installer.exe`, encodes it, calls `analyze_file(file_b64="TVqQAAMA...", filename="free_software_installer.exe")`

**Agent (response):**
> Verdict: **SUSPICIOUS** (confidence 67%)
>
> The installer is packed with UPX and could not be fully unpacked for deep analysis.
> It contacts several external domains during install (extracted from strings).
> No Authenticode signature is present. Recommend caution.
>
> Full report: https://malhaus.example.com/report/8c3a1b2e...

---

### Analyzing a remote URL

**User:** Submit `https://cdn.example.com/patch_2024.ps1` to malhaus

**Agent:** calls `analyze_url(url="https://cdn.example.com/patch_2024.ps1")`

**Agent (response):**
> Verdict: **BENIGN** (confidence 88%)
>
> The PowerShell script sets Windows Update registry keys and calls `wuauclt.exe /detectnow`.
> No suspicious patterns (no downloads, no encoded payloads, no persistence mechanisms).
>
> Full report: https://malhaus.example.com/report/f1e2d3c4...

---

### Batch analysis

**User:** I have three files in `/mnt/evidence/case-2024-01/`. Check all of them.

**Agent:** calls `analyze_file` three times in sequence, then synthesizes:

| File | Verdict | Confidence | Key finding |
|------|---------|------------|-------------|
| `/mnt/evidence/case-2024-01/dropper.exe` | LIKELY_MALWARE | 94% | Process injection imports, UPX packed |
| `/mnt/evidence/case-2024-01/document.docx` | SUSPICIOUS | 61% | VBA macro with external OLE link |
| `/mnt/evidence/case-2024-01/readme.txt` | BENIGN | 99% | Plain text, no executable content |

---

## Testing

Run these from the server to verify the MCP server is working end-to-end:

```bash
# 1. Quick reachability check
curl http://localhost:8001/mcp
# Expected: {"jsonrpc":"2.0","error":{"message":"Not Acceptable..."}}
# Any JSON response = server is up.

# 2. Full tool listing + URL analysis from inside the container
docker compose exec -T malhaus python3 - <<'EOF'
import asyncio
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

async def test():
    async with streamablehttp_client("http://localhost:8001/mcp") as (r, w, _):
        async with ClientSession(r, w) as s:
            await s.initialize()
            tools = await s.list_tools()
            print("Tools:", [t.name for t in tools.tools])
            # Analyze a URL
            res = await s.call_tool("analyze_url", {
                "url": "https://secure.eicar.org/eicar.com"
            })
            print(res.content[0].text)

asyncio.run(test())
EOF

# 3. Test analyze_file with a known local file
docker compose exec -T malhaus python3 - <<'EOF'
import asyncio, base64
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

async def test():
    async with streamablehttp_client("http://localhost:8001/mcp") as (r, w, _):
        async with ClientSession(r, w) as s:
            await s.initialize()
            # Read /bin/ls from inside the container and analyze it
            with open("/bin/ls", "rb") as fh:
                b64 = base64.b64encode(fh.read()).decode()
            res = await s.call_tool("analyze_file", {
                "file_b64": b64,
                "filename": "ls"
            })
            print(res.content[0].text)

asyncio.run(test())
EOF
```

---

## Environment variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MALHAUS_MCP_API_KEY` | **Yes** | *(none)* | API key (`mh_...`) created in the admin panel. Used internally by the MCP server. Not exposed to clients. |
| `MALHAUS_MCP_PORT` | No | `8001` | Port the MCP server listens on. Change only if 8001 conflicts with something. |
| `MALHAUS_INTERNAL_URL` | No | `http://localhost:8000` | Internal REST API base URL. Only change if REST API runs on a different host/port. |
| `MALHAUS_PUBLIC_URL` | No | *(derived from request)* | Override the public base URL used in report links, e.g. `https://malhaus.example.com`. Automatically derived from the HTTP request Host header if not set. |

---

## Security notes

- `MALHAUS_MCP_API_KEY` is an internal credential. It allows the MCP server to submit jobs. Treat it like any other API key — do not share it or expose it in logs.
- The MCP server has **no authentication** of its own — anyone who can reach port 8001 can call the tools. If you expose port 8001 publicly, protect it with a firewall rule or nginx auth. For internal/private deployments this is usually fine.
- Report URLs returned by the tools point to the malhaus web UI. Those reports are accessible without authentication (same as any other report page).
- Every MCP submission appears in the malhaus web index alongside browser submissions.
