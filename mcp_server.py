#!/usr/bin/env python3
"""
Malhaus MCP server — exposes malware triage as MCP tools.

Runs on port 8001 (Streamable HTTP transport), wraps the malhaus REST API
running at localhost:8000 inside the same container.

Required env var (set in .env):
  MALHAUS_MCP_API_KEY  — a valid malhaus API key (mh_...) created in the
                         admin panel. The MCP server uses it to authenticate
                         with the REST API internally.

Optional env vars:
  MALHAUS_MCP_PORT     — port to listen on (default 8001)
  MALHAUS_INTERNAL_URL — internal REST base URL (default http://localhost:8000)

Connect from any MCP client:
  URL: http://your-server:8001/mcp   (Streamable HTTP transport)
"""

import contextvars
import os
import time

import requests
from mcp.server.fastmcp import FastMCP
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest

MALHAUS_INTERNAL = os.environ.get("MALHAUS_INTERNAL_URL", "http://localhost:8000")
MALHAUS_API_KEY  = os.environ.get("MALHAUS_MCP_API_KEY", "")

# Filled in per-request by HostMiddleware so _fmt() can build public report URLs
# without requiring manual MALHAUS_PUBLIC_URL configuration.
_request_public_base: contextvars.ContextVar[str] = contextvars.ContextVar(
    "_request_public_base", default=""
)


class HostMiddleware(BaseHTTPMiddleware):
    """Capture the public base URL from each incoming request's Host header."""
    async def dispatch(self, request: StarletteRequest, call_next):
        override = os.environ.get("MALHAUS_PUBLIC_URL", "").rstrip("/")
        if override:
            _request_public_base.set(override)
        else:
            host   = request.headers.get("host", "")
            scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
            # Strip the MCP port (8001) — the web app is served via nginx on 80/443
            hostname = host.split(":")[0]
            if hostname:
                _request_public_base.set(f"{scheme}://{hostname}")
        return await call_next(request)

_POLL_INTERVAL = 5    # seconds between status polls
_POLL_TIMEOUT  = 360  # max seconds to wait for a result
_MCP_PORT      = int(os.environ.get("MALHAUS_MCP_PORT", "8001"))

# host and port belong on the constructor, not on run()
mcp = FastMCP(
    "malhaus",
    instructions=(
        "Malhaus is a malware triage engine. "
        "Use analyze_file to scan a file (pass base64-encoded content + filename), "
        "analyze_url to scan a file downloaded from a URL, "
        "or analyze_sha256 to retrieve a cached result by hash. "
        "Analysis typically takes 30-120 seconds. "
        "Results include verdict (benign/suspicious/likely_malware), confidence, "
        "heuristic score, top reasons, and extracted IOCs."
    ),
    host="0.0.0.0",
    port=_MCP_PORT,
)


def _headers() -> dict:
    return {"Authorization": f"Bearer {MALHAUS_API_KEY}"}


def _poll_job(job_id: str) -> dict:
    """Poll /api/v1/jobs/<job_id> until done or timeout."""
    deadline = time.time() + _POLL_TIMEOUT
    while time.time() < deadline:
        r = requests.get(
            f"{MALHAUS_INTERNAL}/api/v1/jobs/{job_id}",
            headers=_headers(),
            timeout=30,
        )
        r.raise_for_status()
        data = r.json()
        status = data.get("status")
        if status == "done":
            return data
        if status == "failed":
            raise RuntimeError(f"Analysis failed: {data.get('error', 'unknown error')}")
        time.sleep(_POLL_INTERVAL)
    raise TimeoutError(f"Analysis did not complete within {_POLL_TIMEOUT}s")


def _fmt(data: dict) -> str:
    """Format a completed job result as readable text."""
    v       = data.get("verdict") or {}
    risk    = v.get("risk_level", "unknown").upper()
    conf    = v.get("confidence", 0)
    ftype   = v.get("file_type", "unknown")
    sha     = data.get("sha256", "")
    heur    = data.get("heuristic_score", "?")
    reasons = data.get("top_reasons") or v.get("top_reasons") or []
    iocs    = v.get("iocs") or data.get("iocs") or {}
    cached  = data.get("cached", False)

    lines = [
        f"Verdict: {risk}  (confidence {conf}%){' [cached]' if cached else ''}",
        f"File type: {ftype}",
        f"SHA-256: {sha}",
        f"Heuristic score: {heur}/100",
        "",
        "Top reasons:",
    ]
    for reason in reasons[:8]:
        lines.append(f"  - {reason}")

    for key in ("urls", "ips", "domains", "registry_paths", "mutexes"):
        vals = (iocs.get(key) or [])[:10]
        if vals:
            lines.append(f"\nIOCs ({key}): {', '.join(vals)}")

    report_url = data.get("report_url")
    if report_url:
        base = _request_public_base.get("").rstrip("/") or MALHAUS_INTERNAL.rstrip("/")
        lines.append(f"\nFull report: {base}{report_url}")

    return "\n".join(lines)


def _submit_and_wait(payload: dict) -> str:
    if not MALHAUS_API_KEY:
        return (
            "Error: MALHAUS_MCP_API_KEY is not set. "
            "Create an API key in the malhaus admin panel, then add "
            "MALHAUS_MCP_API_KEY=mh_... to your .env file and restart the container."
        )
    r = requests.post(
        f"{MALHAUS_INTERNAL}/api/v1/analyze",
        json=payload,
        headers=_headers(),
        timeout=60,
    )
    r.raise_for_status()
    resp = r.json()
    if resp.get("status") == "done":
        return _fmt(resp)
    job_id = resp.get("job_id")
    if not job_id:
        return f"Unexpected response from malhaus: {resp}"
    data = _poll_job(job_id)
    return _fmt(data)


@mcp.tool()
def analyze_file(file_b64: str, filename: str = "sample.bin") -> str:
    """
    Analyze a file for malware.

    Args:
        file_b64: File content encoded as base64.
        filename: Original filename (helps with type detection, e.g. "invoice.doc").

    Returns a verdict (benign/suspicious/likely_malware), confidence score,
    heuristic score, the top reasons, and any extracted IOCs.
    Analysis typically takes 30-120 seconds.
    """
    return _submit_and_wait({"file_b64": file_b64, "filename": filename})


@mcp.tool()
def analyze_url(url: str) -> str:
    """
    Download a file from a URL and analyze it for malware.

    Args:
        url: Public URL pointing directly to the file to analyze.

    Returns a verdict (benign/suspicious/likely_malware), confidence score,
    heuristic score, the top reasons, and any extracted IOCs.
    Analysis typically takes 30-120 seconds.
    """
    return _submit_and_wait({"url": url})


@mcp.tool()
def analyze_sha256(sha256: str) -> str:
    """
    Retrieve a cached malware analysis result by SHA-256 hash.

    Args:
        sha256: Hex SHA-256 of the file (64 characters).

    Returns the cached verdict if the file was previously analyzed,
    or a message indicating no cached result is available.
    """
    if not MALHAUS_API_KEY:
        return "Error: MALHAUS_MCP_API_KEY is not set."
    r = requests.post(
        f"{MALHAUS_INTERNAL}/api/v1/analyze",
        json={"sha256": sha256},
        headers=_headers(),
        timeout=30,
    )
    if r.status_code == 404:
        return f"No cached result for {sha256}. Submit the file via analyze_file or analyze_url."
    r.raise_for_status()
    resp = r.json()
    if resp.get("status") == "done":
        return _fmt(resp)
    job_id = resp.get("job_id")
    if not job_id:
        return f"Unexpected response: {resp}"
    data = _poll_job(job_id)
    return _fmt(data)


if __name__ == "__main__":
    import uvicorn
    app = mcp.streamable_http_app()
    app.add_middleware(HostMiddleware)
    uvicorn.run(app, host="0.0.0.0", port=_MCP_PORT)
