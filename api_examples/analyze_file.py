#!/usr/bin/env python3
"""
Analyze a local file via malhaus.

Demonstrates multiple approaches:
  --mode rest   Direct multipart upload (REST API, single step)
  --mode mcp    Two-step upload (file_id pattern used by the MCP server)
  --mode b64    Base64-encode and send as JSON body
  --sha256      Look up a previously analyzed file by hash (no upload)

Usage:
  export MALTRIAGE_TOKEN="mh_..."
  python analyze_file.py suspicious.exe
  python analyze_file.py suspicious.exe --mode mcp
  python analyze_file.py suspicious.exe --mode mcp --archive-password infected
  python analyze_file.py suspicious.exe --mode b64
  python analyze_file.py suspicious.exe --include-images
  python analyze_file.py --sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
"""

import argparse
import base64
import os
import sys
import time
import requests

HOST  = os.environ.get("MALTRIAGE_HOST", "https://your-domain.com")
TOKEN = os.environ.get("MALTRIAGE_TOKEN", "")

POLL_INTERVAL = 5   # seconds between status checks
POLL_TIMEOUT  = 300 # give up after 5 minutes


def headers() -> dict:
    if not TOKEN:
        sys.exit("Set MALTRIAGE_TOKEN to your mh_... API key")
    return {"Authorization": f"Bearer {TOKEN}"}


def poll(job_id: str, include: str = "") -> dict:
    params   = {"include": include} if include else {}
    deadline = time.time() + POLL_TIMEOUT
    while time.time() < deadline:
        r = requests.get(
            f"{HOST}/api/v1/jobs/{job_id}",
            headers=headers(),
            params=params,
            timeout=15,
        )
        r.raise_for_status()
        data   = r.json()
        status = data["status"]
        print(f"  status: {status}")
        if status == "done":
            return data
        if status == "failed":
            sys.exit(f"Analysis failed: {data.get('error')}")
        time.sleep(POLL_INTERVAL)
    sys.exit(f"Timed out after {POLL_TIMEOUT}s")


def print_result(result: dict) -> None:
    v = result["verdict"]
    print()
    print(f"Risk     : {v['risk_level']} (confidence {v['confidence']}%)")
    print(f"SHA-256  : {result['sha256']}")
    print(f"Report   : {HOST}{result['report_url']}")
    print()
    print("Top reasons:")
    for r in result.get("top_reasons", []):
        print(f"  - {r}")


# ── REST: direct multipart upload ────────────────────────────────────────────

def rest_analyze(path: str, include: str = "", archive_password: str = "") -> None:
    print(f"[REST] Uploading {path}")
    extra = {"archive_password": archive_password} if archive_password else {}
    with open(path, "rb") as f:
        resp = requests.post(
            f"{HOST}/api/v1/analyze",
            headers=headers(),
            files={"file": f},
            data=extra,
            timeout=60,
        )
    resp.raise_for_status()
    data = resp.json()
    job_id = data["job_id"]
    print(f"Job ID: {job_id}")
    if data.get("cached"):
        print(f"Cache hit — report: {HOST}{data.get('report_url', '')}")
        return
    print("Polling...")
    result = poll(job_id, include)
    print_result(result)


# ── MCP two-step: upload → file_id → analyze ────────────────────────────────

def mcp_analyze(path: str, include: str = "", archive_password: str = "") -> None:
    # Step 1 — upload, receive file_id and sha256
    print(f"[MCP] Uploading {path}")
    extra = {"archive_password": archive_password} if archive_password else {}
    with open(path, "rb") as f:
        up = requests.post(
            f"{HOST}/api/v1/upload",
            headers=headers(),
            files={"file": f},
            data=extra,
            timeout=60,
        )
    up.raise_for_status()
    up_data = up.json()
    print(f"SHA-256 : {up_data['sha256']}")

    # Cache hit detected at upload time — no need to call /analyze
    if up_data.get("cached"):
        print(f"Already analyzed — report: {HOST}{up_data.get('report_url', '')}")
        return

    file_id = up_data["file_id"]
    print(f"File ID : {file_id} (expires in {up_data['expires_in']}s)")

    # Step 2 — analyze by file_id (archive_password inherited from staged record)
    print("Submitting for analysis...")
    resp = requests.post(
        f"{HOST}/api/v1/analyze",
        headers={**headers(), "Content-Type": "application/json"},
        json={"file_id": file_id},
        timeout=30,
    )
    resp.raise_for_status()
    job_id = resp.json()["job_id"]
    print(f"Job ID: {job_id}")
    print("Polling...")
    result = poll(job_id, include)
    print_result(result)


# ── Base64: encode file and send as JSON ─────────────────────────────────────

def b64_analyze(path: str, include: str = "", archive_password: str = "") -> None:
    print(f"[B64] Encoding {path}")
    with open(path, "rb") as f:
        encoded = base64.b64encode(f.read()).decode()
    payload = {
        "file_b64":  encoded,
        "filename":  os.path.basename(path),
    }
    if archive_password:
        payload["archive_password"] = archive_password
    resp = requests.post(
        f"{HOST}/api/v1/analyze",
        headers={**headers(), "Content-Type": "application/json"},
        json=payload,
        timeout=60,
    )
    resp.raise_for_status()
    job_id = resp.json()["job_id"]
    print(f"Job ID: {job_id}")
    print("Polling...")
    result = poll(job_id, include)
    print_result(result)


# ── SHA-256 lookup: check if already analyzed ─────────────────────────────────

def sha256_lookup(sha256: str, include: str = "") -> None:
    print(f"[SHA256] Looking up {sha256}")
    resp = requests.post(
        f"{HOST}/api/v1/analyze",
        headers={**headers(), "Content-Type": "application/json"},
        json={"sha256": sha256},
        timeout=15,
    )
    if resp.status_code == 404:
        sys.exit(f"Not found: {resp.json().get('error')}")
    resp.raise_for_status()
    data = resp.json()
    if data.get("cached"):
        print(f"Found — report: {HOST}{data.get('report_url', '')}")
        job_id = data["job_id"]
        result = poll(job_id, include)
        print_result(result)
    else:
        print(f"Job ID: {data['job_id']}")
        result = poll(data["job_id"], include)
        print_result(result)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="malhaus file analyzer")
    parser.add_argument("file", nargs="?", help="Path to the file to analyze")
    parser.add_argument(
        "--mode", choices=["rest", "mcp", "b64"], default="rest",
        help="rest = direct upload (default), mcp = two-step via file_id, b64 = base64 JSON",
    )
    parser.add_argument(
        "--sha256",
        help="Look up a previously analyzed file by SHA-256 hash (no upload needed)",
    )
    parser.add_argument(
        "--archive-password", default="",
        help="Password for encrypted ZIP/RAR archives",
    )
    parser.add_argument(
        "--include-images", action="store_true",
        help="Include entropy/bigram/compression images and PCA 2D projection in result",
    )
    args = parser.parse_args()

    include = "images,takens2d" if args.include_images else ""

    if args.sha256:
        sha256_lookup(args.sha256, include)
        return

    if not args.file:
        parser.error("Provide a file path or --sha256")

    if args.mode == "mcp":
        mcp_analyze(args.file, include, args.archive_password)
    elif args.mode == "b64":
        b64_analyze(args.file, include, args.archive_password)
    else:
        rest_analyze(args.file, include, args.archive_password)


if __name__ == "__main__":
    main()
