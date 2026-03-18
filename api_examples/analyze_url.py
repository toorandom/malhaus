#!/usr/bin/env python3
"""
Analyze a remote file by URL via malhaus.

URL submission is identical for REST and MCP — the server downloads the file,
no binary transfer from this machine. This is the simplest integration path.

Usage:
  export MALTRIAGE_TOKEN="mh_..."
  python analyze_url.py https://example.com/suspicious.exe
  python analyze_url.py https://example.com/suspicious.exe --include-images
"""

import argparse
import os
import sys
import time
import requests

HOST  = os.environ.get("MALTRIAGE_HOST", "https://your-domain.com")
TOKEN = os.environ.get("MALTRIAGE_TOKEN", "")

POLL_INTERVAL = 5
POLL_TIMEOUT  = 300


def headers() -> dict:
    if not TOKEN:
        sys.exit("Set MALTRIAGE_TOKEN to your mh_... API key")
    return {"Authorization": f"Bearer {TOKEN}"}


def submit(url: str) -> str:
    print(f"Submitting URL: {url}")
    resp = requests.post(
        f"{HOST}/api/v1/analyze",
        headers={**headers(), "Content-Type": "application/json"},
        json={"url": url},
        timeout=30,
    )
    resp.raise_for_status()
    job_id = resp.json()["job_id"]
    print(f"Job ID: {job_id}")
    return job_id


def poll(job_id: str, include: str = "") -> dict:
    params   = {"include": include} if include else {}
    deadline = time.time() + POLL_TIMEOUT
    print("Polling...")
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
    if result.get("takens2d"):
        print()
        print("PCA 2D projection included (takens2d.b64)")


def main() -> None:
    parser = argparse.ArgumentParser(description="malhaus URL analyzer")
    parser.add_argument("url", help="HTTP/HTTPS URL of the file to analyze")
    parser.add_argument(
        "--include-images", action="store_true",
        help="Include entropy/bigram/compression images and PCA 2D projection in result",
    )
    args = parser.parse_args()

    include = "images,takens2d" if args.include_images else ""
    job_id  = submit(args.url)
    result  = poll(job_id, include)
    print_result(result)


if __name__ == "__main__":
    main()
