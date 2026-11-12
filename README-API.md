# malhaus REST API

A standard HTTP API for submitting files or URLs to the malhaus triage pipeline, bypassing the web captcha. Analysis results appear in the web index alongside browser-submitted reports.

---

## Authentication

All API requests require a Bearer token issued by the server administrator.

```
Authorization: Bearer mh_<64-hex-chars>
```

### Creating a key (server-side, admin only)

```bash
python manage_keys.py create --label "Alice — security team" --rate-limit 30
```

Output (token shown **once only** — save it immediately):

```
  API key created — store this token securely. It will NOT be shown again.

  Token  : mh_<your-64-hex-token>
  Key ID : 227e520f-6020-498a-9954-c48c461b3a33
  Label  : Alice — security team
  Rate   : 30 requests/hour

  Usage:
    curl -H "Authorization: Bearer mh_a96c54b3..." ...
```

### Managing keys

```bash
# List all keys
python manage_keys.py list

# Show details for one key
python manage_keys.py info 227e520f-6020-498a-9954-c48c461b3a33

# Revoke immediately (takes effect on the next request)
python manage_keys.py revoke 227e520f-6020-498a-9954-c48c461b3a33

# Delete old completed/failed jobs (housekeeping)
python manage_keys.py cleanup-jobs --days 30
```

Keys are stored as SHA-256 hashes in `maltriage.db` — the plaintext token is never persisted.

---

## Base URL

```
https://<your-domain>/api/v1
```

A live instance is running at **https://grothendieck.ff2.nl** — you can use it to try the API before deploying your own.

---

## Endpoints

### `GET /report/<sha256>/json`

Returns the raw analysis JSON for any previously analyzed file — no authentication required. This is the same data rendered in the web report, available as machine-readable JSON directly from the report URL.

```bash
curl https://<your-domain>/report/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855/json
```

A **JSON ↗** button linking to this endpoint appears on every web report page.

---

### `POST /api/v1/upload`

Stage a file for analysis. Returns `file_id` and `sha256` of the uploaded file. If the file was already analyzed the response sets `cached: true` and includes `report_url` — no need to call `/analyze` again.

The staged file is tied to the key that uploaded it and expires after **1 hour** or is consumed on first use, whichever comes first.

**Request — multipart/form-data**

| Field              | Type   | Required | Description                              |
|--------------------|--------|----------|------------------------------------------|
| `file`             | binary | yes*     | The file to stage                        |
| `archive_password` | string | no       | Password for encrypted ZIP/RAR archives  |

**Request — JSON body (base64)**

| Field              | Type   | Required | Description                              |
|--------------------|--------|----------|------------------------------------------|
| `file_b64`         | string | yes*     | Base64-encoded file content              |
| `filename`         | string | no       | Original filename (for display)          |
| `archive_password` | string | no       | Password for encrypted ZIP/RAR archives  |

\* Provide exactly one of `file` or `file_b64`.

**Response `201 Created` — not yet analyzed**

```json
{
  "sha256":      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "cached":      false,
  "file_id":     "3f2e1a...",
  "filename":    "suspicious.exe",
  "expires_in":  3600,
  "analyze_url": "/api/v1/analyze"
}
```

**Response `200 OK` — already analyzed (cache hit)**

```json
{
  "sha256":      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "cached":      true,
  "filename":    "suspicious.exe",
  "report_url":  "/report/e3b0c442...",
  "file_id":     null,
  "expires_in":  null
}
```

---

### `POST /api/v1/analyze`

Submit a file for triage. Accepts five input modes — provide exactly one. Returns immediately with a job ID; analysis runs in the background.

If the file was already analyzed (by SHA-256 hash), the job is resolved immediately with `cached: true` — no re-analysis.

**Request — file upload (multipart/form-data)**

| Field              | Type   | Required | Description                                      |
|--------------------|--------|----------|--------------------------------------------------|
| `file`             | binary | yes*     | The file to analyze (direct upload)              |
| `file_id`          | string | yes*     | ID from `POST /api/v1/upload`                    |
| `file_b64`         | string | yes*     | Base64-encoded file content (JSON body only)     |
| `url`              | string | yes*     | URL to download and analyze                      |
| `sha256`           | string | yes*     | SHA-256 of a previously analyzed file (no upload)|
| `use_ghidra`       | string | no       | `"1"` to enable Ghidra (slow)                    |
| `archive_password` | string | no       | Password for encrypted ZIP/RAR (inherited from `file_id` if set during upload) |

\* Provide exactly one of `file`, `file_id`, `file_b64`, `url`, or `sha256`.

**Request — JSON body**

```json
{
  "url": "https://example.com/sample.exe",
  "use_ghidra": false,
  "archive_password": ""
}
```

```json
{
  "file_b64":  "<base64-encoded content>",
  "filename":  "suspicious.exe",
  "archive_password": "infected"
}
```

```json
{
  "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

**Response `202 Accepted`**

```json
{
  "job_id":     "3f2e1a...",
  "status":     "pending",
  "status_url": "/api/v1/jobs/3f2e1a..."
}
```

---

### `GET /api/v1/jobs/<job_id>`

Poll a job for status and results. Only the key that submitted the job can poll it.

**Query parameters**

| Parameter | Values              | Description                                             |
|-----------|---------------------|---------------------------------------------------------|
| `include` | `images,takens2d`   | Comma-separated list of optional sections to include    |

`images` — adds base64 PNG + interpretation for entropy profile, compression curve, bigram matrix.
`takens2d` — adds the PCA 2D projection of the byte trigram point cloud as base64 JPEG.

**Response — in progress**

```json
{ "status": "pending", "job_id": "3f2e1a..." }
{ "status": "running", "job_id": "3f2e1a..." }
```

**Response — failed**

```json
{
  "status": "failed",
  "job_id": "3f2e1a...",
  "error":  "Unsupported file type: iso"
}
```

**Response — done**

```json
{
  "status":   "done",
  "job_id":   "3f2e1a...",
  "sha256":   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "container_sha256": null,
  "sha256_source": "analyzed_file",
  "report_url": "/report/e3b0c442...",
  "verdict": {
    "risk_level": "likely_malware",
    "confidence": 92,
    "file_type":  "PE32 executable"
  },
  "heuristic_score": 74,
  "top_reasons": [
    "High entropy sections consistent with packing or encryption",
    "Imports VirtualAlloc, WriteProcessMemory — classic process injection pattern",
    "No valid authenticode signature"
  ],
  "network_artifacts": {
    "summary": "Network artifacts found statically — URLs: http://evil.example/gate.php; IPs: 185.220.101.4:8443. Domain age: evil.example 6d old NEWLY REGISTERED.",
    "urls": ["http://evil.example/gate.php"], "domains": ["evil.example"], "ips": ["185.220.101.4:8443"], "emails": [],
    "abused_services": [], "benign_infra": ["ocsp.digicert.com"],
    "domain_ages": [{"domain": "evil.example", "created": "2026-11-04", "age_days": 6, "source": "rdap"}],
    "network_apis": {"http_client": ["InternetOpenUrlW"], "download_to_file": ["URLDownloadToFileW"]},
    "items": [{"type": "url", "value": "http://evil.example/gate.php", "class": "unknown", "sources": ["strings_utf16le"], "context": "..."}]
  },
  "phishing": {},
  "tools_used": [
    "mandatory_authenticode_verify",
    "mandatory_objdump_pe_headers",
    "mandatory_objdump_pe_dynamic",
    "mandatory_radare2_info",
    "mandatory_radare2_entry"
  ],
  "tool_outputs": {
    "mandatory_authenticode_verify": {
      "stdout": "...",
      "stderr": "",
      "error":  null
    }
  }
}
```

**Response — done, with `?include=images,takens2d`**

The response above plus:

```json
{
  "images": {
    "entropy_profile": {
      "b64":            "<base64 PNG>",
      "description":    "Entropy profile",
      "interpretation": "Long red plateau from offset 0x3000 — consistent with a packed payload."
    },
    "compression_curve": {
      "b64":            "<base64 PNG>",
      "description":    "Compression curve",
      "interpretation": "Compression ratio ≥ 0.97 at all levels — file resists compression."
    },
    "bigram_matrix": {
      "b64":            "<base64 PNG>",
      "description":    "Bigram matrix",
      "interpretation": "Near-uniform distribution — characteristic of encrypted or random data."
    }
  },
  "takens2d": {
    "b64":            "<base64 PNG>",
    "description":    "Byte trigram PCA 2D projection",
    "interpretation": "Diffuse isotropic scatter — no structural clustering."
  }
}
```

---

## Rate limiting

Each key has its own per-hour limit (set at creation time, default 60). When exceeded:

```
HTTP 429
{ "error": "Rate limit exceeded (30/hour)" }
```

---

## Error codes

| Code | Meaning                                |
|------|----------------------------------------|
| 400  | Missing or invalid input               |
| 401  | Missing, invalid, or revoked API key   |
| 404  | Job not found (or belongs to other key)|
| 429  | Per-key rate limit exceeded            |
| 500  | Internal server error                  |

---

## Examples

> Ready-to-run scripts are in [`api_examples/`](api_examples/):
> - `rest_analyze_file.sh` / `rest_analyze_url.sh` — curl, REST API
> - `mcp_analyze_file.sh` / `mcp_analyze_url.sh` — curl, MCP two-step
> - `analyze_file.py` / `analyze_url.py` — Python, both modes

### curl — file upload

```bash
TOKEN="mh_<your-64-hex-token>"
HOST="https://your-domain.com"

# Submit
JOB=$(curl -s -X POST "$HOST/api/v1/analyze" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/tmp/suspicious.exe" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['job_id'])")

echo "Job: $JOB"

# Poll until done
while true; do
  RESP=$(curl -s "$HOST/api/v1/jobs/$JOB" \
    -H "Authorization: Bearer $TOKEN")
  STATUS=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])")
  echo "Status: $STATUS"
  [ "$STATUS" = "done" ] || [ "$STATUS" = "failed" ] && break
  sleep 5
done

echo "$RESP" | python3 -m json.tool
```

### curl — URL submission + images

```bash
curl -s -X POST "$HOST/api/v1/analyze" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com/sample.exe"}' \
  | python3 -m json.tool

# After job completes, fetch with images
curl -s "$HOST/api/v1/jobs/$JOB?include=images,takens2d" \
  -H "Authorization: Bearer $TOKEN" \
  | python3 -m json.tool
```

### Python — full polling client

```python
import time
import requests

HOST  = "https://your-domain.com"
TOKEN = "mh_<your-64-hex-token>"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}


def analyze_file(path: str, include_images: bool = False) -> dict:
    # Submit
    with open(path, "rb") as f:
        resp = requests.post(
            f"{HOST}/api/v1/analyze",
            headers=HEADERS,
            files={"file": f},
            timeout=30,
        )
    resp.raise_for_status()
    job_id = resp.json()["job_id"]
    print(f"Job submitted: {job_id}")

    # Poll
    include = "images,takens2d" if include_images else ""
    params  = {"include": include} if include else {}
    while True:
        r = requests.get(
            f"{HOST}/api/v1/jobs/{job_id}",
            headers=HEADERS,
            params=params,
            timeout=10,
        )
        r.raise_for_status()
        data   = r.json()
        status = data["status"]
        print(f"  status: {status}")
        if status == "done":
            return data
        if status == "failed":
            raise RuntimeError(data.get("error", "analysis failed"))
        time.sleep(5)


def analyze_url(url: str) -> dict:
    resp = requests.post(
        f"{HOST}/api/v1/analyze",
        headers=HEADERS,
        json={"url": url},
        timeout=30,
    )
    resp.raise_for_status()
    job_id = resp.json()["job_id"]
    print(f"Job submitted: {job_id}")

    while True:
        r = requests.get(
            f"{HOST}/api/v1/jobs/{job_id}",
            headers=HEADERS,
            timeout=10,
        )
        r.raise_for_status()
        data = r.json()
        if data["status"] == "done":
            return data
        if data["status"] == "failed":
            raise RuntimeError(data.get("error", "analysis failed"))
        time.sleep(5)


if __name__ == "__main__":
    result = analyze_file("/tmp/suspicious.exe", include_images=True)
    v = result["verdict"]
    print(f"\nRisk    : {v['risk_level']} (confidence {v['confidence']}%)")
    print(f"SHA-256 : {result['sha256']}")
    print(f"Report  : {HOST}{result['report_url']}")
    print("\nTop reasons:")
    for r in result["top_reasons"]:
        print(f"  - {r}")
```

### Python — save images to disk

```python
import base64

result = analyze_file("/tmp/sample.exe", include_images=True)

for name, img in (result.get("images") or {}).items():
    if img.get("b64"):
        with open(f"{name}.png", "wb") as f:
            f.write(base64.b64decode(img["b64"]))
        print(f"Saved {name}.png — {img['interpretation']}")

if result.get("takens2d") and result["takens2d"].get("b64"):
    with open("takens2d.png", "wb") as f:
        f.write(base64.b64decode(result["takens2d"]["b64"]))
    print("Saved takens2d.png")
```

---

## Security notes

- Always use HTTPS in production — set `MALHAUS_HTTPS=1` and put a TLS-terminating reverse proxy (nginx, caddy) in front
- API keys are single-use bearer tokens; treat them like passwords
- Revoke compromised keys immediately with `python manage_keys.py revoke <key_id>`
- The `ip` field logged in `web_recents` for API submissions is `api:<first-8-chars-of-key-id>` for traceability without exposing the full key

### `network_artifacts` and `phishing`

- `network_artifacts` — validated network IOCs from a whole-file scan (ASCII + UTF-16LE strings, FLOSS, decoded
  document/e-mail text). Code identifiers such as `System.SysUtils` or `kernel32.dll` are rejected; certificate
  CRL/OCSP, schema and installer-vendor hosts are listed under `benign_infra` and do not affect the score.
  `domain_ages` comes from RDAP (whois fallback) and is disabled with `MALHAUS_DOMAIN_AGE_LOOKUP=0`.
- `phishing` — present for PDF, DOCX/XLSX/PPTX, `.eml` and `.msg`: `score` 0–100, `verdict`
  (`phishing` / `suspicious` / `no_strong_indicators`), `signals` (weighted), `links` (visible text vs real target,
  with flags), sender headers and attachments for e-mail, domain ages, and the LLM's read (`llm`). Image-only PDFs
  are OCR'd (tesseract, else the vision LLM) before analysis. Pictures embedded in the e-mail/document (inline
  `cid:` parts, image attachments, HTML `data:` URIs, OOXML media) are OCR'd and QR-decoded too; `image_ocr` lists
  each one (`name`, `source`, `width`, `height`, `method`, `text`, `qr`) and their text is scored with the body.
  Limits: `MALHAUS_IMAGE_OCR_MAX` (default 12) and `MALHAUS_IMAGE_OCR_VISION_MAX` (default 6).
- Sub-components — no new fields: inner files (installer payloads, archive members, attachments, embedded
  objects, nested containers) are analysed with the same tools. `tool_outputs.mandatory_subcomponents.stdout`
  lists each one (path inside the object, type, score, reasons, path on disk); every other `tool_outputs.<tool>.stdout`
  also carries that tool's output for each inner file after a `===== sub-component: <outer ▸ inner> (<type>) =====`
  header, so parse a tool's own section up to the first such header. Sub-component findings appear in `top_reasons`.
- Promoted files (archives whose inner file is analysed instead of the upload):
  - `sha256` — hash of the file the verdict is about: the promoted inner file (e.g. the EXE inside the ZIP/7z), or the
    upload itself when nothing was promoted. Same key name as before.
  - `container_sha256` — hash of the uploaded container when a file inside it was promoted, otherwise `null`.
  - `sha256_source` — `"analyzed_file"` (normal) or `"original_upload"`: reports created before promoted-file hashes were
    recorded only know the upload's hash, so `sha256` is then the ORIGINAL uploaded file's hash, not the analysed one's
    (`container_sha256` equals it).
  - `report_url` / `report_json_url` stay keyed by the uploaded file; `GET /report/<sha256>[/json]` and
    `POST /api/v1/analyze` with `sha256` accept either hash.
  - `tool_outputs.sha256.stdout` is `sha256sum` output: line 1 = uploaded file, line 2 (when promoted) = analysed file.
