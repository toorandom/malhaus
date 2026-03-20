"""
REST API v1 — /api/v1/

Authentication : Authorization: Bearer mh_<64hex>
Rate limiting  : per-key, configurable (default 60/hour)

Endpoints:
  POST /api/v1/upload           — stage a file, receive file_id (expires 1 h)
  POST /api/v1/analyze          — submit file, file_id, or URL for analysis
  GET  /api/v1/jobs/<job_id>    — poll job status / fetch result
"""
import json
import os
import threading
import time
import uuid
import hashlib
import sqlite3
from pathlib import Path

import requests as http_requests
from flask import Blueprint, request, jsonify, url_for

from webapp.api_auth import verify_bearer, api_rate_check, ensure_api_tables
from webapp.routes import (
    _acquire_analysis_slot, _release_analysis_slot, _update_analysis_slot,
    _get_cached_recent, _write_recent, _download_url_to_file,
    _sha256_file, UPLOAD_DIR, DB_PATH,
)
from tools.cli_tools import detect_file_type
from agent.triage_agent import analyze
import config

api_bp = Blueprint("api", __name__, url_prefix="/api/v1")

BASE_DIR = Path(__file__).resolve().parents[1]

ALLOWED_KINDS = {
    "pe", "elf", "office", "office_openxml",
    "ps1", "shell", "js", "msi", "pdf", "lnk", "vbs", "hta", "archive",
}


# ---------------------------------------------------------------------------
# DB helpers for api_jobs
# ---------------------------------------------------------------------------

def _db() -> sqlite3.Connection:
    con = sqlite3.connect(str(DB_PATH))
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    return con


# ---------------------------------------------------------------------------
# DB helpers for api_staged_files
# ---------------------------------------------------------------------------

STAGED_TTL = 3600  # staged files expire after 1 hour


def _staged_put(
    file_id: str, key_id: str, path: str, filename: str,
    archive_password: str = "", sha256: str = "",
) -> None:
    ensure_api_tables()
    con = _db()
    try:
        con.execute(
            "DELETE FROM api_staged_files WHERE created_at < ?",
            (int(time.time()) - STAGED_TTL,),
        )
        con.execute(
            "INSERT INTO api_staged_files"
            "(file_id, key_id, path, filename, archive_password, sha256, created_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (file_id, key_id, path, filename, archive_password, sha256, int(time.time())),
        )
        con.commit()
    finally:
        con.close()


def _staged_pop(file_id: str, key_id: str) -> dict | None:
    """Return and delete the staged file row. Returns None if not found or wrong key."""
    con = _db()
    try:
        row = con.execute(
            "SELECT file_id, path, filename, archive_password, sha256 "
            "FROM api_staged_files "
            "WHERE file_id = ? AND key_id = ? AND created_at >= ?",
            (file_id, key_id, int(time.time()) - STAGED_TTL),
        ).fetchone()
        if not row:
            return None
        con.execute("DELETE FROM api_staged_files WHERE file_id = ?", (file_id,))
        con.commit()
        return dict(row)
    finally:
        con.close()


# ---------------------------------------------------------------------------
# DB helpers for api_jobs
# ---------------------------------------------------------------------------

def _job_create(job_id: str, key_id: str, filename: str) -> None:
    ensure_api_tables()
    now = int(time.time())
    con = _db()
    try:
        con.execute(
            "INSERT INTO api_jobs(job_id, key_id, status, created_at, updated_at, filename) "
            "VALUES(?,?,?,?,?,?)",
            (job_id, key_id, "pending", now, now, filename),
        )
        con.commit()
    finally:
        con.close()


def _job_update(job_id: str, **fields) -> None:
    if not fields:
        return
    fields["updated_at"] = int(time.time())
    set_clause = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values()) + [job_id]
    con = _db()
    try:
        con.execute(f"UPDATE api_jobs SET {set_clause} WHERE job_id = ?", values)
        con.commit()
    finally:
        con.close()


def _job_get(job_id: str) -> dict | None:
    con = _db()
    try:
        row = con.execute(
            "SELECT job_id, key_id, status, created_at, updated_at, sha256, filename, result_json, error "
            "FROM api_jobs WHERE job_id = ?",
            (job_id,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        con.close()


# ---------------------------------------------------------------------------
# Result formatting
# ---------------------------------------------------------------------------

def _build_html_summary(
    risk_level, confidence, file_type, sha256, report_url, report_json_url,
    heuristic_score, top_reasons, strings_score, strings_summary,
) -> str:
    risk_color = {
        "malicious": "#c0392b", "suspicious": "#e67e22",
        "benign": "#27ae60", "unknown": "#7f8c8d",
    }.get(str(risk_level).lower(), "#7f8c8d")
    reasons_html = "".join(f"<li>{r}</li>" for r in top_reasons)
    return (
        f'<div style="font-family:monospace;font-size:13px;line-height:1.6">'
        f'<p><strong>Risk:</strong> '
        f'<span style="color:{risk_color};font-weight:bold">{risk_level}</span>'
        f' &nbsp; <strong>Confidence:</strong> {confidence}%'
        f' &nbsp; <strong>Heuristic score:</strong> {heuristic_score}'
        f' &nbsp; <strong>Strings score:</strong> {strings_score}/100</p>'
        f'<p><strong>File type:</strong> {file_type}</p>'
        f'<p><strong>SHA-256:</strong> <code>{sha256}</code></p>'
        f'<p>'
        f'<a href="{report_url}">HTML report</a>'
        f' &nbsp;|&nbsp; '
        f'<a href="{report_json_url}">Full JSON</a>'
        f'</p>'
        f'<p><strong>Strings summary:</strong> {strings_summary}</p>'
        f'<strong>Top reasons:</strong><ul>{reasons_html}</ul>'
        f'</div>'
    )


def _build_result(job: dict, include: set[str]) -> dict:
    """
    Build the structured API response from a completed job row.
    include: set of optional sections e.g. {'images', 'takens2d'}
    """
    report = json.loads(job["result_json"])
    v   = report.get("verdict", {}) or {}
    h   = report.get("heuristics", {}) or {}
    pre = report.get("preflight", {}) or {}
    viz = report.get("visualizations", {}) or {}

    # Collect tool outputs — everything in preflight that looks like a tool result
    tool_outputs = {}
    for k, val in pre.items():
        if k in ("kind", "sha256_raw", "upx_packed", "container_kind"):
            continue
        if isinstance(val, dict):
            tool_outputs[k] = {
                "stdout": val.get("stdout") or "",
                "stderr": val.get("stderr") or "",
                "error":  val.get("error"),
            }
    tools_used = list(tool_outputs.keys())

    sha256_val   = job["sha256"] or ""
    report_url   = url_for("bp.report_sha", sha256=sha256_val, _external=False) if sha256_val else None
    report_json_url = url_for("bp.report_sha_json", sha256=sha256_val, _external=False) if sha256_val else None

    sl = report.get("strings_llm", {}) or {}

    out: dict = {
        "status":      "done",
        "job_id":      job["job_id"],
        "verdict": {
            "risk_level": v.get("risk_level", "unknown"),
            "confidence":  v.get("confidence", 0),
            "file_type":   v.get("file_type", ""),
        },
        "top_reasons":  v.get("top_reasons", []),
        "heuristic_score": h.get("score", 0),
        "strings_score":   sl.get("strings_score", 0),
        "strings_summary": sl.get("summary", ""),
        "sha256":      sha256_val,
        "report_url":      report_url,
        "report_json_url": report_json_url,
        "tools_used":   tools_used,
        "tool_outputs": tool_outputs,
        "html_summary": _build_html_summary(
            risk_level=v.get("risk_level", "unknown"),
            confidence=v.get("confidence", 0),
            file_type=v.get("file_type", ""),
            sha256=sha256_val,
            report_url=report_url,
            report_json_url=report_json_url,
            heuristic_score=h.get("score", 0),
            top_reasons=v.get("top_reasons", []),
            strings_score=sl.get("strings_score", 0),
            strings_summary=sl.get("summary", ""),
        ),
    }


    # --- optional: images ---
    if "images" in include:
        images = {}
        for key, label in [
            ("entropy_profile",  "Entropy profile"),
            ("compression_curve","Compression curve"),
            ("bigram_matrix",    "Bigram matrix"),
        ]:
            vz = viz.get(key, {}) or {}
            if vz.get("ok") and vz.get("b64"):
                images[key] = {
                    "b64":            vz["b64"],
                    "description":    label,
                    "interpretation": vz.get("interpretation", ""),
                }
            elif vz.get("skipped"):
                images[key] = {"skipped": True, "reason": "not applicable for this file type"}
        out["images"] = images

    # --- optional: takens2d (PCA projection — already computed) ---
    if "takens2d" in include:
        tk = viz.get("takens_embedding", {}) or {}
        if tk.get("ok") and tk.get("b64"):
            out["takens2d"] = {
                "b64":            tk["b64"],           # PCA 2D PNG, already rendered
                "description":    "Byte trigram PCA 2D projection",
                "interpretation": tk.get("interpretation", ""),
            }
        else:
            out["takens2d"] = None

    return out


# ---------------------------------------------------------------------------
# Auth helper
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# POST /api/v1/upload  — stage a file for use with /analyze
# ---------------------------------------------------------------------------

@api_bp.post("/upload")
def api_upload():
    """
    Stage a file for analysis. Returns file_id, sha256, and whether it was
    already analyzed (cached=true → skip /analyze entirely).

    Accepts:
      - multipart/form-data  field "file"
      - JSON body            {"file_b64": "<base64>", "filename": "sample.exe"}

    Optional fields (either mode):
      archive_password — password for encrypted ZIP/RAR
    """
    key = verify_bearer(request.headers.get("Authorization"))
    if not key:
        resp = jsonify({"error": "Invalid or missing API key"})
        resp.headers["WWW-Authenticate"] = 'Bearer realm="malhaus"'
        resp.status_code = 401
        return resp

    body             = request.get_json(silent=True) or {}
    archive_password = (request.form.get("archive_password") or body.get("archive_password") or "").strip()

    # ── Resolve file content ─────────────────────────────────────────────────
    saved_path: Path | None = None
    orig_name: str = "upload"

    f = request.files.get("file")
    if f and f.filename:
        if request.content_length and request.content_length > config.MAX_UPLOAD_BYTES:
            return jsonify({"error": f"File too large. Max is {config.MAX_UPLOAD_MB} MB."}), 413
        orig_name   = os.path.basename(f.filename) or "upload"
        safe_suffix = Path(orig_name).suffix[:16]
        saved_path  = UPLOAD_DIR / f"{uuid.uuid4().hex}{safe_suffix}"
        try:
            f.save(saved_path)
        except Exception as e:
            return jsonify({"error": f"Save failed: {e}"}), 500

    elif body.get("file_b64"):
        import base64 as _b64
        orig_name   = os.path.basename(body.get("filename") or "upload")
        safe_suffix = Path(orig_name).suffix[:16]
        saved_path  = UPLOAD_DIR / f"{uuid.uuid4().hex}{safe_suffix}"
        try:
            raw = _b64.b64decode(body["file_b64"])
            if len(raw) > config.MAX_UPLOAD_BYTES:
                return jsonify({"error": f"File too large. Max is {config.MAX_UPLOAD_MB} MB."}), 413
            saved_path.write_bytes(raw)
        except Exception as e:
            return jsonify({"error": f"Base64 decode failed: {e}"}), 400

    else:
        return jsonify({"error": "Provide 'file' (multipart) or 'file_b64' (JSON base64)"}), 400

    # ── Compute SHA-256 ──────────────────────────────────────────────────────
    sha256_val = _sha256_file(saved_path)

    # ── Cache hit — already analyzed, no need to submit again ────────────────
    cached = _get_cached_recent(sha256_val)
    if cached and cached.get("report_json"):
        try:
            saved_path.unlink(missing_ok=True)
        except Exception:
            pass
        return jsonify({
            "sha256":      sha256_val,
            "cached":      True,
            "filename":    cached.get("filename", orig_name),
            "report_url":  url_for("bp.report_sha", sha256=sha256_val, _external=False),
            "expires_in":  None,
            "file_id":     None,
        }), 200

    # ── Stage for analysis ───────────────────────────────────────────────────
    file_id = str(uuid.uuid4())
    _staged_put(file_id, key["key_id"], str(saved_path), orig_name,
                archive_password=archive_password, sha256=sha256_val)

    return jsonify({
        "sha256":      sha256_val,
        "cached":      False,
        "file_id":     file_id,
        "filename":    orig_name,
        "expires_in":  STAGED_TTL,
        "analyze_url": url_for("api.api_analyze", _external=False),
    }), 201


# ---------------------------------------------------------------------------
# Auth helper
# ---------------------------------------------------------------------------

def _auth_error(msg: str, code: int = 401):
    resp = jsonify({"error": msg})
    if code == 401:
        resp.headers["WWW-Authenticate"] = 'Bearer realm="malhaus"'
    resp.status_code = code
    return resp


# ---------------------------------------------------------------------------
# POST /api/v1/analyze
# ---------------------------------------------------------------------------

@api_bp.post("/analyze")
def api_analyze():
    key = verify_bearer(request.headers.get("Authorization"))
    if not key:
        return _auth_error("Invalid or missing API key")

    if not api_rate_check(key["key_id"], key["rate_limit_per_hour"]):
        return _auth_error(
            f"Rate limit exceeded ({key['rate_limit_per_hour']}/hour)", 429
        )

    # --- input: sha256, file, file_b64, file_id, or url ---
    body     = request.get_json(silent=True) or {}
    sha256_lookup = (request.form.get("sha256") or body.get("sha256") or "").strip().lower()
    url      = (request.form.get("url")      or body.get("url")      or "").strip()
    file_id  = (request.form.get("file_id")  or body.get("file_id")  or "").strip()
    use_ghidra = bool(request.form.get("use_ghidra") or body.get("use_ghidra"))
    archive_password = (
        request.form.get("archive_password") or body.get("archive_password") or ""
    ).strip()

    # SHA-256 shortcut — if already analyzed, return immediately without a job
    if sha256_lookup:
        cached = _get_cached_recent(sha256_lookup)
        if cached and cached.get("report_json"):
            job_id = str(uuid.uuid4())
            _job_create(job_id, key["key_id"], cached.get("filename", ""))
            _job_update(
                job_id,
                status="done",
                sha256=sha256_lookup,
                result_json=cached["report_json"],
            )
            return jsonify({
                "job_id":     job_id,
                "status":     "done",
                "sha256":     sha256_lookup,
                "cached":     True,
                "report_url": url_for("bp.report_sha", sha256=sha256_lookup, _external=False),
                "status_url": url_for("api.api_job_status", job_id=job_id, _external=False),
            }), 200
        elif sha256_lookup and not (request.files.get("file") or body.get("file_b64") or file_id or url):
            return jsonify({"error": f"SHA-256 {sha256_lookup} not found in cache. Submit the file."}), 404

    saved_path: Path | None = None
    orig_name: str | None   = None

    f = request.files.get("file")
    if f and f.filename:
        # Direct multipart upload
        orig_name   = os.path.basename(f.filename) or "upload"
        safe_suffix = Path(orig_name).suffix[:16]
        saved_path  = UPLOAD_DIR / f"{uuid.uuid4().hex}{safe_suffix}"
        try:
            f.save(saved_path)
        except Exception as e:
            return jsonify({"error": f"Upload failed: {e}"}), 500
    elif body.get("file_b64"):
        # Base64-encoded file in JSON body
        import base64 as _b64
        orig_name   = os.path.basename(body.get("filename") or "upload")
        safe_suffix = Path(orig_name).suffix[:16]
        saved_path  = UPLOAD_DIR / f"{uuid.uuid4().hex}{safe_suffix}"
        try:
            raw = _b64.b64decode(body["file_b64"])
            if len(raw) > config.MAX_UPLOAD_BYTES:
                return jsonify({"error": f"File too large. Max is {config.MAX_UPLOAD_MB} MB."}), 413
            saved_path.write_bytes(raw)
        except Exception as e:
            return jsonify({"error": f"Base64 decode failed: {e}"}), 400
    elif file_id:
        # Two-step: file was pre-uploaded via POST /api/v1/upload
        staged = _staged_pop(file_id, key["key_id"])
        if not staged:
            return jsonify({"error": "file_id not found, wrong key, or expired (TTL 1 hour)"}), 404
        saved_path = Path(staged["path"])
        orig_name  = staged["filename"]
        # Inherit archive_password from staged record if caller didn't override
        if not archive_password and staged.get("archive_password"):
            archive_password = staged["archive_password"]
        if not saved_path.exists():
            return jsonify({"error": "Staged file no longer exists on disk"}), 410
    elif url:
        orig_name = os.path.basename(url.split("?")[0]) or "downloaded.bin"
    else:
        return jsonify({"error": "Provide 'file' (multipart), 'file_id', or 'url'"}), 400

    job_id = str(uuid.uuid4())
    _job_create(job_id, key["key_id"], orig_name or "")

    # Run analysis in background thread
    _opts = {
        "use_ghidra":       use_ghidra,
        "archive_password": archive_password,
    }
    _key_id    = key["key_id"]
    _url       = url
    _orig_name = orig_name

    def _run():
        slot_id = None
        path    = saved_path
        try:
            _job_update(job_id, status="running")

            # URL download (if needed)
            if _url and path is None:
                try:
                    path, _ = _download_url_to_file(
                        _url, UPLOAD_DIR, config.MAX_UPLOAD_BYTES
                    )
                except (ValueError, http_requests.RequestException) as e:
                    _job_update(job_id, status="failed", error=str(e))
                    return

            # File type check
            kind = detect_file_type(str(path))
            if kind not in ALLOWED_KINDS:
                _job_update(
                    job_id, status="failed",
                    error=f"Unsupported file type: {kind}",
                )
                try:
                    path.unlink(missing_ok=True)
                except Exception:
                    pass
                return

            sha256_val = _sha256_file(path)
            _job_update(job_id, sha256=sha256_val)

            # Cache hit — re-use existing report
            cached = _get_cached_recent(sha256_val)
            if cached and cached.get("report_json"):
                _job_update(
                    job_id,
                    status="done",
                    sha256=sha256_val,
                    result_json=cached["report_json"],
                )
                try:
                    path.unlink(missing_ok=True)
                except Exception:
                    pass
                return

            # Concurrency slot
            slot_id = _acquire_analysis_slot(_orig_name or "")
            if slot_id is None:
                _job_update(
                    job_id, status="failed",
                    error="Server busy — another analysis is in progress. Retry shortly.",
                )
                try:
                    path.unlink(missing_ok=True)
                except Exception:
                    pass
                return
            _update_analysis_slot(slot_id, sha256_val)

            # Run analysis
            result = analyze(str(path), options=_opts)

            if result.get("aborted"):
                reason = result.get("abort_reason", "unknown")
                msg = {
                    "wrong_password": "Archive extraction failed — wrong or missing password.",
                }.get(reason, f"Analysis aborted: {reason}")
                _job_update(job_id, status="failed", error=msg)
                return

            # Persist to web_recents so it appears in the index
            _v    = result.get("verdict", {}) or {}
            _h    = result.get("heuristics", {}) or {}
            _pre  = result.get("preflight", {}) or {}
            _kind = _pre.get("kind") or kind
            _cont = _pre.get("container_kind", "")
            _dkind = f"{_cont}→{_kind}" if _cont else _kind
            result_json = json.dumps(result)
            _write_recent(
                _orig_name or "sample", sha256_val, _dkind,
                f"api:{_key_id[:8]}",
                _v.get("risk_level", "unknown"),
                int(_v.get("confidence", 0) or 0),
                int(_h.get("score", 0) or 0),
                result_json,
            )

            _job_update(
                job_id,
                status="done",
                sha256=sha256_val,
                result_json=result_json,
            )

        except Exception as e:
            _job_update(job_id, status="failed", error=str(e))
        finally:
            if slot_id is not None:
                _release_analysis_slot(slot_id)
            if path and path != saved_path:
                try:
                    path.unlink(missing_ok=True)
                except Exception:
                    pass
            elif saved_path:
                try:
                    saved_path.unlink(missing_ok=True)
                except Exception:
                    pass

    threading.Thread(target=_run, daemon=True).start()

    return jsonify({
        "job_id":     job_id,
        "status":     "pending",
        "status_url": url_for("api.api_job_status", job_id=job_id, _external=False),
    }), 202


# ---------------------------------------------------------------------------
# GET /api/v1/jobs/<job_id>
# ---------------------------------------------------------------------------

@api_bp.get("/jobs/<job_id>")
def api_job_status(job_id: str):
    key = verify_bearer(request.headers.get("Authorization"))
    if not key:
        return _auth_error("Invalid or missing API key")

    job = _job_get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404

    # Only the key that submitted can poll the job
    if job["key_id"] != key["key_id"]:
        return jsonify({"error": "Job not found"}), 404

    status = job["status"]

    if status in ("pending", "running"):
        return jsonify({"status": status, "job_id": job_id}), 200

    if status == "failed":
        return jsonify({"status": "failed", "job_id": job_id, "error": job["error"]}), 200

    # status == "done"
    include_raw = request.args.get("include", "")
    include = {s.strip() for s in include_raw.split(",") if s.strip()}

    try:
        result = _build_result(job, include)
    except Exception as e:
        return jsonify({"status": "done", "job_id": job_id, "error": f"Result parse error: {e}"}), 500

    return jsonify(result), 200
