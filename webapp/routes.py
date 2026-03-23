import os
import re
import hashlib
import json
import time
import sqlite3
import socket
import ipaddress
import uuid
import shutil
import threading
import queue
from pathlib import Path
from urllib.parse import urlparse
import requests
from flask import stream_with_context
from tools.cli_tools import detect_file_type
from flask import Blueprint, render_template, request, redirect, url_for, flash, make_response, current_app, jsonify

from agent.triage_agent import analyze
import config

bp = Blueprint("bp", __name__)


BASE_DIR = Path(__file__).resolve().parents[1]
DB_PATH = BASE_DIR / "maltriage.db"
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)


def _client_ip(req) -> str:
    # Only trust X-Forwarded-For when running behind a known trusted proxy
    # (set MALHAUS_TRUSTED_PROXY=1 in config.source if behind nginx/caddy/etc.)
    if os.environ.get("MALHAUS_TRUSTED_PROXY") == "1":
        xff = req.headers.get("X-Forwarded-For", "").strip()
        if xff:
            candidate = xff.split(",")[0].strip()
            try:
                ipaddress.ip_address(candidate)  # validate it's a real IP
                return candidate
            except ValueError:
                pass
    return (req.remote_addr or "unknown").strip()


def _db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def _ensure_tables():
    con = _db()
    try:
        # rate limit table
        con.execute("""
        CREATE TABLE IF NOT EXISTS rate_limits (
            ip TEXT NOT NULL,
            ts INTEGER NOT NULL
        )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_rate_ip_ts ON rate_limits(ip, ts)")

        # guaranteed recents table for homepage
        con.execute("""
        CREATE TABLE IF NOT EXISTS web_recents (
            analyzed_at TEXT NOT NULL,
            filename TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            kind TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            confidence INTEGER NOT NULL,
            score INTEGER NOT NULL
        )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_web_recents_time ON web_recents(analyzed_at)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_web_recents_sha ON web_recents(sha256)")

        # cross-process concurrency slot table
        con.execute("""
        CREATE TABLE IF NOT EXISTS active_analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at INTEGER NOT NULL,
            filename TEXT NOT NULL DEFAULT '',
            sha256 TEXT NOT NULL DEFAULT ''
        )
        """)

        # migrations
        for _col, _def in [
            ("web_recents", "ip TEXT"),
            ("web_recents", "report_json TEXT"),
            ("active_analyses", "filename TEXT NOT NULL DEFAULT ''"),
            ("active_analyses", "sha256 TEXT NOT NULL DEFAULT ''"),
        ]:
            try:
                con.execute(f"ALTER TABLE {_col} ADD COLUMN {_def}")
            except sqlite3.OperationalError:
                pass

        con.commit()
    finally:
        con.close()


def _acquire_analysis_slot(filename: str = "") -> int | None:
    """Insert a slot row if under MAX_CONCURRENT. Returns row id on success, None if full.
    Also evicts stale slots older than 1 hour (crashed workers)."""
    _ensure_tables()
    con = _db()
    con.isolation_level = None
    try:
        con.execute("BEGIN EXCLUSIVE")
        stale_cutoff = int(time.time()) - 3600
        con.execute("DELETE FROM active_analyses WHERE started_at < ?", (stale_cutoff,))
        row = con.execute("SELECT COUNT(*) FROM active_analyses").fetchone()
        if row[0] >= config.MAX_CONCURRENT:
            con.execute("ROLLBACK")
            return None
        cur = con.execute(
            "INSERT INTO active_analyses(started_at, filename) VALUES(?,?)",
            (int(time.time()), filename),
        )
        slot_id = cur.lastrowid
        con.execute("COMMIT")
        return slot_id
    except Exception:
        try:
            con.execute("ROLLBACK")
        except Exception:
            pass
        return None
    finally:
        con.close()


def _update_analysis_slot(slot_id: int, sha256: str) -> None:
    try:
        con = _db()
        try:
            con.execute("UPDATE active_analyses SET sha256=? WHERE id=?", (sha256, slot_id))
            con.commit()
        finally:
            con.close()
    except Exception:
        pass


def _get_active_analyses() -> list:
    """Return list of dicts with filename/sha256 for currently running analyses."""
    try:
        con = _db()
        try:
            rows = con.execute(
                "SELECT filename, sha256 FROM active_analyses ORDER BY started_at"
            ).fetchall()
            return [{"filename": r[0], "sha256": r[1]} for r in rows]
        finally:
            con.close()
    except Exception:
        return []


def _release_analysis_slot(slot_id: int) -> None:
    try:
        con = _db()
        try:
            con.execute("DELETE FROM active_analyses WHERE id = ?", (slot_id,))
            con.commit()
        finally:
            con.close()
    except Exception:
        pass


def _used_in_last_hour(ip: str) -> int:
    _ensure_tables()
    now = int(time.time())
    window_start = now - 3600
    con = _db()
    try:
        row = con.execute(
            "SELECT COUNT(*) AS c FROM rate_limits WHERE ip = ? AND ts >= ?",
            (ip, window_start),
        ).fetchone()
        return int(row["c"])
    finally:
        con.close()


def _rate_check_and_record(ip: str) -> tuple[bool, int]:
    _ensure_tables()
    now = int(time.time())
    window_start = now - 3600
    con = _db()
    con.isolation_level = None
    try:
        con.execute("BEGIN EXCLUSIVE")
        c = int(con.execute(
            "SELECT COUNT(*) AS c FROM rate_limits WHERE ip = ? AND ts >= ?",
            (ip, window_start),
        ).fetchone()["c"])
        if c >= config.MAX_PER_HOUR_PER_IP:
            con.execute("ROLLBACK")
            return (False, 0)
        con.execute("INSERT INTO rate_limits(ip, ts) VALUES(?, ?)", (ip, now))
        con.execute("COMMIT")
        remaining = config.MAX_PER_HOUR_PER_IP - (c + 1)
        return (True, remaining)
    except Exception:
        try:
            con.execute("ROLLBACK")
        except Exception:
            pass
        return (False, 0)
    finally:
        con.close()


def _fetch_recents(limit: int = 10, offset: int = 0):
    _ensure_tables()
    con = _db()
    try:
        return con.execute(
            """
            SELECT analyzed_at, filename, sha256, kind, ip, risk_level, confidence, score
            FROM web_recents
            ORDER BY analyzed_at DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        ).fetchall()
    finally:
        con.close()



def _extract_sha256_from_result(result: dict) -> str:
    try:
        pre = result.get("preflight", {}) or {}
        sh = (pre.get("sha256", {}) or {}).get("stdout", "") or ""
        tok = sh.split()
        if tok:
            return tok[0]
    except Exception:
        pass
    return ""


def _extract_kind_from_result(result: dict) -> str:
    pre = result.get("preflight", {}) or {}
    return (pre.get("kind") or pre.get("file_type") or "").strip() or (result.get("verdict", {}) or {}).get("file_type", "") or "unknown"



def _get_cached_recent(sha256: str):
    """Return latest cached row from web_recents for a SHA256, or None."""
    import sqlite3
    from pathlib import Path

    db_path = Path(__file__).resolve().parents[1] / "maltriage.db"
    con = sqlite3.connect(str(db_path))
    con.row_factory = sqlite3.Row
    try:
        cur = con.cursor()
        cur.execute(
            """SELECT analyzed_at, filename, sha256, kind, ip, risk_level, confidence, score, report_json
               FROM web_recents
               WHERE sha256 = ?
               ORDER BY analyzed_at DESC
               LIMIT 1""",
            (sha256,),
        )
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        con.close()

def _write_recent(filename: str, sha256: str, kind: str, ip: str, risk: str, conf: int, score: int, report_json: str):
    _ensure_tables()
    analyzed_at = time.strftime("%Y-%m-%d %H:%M:%S")
    con = _db()
    try:
        con.execute(
            """
            INSERT INTO web_recents(analyzed_at, filename, sha256, kind, ip, risk_level, confidence, score, report_json)
            VALUES(?,?,?,?,?,?,?,?,?)
            """,
            (analyzed_at, filename, sha256, kind, ip, risk, int(conf), int(score), report_json),
        )
        # keep table small (last 200)
        con.execute("""
          DELETE FROM web_recents
          WHERE rowid NOT IN (
            SELECT rowid FROM web_recents ORDER BY analyzed_at DESC LIMIT 200
          )
        """)
        con.commit()
    finally:
        con.close()


_PRIVATE_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local / cloud metadata
    ipaddress.ip_network("100.64.0.0/10"),    # carrier-grade NAT
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

def _is_private_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
        return any(ip in net for net in _PRIVATE_NETS)
    except ValueError:
        return True  # unparseable — treat as unsafe

def _check_ssrf(hostname: str) -> None:
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        raise ValueError(f"Could not resolve hostname: {e}")
    for info in infos:
        addr = info[4][0]
        if _is_private_ip(addr):
            raise ValueError(f"URL resolves to a private/reserved address ({addr}) — blocked.")

def _download_url_to_file(url: str, out_dir: Path, max_bytes: int) -> tuple[Path, str]:
    """Returns (saved_path, original_filename)."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http/https URLs are supported")

    _check_ssrf(parsed.hostname or "")

    # Preserve original name for display only; save under a UUID to avoid path traversal
    orig_name = os.path.basename(parsed.path) or "downloaded.bin"
    safe_suffix = Path(orig_name).suffix[:16]  # keep extension for file(1) detection
    out_path = out_dir / f"{uuid.uuid4().hex}{safe_suffix}"

    # Total download budget: 10 seconds per allowed MB (e.g. 10 MB → 100 s)
    total_timeout = 10 * config.MAX_UPLOAD_MB
    deadline = time.time() + total_timeout

    with requests.get(url, stream=True, timeout=(10, 30), allow_redirects=True) as r:
        r.raise_for_status()

        cl = r.headers.get("Content-Length")
        if cl and cl.isdigit() and int(cl) > max_bytes:
            raise ValueError(f"URL content too large (max {config.MAX_UPLOAD_MB} MB)")

        total = 0
        with open(out_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=1024 * 128):
                if not chunk:
                    continue
                if time.time() > deadline:
                    f.close()
                    try:
                        out_path.unlink(missing_ok=True)
                    except Exception:
                        pass
                    raise ValueError(f"Download exceeded time limit ({total_timeout}s for {config.MAX_UPLOAD_MB} MB max)")
                total += len(chunk)
                if total > max_bytes:
                    f.close()
                    try:
                        out_path.unlink(missing_ok=True)
                    except Exception:
                        pass
                    raise ValueError(f"Downloaded content exceeds max {config.MAX_UPLOAD_MB} MB")
                f.write(chunk)

    return out_path, orig_name


@bp.get("/")
def index():
    page = int(request.args.get("page", "1") or "1")
    if page < 1: page = 1
    limit = 10
    offset = (page - 1) * limit

    ip = _client_ip(request)
    used = _used_in_last_hour(ip)
    remaining = max(0, config.MAX_PER_HOUR_PER_IP - used)

    recents = _fetch_recents(limit=limit, offset=offset)
    total_recent = recent_count()
    has_prev = page > 1
    has_next = (offset + limit) < total_recent
    html = render_template("index.html", page=page, has_prev=has_prev, has_next=has_next,
        recents=recents,
        max_mb=config.MAX_UPLOAD_MB,
        ip=ip,
        remaining=remaining,
        max_per_hour=config.MAX_PER_HOUR_PER_IP,
    )
    resp = make_response(html)
    # Force refresh when hitting back
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    return resp


@bp.get("/about")
def about():
    return render_template("about.html")



@bp.get("/report/<sha256>")
def report_sha(sha256: str):
    """
    View cached result by sha256 (no re-analysis).
    """
    _ensure_tables()
    con = _db()
    try:
        row = con.execute(
            "SELECT sha256 FROM web_recents WHERE sha256 = ? ORDER BY analyzed_at DESC LIMIT 1",
            (sha256,),
        ).fetchone()
    finally:
        con.close()

    if not row:
        flash("No cached report found for that SHA-256.", "error")
        return redirect(url_for("bp.index"))

    # Your analyze() already caches by sha256; we call analyze on the stored upload path would fail.
    # So: load cached artifact from agent cache DB/file if you have it.
    # Minimal approach: triage_agent already returns cached results by sha256 internally when same file is re-submitted.
    # We'll store full result JSON for web in a cache table.
    rec = None
    con = _db()
    try:
        rec = con.execute(
            "SELECT filename, report_json FROM web_recents WHERE sha256 = ? ORDER BY analyzed_at DESC LIMIT 1",
            (sha256,),
        ).fetchone()
    finally:
        con.close()

    if not rec or not rec["report_json"]:
        flash("No cached report JSON stored for that SHA-256 yet.", "error")
        return redirect(url_for("bp.index"))

    result = json.loads(rec["report_json"])
    try:
        filename = rec["filename"]
    except (IndexError, KeyError):
        filename = None
    return render_template("report.html", result=result, filename=filename, sha256=sha256, ip=_client_ip(request), remaining=max(0, config.MAX_PER_HOUR_PER_IP - _used_in_last_hour(_client_ip(request))), llm_debug=config.LLM_DEBUG_IN_REPORT)


@bp.get("/report/<sha256>/json")
def report_sha_json(sha256: str):
    """Return the raw analysis JSON for a given SHA-256 (same data as the web report)."""
    _ensure_tables()
    con = _db()
    try:
        rec = con.execute(
            "SELECT report_json FROM web_recents WHERE sha256 = ? ORDER BY analyzed_at DESC LIMIT 1",
            (sha256,),
        ).fetchone()
    finally:
        con.close()
    if not rec or not rec["report_json"]:
        return jsonify({"error": "No report found for that SHA-256"}), 404
    return current_app.response_class(
        rec["report_json"], status=200, mimetype="application/json"
    )


def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

@bp.post("/upload")
def upload():
    ip = _client_ip(request)

    allowed, remaining = _rate_check_and_record(ip)
    if not allowed:
        flash(f"Rate limit: max {config.MAX_PER_HOUR_PER_IP} submissions/hour for {ip}.", "error")
        return redirect(url_for("bp.index"))

    sha_lookup = (request.form.get("sha256_lookup") or "").strip().lower()
    use_ghidra = (request.form.get("use_ghidra") == "1")

    if sha_lookup and re.fullmatch(r"[0-9a-f]{64}", sha_lookup):
        return redirect(url_for("bp.report_sha", sha256=sha_lookup))

    f = request.files.get("file")
    # File takes priority over URL — if a file is chosen, ignore any URL in the form
    url = "" if (f and f.filename) else (request.form.get("url") or "").strip()
    if not url and (not f or not f.filename):
        flash("Provide a file OR an http/https URL OR a SHA-256.", "error")
        return redirect(url_for("bp.index"))

    # Validate URL scheme + SSRF early so we can redirect immediately on bad input
    if url:
        try:
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https"):
                raise ValueError("Only http/https URLs are supported")
            _check_ssrf(parsed.hostname or "")
        except ValueError as e:
            flash(str(e), "error")
            return redirect(url_for("bp.index"))

    # For file uploads, save to disk now (quick); URL downloads happen inside the stream
    saved_path: Path | None = None
    orig_name: str | None = None
    if not url:
        if request.content_length and request.content_length > config.MAX_UPLOAD_BYTES:
            flash(f"File too large. Max is {config.MAX_UPLOAD_MB} MB.", "error")
            return redirect(url_for("bp.index"))
        orig_name = os.path.basename(f.filename) or "upload"
        safe_suffix = Path(orig_name).suffix[:16]
        saved_path = UPLOAD_DIR / f"{uuid.uuid4().hex}{safe_suffix}"
        try:
            f.save(saved_path)
        except Exception as e:
            flash(f"Upload failed: {e}", "error")
            return redirect(url_for("bp.index"))

    archive_password = (request.form.get("archive_password") or "").strip()
    _url, _saved_path, _orig_name, _ip, _remaining, _use_ghidra, _archive_password = \
        url, saved_path, orig_name, ip, remaining, use_ghidra, archive_password

    ALLOWED_KINDS = {"pe", "elf", "office", "office_openxml", "ps1", "shell", "js", "msi",
                     "pdf", "lnk", "vbs", "hta", "archive"}

    def _stream():
        path = _saved_path
        orig = _orig_name
        slot_id = None
        try:
            # URL download happens here so we can show "Downloading URL" to the user
            if _url:
                yield f"data: {json.dumps({'msg': 'Downloading URL'})}\n\n"
                try:
                    path, orig = _download_url_to_file(_url, UPLOAD_DIR, config.MAX_UPLOAD_BYTES)
                except requests.RequestException as e:
                    yield f"data: {json.dumps({'error': f'URL download failed: {e}'})}\n\n"
                    return
                except ValueError as e:
                    yield f"data: {json.dumps({'error': str(e)})}\n\n"
                    return

            sha256_val = _sha256_file(path)
            kind = detect_file_type(str(path))

            if kind not in ALLOWED_KINDS:
                yield f"data: {json.dumps({'error': f'Unsupported file type: {kind}. Allowed: {sorted(ALLOWED_KINDS)}'})}\n\n"
                return

            # Cache hit — redirect immediately, do NOT write a new row (avoids duplicates)
            cached = _get_cached_recent(sha256_val)
            if cached and cached.get("report_json"):
                yield f"data: {json.dumps({'redirect': url_for('bp.report_sha', sha256=sha256_val)})}\n\n"
                return

            # Acquire concurrency slot — checked here (inside stream) so we can send
            # a proper SSE error instead of an invisible redirect.
            slot_id = _acquire_analysis_slot(orig or "")
            if slot_id is None:
                running = _get_active_analyses()
                if running:
                    r = running[0]
                    detail = r["filename"] or ""
                    if r["sha256"]:
                        detail += f" ({r['sha256'][:16]}…)" if detail else r["sha256"][:16] + "…"
                    msg = f"Another analysis is in progress: {detail}. Please wait and try again." if detail else "Another analysis is in progress. Please wait and try again."
                else:
                    msg = "Another analysis is in progress. Please wait and try again."
                yield f"data: {json.dumps({'error': msg})}\n\n"
                return

            # Update slot with sha256 now that we have it
            _update_analysis_slot(slot_id, sha256_val)

            # Run analysis in background thread, stream progress events
            q: queue.Queue = queue.Queue()
            holder: dict = {}

            def _run():
                try:
                    result = analyze(
                        str(path),
                        options={"use_ghidra": _use_ghidra, "archive_password": _archive_password},
                        progress_cb=lambda msg: q.put(("msg", msg)),
                    )
                    holder["result"] = result
                    # Write to DB immediately inside the thread so the result is
                    # always cached even if the client disconnected mid-stream.
                    if not result.get("aborted"):
                        _v = result.get("verdict", {}) or {}
                        _h = result.get("heuristics", {}) or {}
                        _pre = result.get("preflight", {}) or {}
                        _inner = _pre.get("kind") or kind
                        _container = _pre.get("container_kind", "")
                        _dkind = f"{_container}→{_inner}" if _container else _inner
                        _write_recent(
                            orig or "sample", sha256_val, _dkind, _ip,
                            _v.get("risk_level", "unknown"),
                            int(_v.get("confidence", 0) or 0),
                            int(_h.get("score", 0) or 0),
                            json.dumps(result),
                        )
                except Exception as e:
                    holder["error"] = str(e)
                finally:
                    q.put(("done", None))

            t = threading.Thread(target=_run, daemon=True)
            t.start()

            while True:
                ev_kind, data = q.get()
                if ev_kind == "msg":
                    yield f"data: {json.dumps({'msg': data})}\n\n"
                else:
                    break

            t.join()

            try:
                path.unlink(missing_ok=True)
            except Exception:
                pass
            _cleanup_extracted(max_age_seconds=3600)

            if "error" in holder:
                yield f"data: {json.dumps({'error': holder['error']})}\n\n"
                return

            result = holder["result"]

            if result.get("aborted"):
                reason = result.get("abort_reason", "unknown")
                msg = {
                    "wrong_password": "Archive extraction failed — wrong or missing password. Please resubmit with the correct password.",
                }.get(reason, f"Analysis aborted: {reason}.")
                yield f"data: {json.dumps({'error': msg})}\n\n"
                return

            yield f"data: {json.dumps({'redirect': url_for('bp.report_sha', sha256=sha256_val)})}\n\n"

        finally:
            if slot_id is not None:
                _release_analysis_slot(slot_id)
            if path and path != _saved_path:
                try:
                    path.unlink(missing_ok=True)
                except Exception:
                    pass

    return current_app.response_class(
        stream_with_context(_stream()),
        mimetype="text/event-stream",
        headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache"},
    )


def _cleanup_extracted(max_age_seconds: int = 3600) -> None:
    extract_dir = BASE_DIR / "extracted"
    if not extract_dir.is_dir():
        return
    cutoff = time.time() - max_age_seconds
    for entry in extract_dir.iterdir():
        try:
            if entry.stat().st_mtime < cutoff:
                if entry.is_dir():
                    shutil.rmtree(entry, ignore_errors=True)
                else:
                    entry.unlink(missing_ok=True)
        except Exception:
            pass


# --- pagination helper ---
def recent_count():
    import sqlite3
    from pathlib import Path
    db_path = Path(__file__).resolve().parents[1] / 'maltriage.db'
    con = sqlite3.connect(str(db_path))
    try:
        cur = con.cursor()
        cur.execute('SELECT COUNT(1) FROM web_recents')
        return int(cur.fetchone()[0] or 0)
    finally:
        con.close()


# --- web_recents pagination helpers ---
def list_web_recents(limit: int = 10, offset: int = 0):
    import sqlite3
    from pathlib import Path
    db_path = Path(__file__).resolve().parents[1] / "maltriage.db"
    con = sqlite3.connect(str(db_path))
    con.row_factory = sqlite3.Row
    try:
        cur = con.cursor()
        cur.execute(
            """SELECT time, filename, sha256, file_type, ip, risk, confidence, score
               FROM web_recents
               ORDER BY time DESC
               LIMIT ? OFFSET ?""",
            (int(limit), int(offset)),
        )
        return [dict(r) for r in cur.fetchall()]
    finally:
        con.close()
