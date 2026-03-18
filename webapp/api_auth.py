"""
API key management helpers.

Key format  : mh_<64 hex chars>   (prefix + 32 random bytes hex = 256-bit secret)
Storage     : SHA-256(secret_part) — plaintext key is never stored
Rate limits : api_rate_limits table, keyed by key_id
"""
import hashlib
import secrets
import sqlite3
import time
import uuid
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
DB_PATH  = BASE_DIR / "maltriage.db"
KEY_PREFIX = "mh_"


def _db() -> sqlite3.Connection:
    con = sqlite3.connect(str(DB_PATH))
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    return con


def ensure_api_tables() -> None:
    con = _db()
    try:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS api_keys (
            key_id            TEXT    PRIMARY KEY,
            key_hash          TEXT    NOT NULL UNIQUE,
            label             TEXT    NOT NULL,
            created_at        INTEGER NOT NULL,
            last_used_at      INTEGER,
            revoked           INTEGER NOT NULL DEFAULT 0,
            rate_limit_per_hour INTEGER NOT NULL DEFAULT 60
        );
        CREATE TABLE IF NOT EXISTS api_jobs (
            job_id      TEXT    PRIMARY KEY,
            key_id      TEXT    NOT NULL,
            status      TEXT    NOT NULL DEFAULT 'pending',
            created_at  INTEGER NOT NULL,
            updated_at  INTEGER NOT NULL,
            sha256      TEXT,
            filename    TEXT,
            result_json TEXT,
            error       TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_api_jobs_key     ON api_jobs(key_id);
        CREATE INDEX IF NOT EXISTS idx_api_jobs_created ON api_jobs(created_at);
        CREATE TABLE IF NOT EXISTS api_rate_limits (
            key_id TEXT NOT NULL,
            ts     INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_api_rl_key_ts ON api_rate_limits(key_id, ts);
        CREATE TABLE IF NOT EXISTS api_staged_files (
            file_id    TEXT    PRIMARY KEY,
            key_id     TEXT    NOT NULL,
            path       TEXT    NOT NULL,
            filename   TEXT    NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_api_staged_key ON api_staged_files(key_id);
        """)
        # Migrations — safe to run on existing DBs
        for _tbl, _col_def in [
            ("api_staged_files", "archive_password TEXT NOT NULL DEFAULT ''"),
            ("api_staged_files", "sha256 TEXT NOT NULL DEFAULT ''"),
        ]:
            try:
                con.execute(f"ALTER TABLE {_tbl} ADD COLUMN {_col_def}")
            except sqlite3.OperationalError:
                pass
        con.commit()
    finally:
        con.close()


def _hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Key verification
# ---------------------------------------------------------------------------

def verify_bearer(auth_header: str | None) -> dict | None:
    """
    Parse and validate an Authorization: Bearer mh_<secret> header.
    Returns key row dict on success, None on failure.
    Updates last_used_at as a side effect.
    """
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    token = auth_header[7:].strip()
    if not token.startswith(KEY_PREFIX):
        return None
    secret = token[len(KEY_PREFIX):]
    if len(secret) != 64:          # 32 bytes hex = exactly 64 chars
        return None
    h = _hash_secret(secret)
    ensure_api_tables()
    con = _db()
    try:
        row = con.execute(
            "SELECT key_id, label, revoked, rate_limit_per_hour "
            "FROM api_keys WHERE key_hash = ?",
            (h,),
        ).fetchone()
        if not row or row["revoked"]:
            return None
        con.execute(
            "UPDATE api_keys SET last_used_at = ? WHERE key_id = ?",
            (int(time.time()), row["key_id"]),
        )
        con.commit()
        return dict(row)
    finally:
        con.close()


# ---------------------------------------------------------------------------
# Per-key rate limiting
# ---------------------------------------------------------------------------

def api_rate_check(key_id: str, limit_per_hour: int) -> bool:
    """
    Returns True and records the request if within rate limit.
    Returns False if limit exceeded.
    """
    con = _db()
    now = int(time.time())
    window_start = now - 3600
    con.isolation_level = None
    try:
        con.execute("BEGIN EXCLUSIVE")
        c = int(con.execute(
            "SELECT COUNT(*) FROM api_rate_limits WHERE key_id = ? AND ts >= ?",
            (key_id, window_start),
        ).fetchone()[0])
        if c >= limit_per_hour:
            con.execute("ROLLBACK")
            return False
        con.execute(
            "INSERT INTO api_rate_limits(key_id, ts) VALUES(?, ?)",
            (key_id, now),
        )
        con.execute("COMMIT")
        return True
    except Exception:
        try:
            con.execute("ROLLBACK")
        except Exception:
            pass
        return False
    finally:
        con.close()


# ---------------------------------------------------------------------------
# Key CRUD (used by manage_keys.py)
# ---------------------------------------------------------------------------

def create_key(label: str, rate_limit_per_hour: int = 60) -> tuple[str, str]:
    """
    Create a new API key.
    Returns (full_token, key_id).  full_token is shown once and never stored.
    """
    ensure_api_tables()
    secret   = secrets.token_hex(32)          # 256-bit random secret
    token    = KEY_PREFIX + secret
    key_id   = str(uuid.uuid4())
    key_hash = _hash_secret(secret)
    con = _db()
    try:
        con.execute(
            "INSERT INTO api_keys(key_id, key_hash, label, created_at, revoked, rate_limit_per_hour) "
            "VALUES(?, ?, ?, ?, 0, ?)",
            (key_id, key_hash, label, int(time.time()), rate_limit_per_hour),
        )
        con.commit()
    finally:
        con.close()
    return token, key_id


def revoke_key(key_id: str) -> bool:
    ensure_api_tables()
    con = _db()
    try:
        cur = con.execute(
            "UPDATE api_keys SET revoked = 1 WHERE key_id = ?",
            (key_id,),
        )
        con.commit()
        return cur.rowcount > 0
    finally:
        con.close()


def list_keys() -> list[dict]:
    ensure_api_tables()
    con = _db()
    try:
        rows = con.execute(
            "SELECT key_id, label, created_at, last_used_at, revoked, rate_limit_per_hour "
            "FROM api_keys ORDER BY created_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        con.close()
