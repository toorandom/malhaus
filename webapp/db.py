import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

BASE_DIR = Path(__file__).resolve().parents[1]
DB_PATH = BASE_DIR / "maltriage.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
  sha256 TEXT PRIMARY KEY,
  filename TEXT,
  kind TEXT,
  risk_level TEXT,
  confidence INTEGER,
  score INTEGER,
  analyzed_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_analyses_time ON analyses(analyzed_at DESC);
"""

def _connect() -> sqlite3.Connection:
  conn = sqlite3.connect(str(DB_PATH))
  conn.row_factory = sqlite3.Row
  conn.execute("PRAGMA journal_mode=WAL;")
  conn.execute("PRAGMA synchronous=NORMAL;")
  return conn

def init_db() -> None:
  conn = _connect()
  try:
    conn.executescript(SCHEMA)
    conn.commit()
  finally:
    conn.close()

def upsert_analysis(row: Dict[str, Any]) -> None:
  init_db()
  conn = _connect()
  try:
    conn.execute(
      """
      INSERT INTO analyses(sha256, filename, kind, risk_level, confidence, score, analyzed_at)
      VALUES(?,?,?,?,?,?, datetime('now'))
      ON CONFLICT(sha256) DO UPDATE SET
        filename=excluded.filename,
        kind=excluded.kind,
        risk_level=excluded.risk_level,
        confidence=excluded.confidence,
        score=excluded.score,
        analyzed_at=datetime('now')
      """,
      (
        row.get("sha256"),
        row.get("filename"),
        row.get("kind"),
        row.get("risk_level"),
        int(row.get("confidence") or 0),
        int(row.get("score") or 0),
      ),
    )
    conn.commit()
  finally:
    conn.close()

def last_analyses(limit: int = 10) -> List[Dict[str, Any]]:
  init_db()
  conn = _connect()
  try:
    rows = conn.execute(
      "SELECT sha256, filename, kind, risk_level, confidence, score, analyzed_at FROM analyses ORDER BY analyzed_at DESC LIMIT ?",
      (int(limit),),
    ).fetchall()
    return [dict(r) for r in rows]
  finally:
    conn.close()
