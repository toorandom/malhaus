import sqlite3
from pathlib import Path
from typing import Optional, Any

def get_conn(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.execute("""CREATE TABLE IF NOT EXISTS cache(
        sha TEXT PRIMARY KEY,
        result TEXT
    )""")
    return conn

def get_cached(conn: sqlite3.Connection, sha: str) -> Optional[str]:
    row = conn.execute("SELECT result FROM cache WHERE sha=?", (sha,)).fetchone()
    return row[0] if row else None

def put_cached(conn: sqlite3.Connection, sha: str, result_json: str) -> None:
    conn.execute("INSERT OR REPLACE INTO cache VALUES (?,?)", (sha, result_json))
    conn.commit()
