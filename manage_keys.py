#!/usr/bin/env python3
"""
Admin CLI for malhaus API key management.

Usage:
  python manage_keys.py create  --label "Alice" [--rate-limit 60]
  python manage_keys.py list
  python manage_keys.py revoke  <key_id>
  python manage_keys.py info    <key_id>
  python manage_keys.py cleanup-jobs [--days 30]
"""
import argparse
import sys
import sqlite3
import time
from pathlib import Path

# Allow running from repo root without installing the package
sys.path.insert(0, str(Path(__file__).resolve().parent))
from webapp.api_auth import create_key, revoke_key, list_keys, ensure_api_tables, DB_PATH


def _fmt_ts(ts: int | None) -> str:
    if ts is None:
        return "never"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def cmd_create(args):
    token, key_id = create_key(args.label, args.rate_limit)
    print()
    print("  API key created — store this token securely. It will NOT be shown again.")
    print()
    print(f"  Token  : {token}")
    print(f"  Key ID : {key_id}")
    print(f"  Label  : {args.label}")
    print(f"  Rate   : {args.rate_limit} requests/hour")
    print()
    print("  Usage:")
    print(f'    curl -H "Authorization: Bearer {token}" ...')
    print()


def cmd_list(args):
    keys = list_keys()
    if not keys:
        print("No API keys found.")
        return
    print()
    fmt = "  {:<36}  {:<20}  {:<8}  {:<19}  {:<19}  {:>6}/h"
    print(fmt.format("key_id", "label", "status", "created", "last_used", "rate"))
    print("  " + "-" * 110)
    for k in keys:
        status = "REVOKED" if k["revoked"] else "active"
        print(fmt.format(
            k["key_id"],
            k["label"][:20],
            status,
            _fmt_ts(k["created_at"]),
            _fmt_ts(k["last_used_at"]),
            k["rate_limit_per_hour"],
        ))
    print()


def cmd_revoke(args):
    ok = revoke_key(args.key_id)
    if ok:
        print(f"Revoked: {args.key_id}")
    else:
        print(f"Key not found: {args.key_id}", file=sys.stderr)
        sys.exit(1)


def cmd_info(args):
    from webapp.api_auth import _db
    con = _db()
    try:
        row = con.execute(
            "SELECT key_id, label, created_at, last_used_at, revoked, rate_limit_per_hour "
            "FROM api_keys WHERE key_id = ?",
            (args.key_id,),
        ).fetchone()
    finally:
        con.close()
    if not row:
        print(f"Key not found: {args.key_id}", file=sys.stderr)
        sys.exit(1)
    print()
    print(f"  Key ID   : {row['key_id']}")
    print(f"  Label    : {row['label']}")
    print(f"  Status   : {'REVOKED' if row['revoked'] else 'active'}")
    print(f"  Created  : {_fmt_ts(row['created_at'])}")
    print(f"  Last used: {_fmt_ts(row['last_used_at'])}")
    print(f"  Rate     : {row['rate_limit_per_hour']}/hour")
    print()


def cmd_cleanup_jobs(args):
    cutoff = int(time.time()) - (args.days * 86400)
    con = sqlite3.connect(str(DB_PATH))
    try:
        cur = con.execute(
            "DELETE FROM api_jobs WHERE created_at < ? AND status IN ('done','failed')",
            (cutoff,),
        )
        con.commit()
        print(f"Deleted {cur.rowcount} completed/failed jobs older than {args.days} days.")
    finally:
        con.close()


def main():
    ensure_api_tables()

    parser = argparse.ArgumentParser(
        description="malhaus API key manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_create = sub.add_parser("create", help="Create a new API key")
    p_create.add_argument("--label",      required=True, help="Human label (name/org)")
    p_create.add_argument("--rate-limit", type=int, default=60, dest="rate_limit",
                          help="Max requests per hour (default: 60)")

    sub.add_parser("list", help="List all API keys")

    p_revoke = sub.add_parser("revoke", help="Revoke an API key")
    p_revoke.add_argument("key_id", help="Key ID to revoke")

    p_info = sub.add_parser("info", help="Show details for a key")
    p_info.add_argument("key_id", help="Key ID")

    p_clean = sub.add_parser("cleanup-jobs", help="Delete old completed/failed jobs")
    p_clean.add_argument("--days", type=int, default=30,
                         help="Delete jobs older than N days (default: 30)")

    args = parser.parse_args()
    {
        "create":       cmd_create,
        "list":         cmd_list,
        "revoke":       cmd_revoke,
        "info":         cmd_info,
        "cleanup-jobs": cmd_cleanup_jobs,
    }[args.cmd](args)


if __name__ == "__main__":
    main()
