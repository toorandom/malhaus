"""Git commit of the running code, read straight from .git (no git binary needed).

Works on bare-metal checkouts and in the Docker image (.dockerignore lets only
.git/HEAD, .git/refs and .git/packed-refs into the build context). MALHAUS_VERSION
overrides it, e.g. for builds made from a tarball without .git.
"""
import os
import re
from pathlib import Path

REPO_URL = "https://github.com/toorandom/malhaus"
_GIT = Path(__file__).resolve().parents[1] / ".git"


def git_commit() -> str:
    """Full commit hash of HEAD, or "" when it cannot be determined."""
    try:
        head = (_GIT / "HEAD").read_text().strip()
        if not head.startswith("ref:"):
            return head if re.fullmatch(r"[0-9a-f]{40}", head) else ""  # detached HEAD
        ref = head[4:].strip()
        loose = _GIT / ref
        if loose.is_file():
            return loose.read_text().strip()
        packed = _GIT / "packed-refs"
        if packed.is_file():
            for line in packed.read_text().splitlines():
                parts = line.split()
                if len(parts) == 2 and parts[1] == ref:
                    return parts[0]
    except OSError:
        pass
    return ""


def version_info() -> dict:
    """{"version": short label, "url": link for it} — re-read on each call so a git pull + HUP shows up."""
    override = os.environ.get("MALHAUS_VERSION", "").strip()
    if override:
        return {"version": override, "url": REPO_URL}
    commit = git_commit()
    if commit:
        return {"version": commit[:7], "url": f"{REPO_URL}/commit/{commit}"}
    return {"version": "unknown", "url": REPO_URL}
