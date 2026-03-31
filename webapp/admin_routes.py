"""
Admin blueprint — API key management UI.
URL prefix: /admin

Security notes:
- All state-changing routes are CSRF-protected (Flask-WTF app-wide)
- Login form requires a per-session CAPTCHA (stored in session, expires with it)
- Brute-force protection: IP blocked for 15 min after 5 failed attempts
- Session inactivity timeout: 5 minutes (checked on every protected route)
- Session regenerated (cleared + reissued) on successful login
"""
import io
import secrets
import sqlite3
import time
from datetime import datetime
from functools import wraps

from captcha.image import ImageCaptcha
from PIL import Image, ImageOps
from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
    Response,
)

from webapp.api_auth import (
    DB_PATH,
    admin_exists,
    change_admin_password,
    create_admin,
    create_key,
    list_keys,
    revoke_key,
    verify_admin,
)

admin_bp = Blueprint("admin_bp", __name__, url_prefix="/admin")

# ── Constants ──────────────────────────────────────────────────────────────────
_SESSION_TIMEOUT    = 300    # seconds of inactivity before logout
_MAX_ATTEMPTS       = 5      # failed logins before IP block
_BLOCK_WINDOW       = 900    # seconds to block after too many failures (15 min)
_CAPTCHA_CHARS      = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no ambiguous I/O/0/1
_CAPTCHA_LEN        = 6
_image_gen          = ImageCaptcha(width=220, height=70)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _format_ts(ts: int | None) -> str:
    if ts is None:
        return "—"
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")


def _client_ip() -> str:
    # ProxyFix (configured in app.py) resolves the real client IP into
    # request.remote_addr, so we no longer need to parse X-Forwarded-For
    # manually (which would allow header spoofing to bypass IP blocking).
    return request.remote_addr or "unknown"


def _db():
    con = sqlite3.connect(str(DB_PATH))
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    return con


def _ensure_login_attempts_table():
    con = _db()
    try:
        con.execute("""
            CREATE TABLE IF NOT EXISTS admin_login_attempts (
                ip         TEXT    NOT NULL,
                ts         INTEGER NOT NULL
            )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_ala_ip_ts ON admin_login_attempts(ip, ts)")
        con.commit()
    finally:
        con.close()


def _record_failed_attempt(ip: str):
    _ensure_login_attempts_table()
    con = _db()
    try:
        con.execute("INSERT INTO admin_login_attempts(ip, ts) VALUES(?, ?)", (ip, int(time.time())))
        # prune old rows
        con.execute("DELETE FROM admin_login_attempts WHERE ts < ?", (int(time.time()) - _BLOCK_WINDOW,))
        con.commit()
    finally:
        con.close()


def _is_ip_blocked(ip: str) -> bool:
    _ensure_login_attempts_table()
    con = _db()
    try:
        count = con.execute(
            "SELECT COUNT(*) FROM admin_login_attempts WHERE ip = ? AND ts >= ?",
            (ip, int(time.time()) - _BLOCK_WINDOW),
        ).fetchone()[0]
        return count >= _MAX_ATTEMPTS
    finally:
        con.close()


def _clear_failed_attempts(ip: str):
    _ensure_login_attempts_table()
    con = _db()
    try:
        con.execute("DELETE FROM admin_login_attempts WHERE ip = ?", (ip,))
        con.commit()
    finally:
        con.close()


def _generate_captcha_text() -> str:
    """Return a fresh captcha text (image served via dedicated route, not stored in cookie)."""
    return "".join(secrets.choice(_CAPTCHA_CHARS) for _ in range(_CAPTCHA_LEN))


def _session_captcha_fresh() -> bool:
    """True if a captcha is already stored in this session and not yet consumed."""
    return bool(session.get("admin_captcha_text"))


def _reset_captcha():
    """Generate a new captcha text and store it in the session."""
    session["admin_captcha_text"] = _generate_captcha_text()


def _verify_captcha(answer: str) -> bool:
    """Verify answer against session captcha, then always clear it (single-use)."""
    expected = session.pop("admin_captcha_text", None)
    if not expected or not answer:
        return False
    return answer.strip().upper() == expected.upper()


# ── Auth decorator ─────────────────────────────────────────────────────────────

def _require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("admin_bp.login"))
        last = session.get("admin_last_active", 0)
        if time.time() - last > _SESSION_TIMEOUT:
            session.clear()
            flash("Session expired due to inactivity.", "error")
            return redirect(url_for("admin_bp.login"))
        session["admin_last_active"] = int(time.time())
        return f(*args, **kwargs)
    return decorated


# ── Routes ─────────────────────────────────────────────────────────────────────

@admin_bp.route("/login", methods=["GET", "POST"])
def login():
    # Already logged in → go to dashboard
    if session.get("admin_logged_in"):
        return redirect(url_for("admin_bp.keys"))

    setup = not admin_exists()
    ip    = _client_ip()

    # Ensure a captcha is ready in the session
    if not _session_captcha_fresh():
        _reset_captcha()

    if request.method == "POST":

        # Brute-force gate
        if _is_ip_blocked(ip):
            flash(f"Too many failed attempts. Try again in {_BLOCK_WINDOW // 60} minutes.", "error")
            _reset_captcha()
            return render_template("admin_login.html", setup=setup,
                                   captcha_img=True)

        # Captcha check (always required, even for setup)
        captcha_answer = request.form.get("captcha", "").strip()
        if not _verify_captcha(captcha_answer):
            _record_failed_attempt(ip)
            flash("Incorrect CAPTCHA. Try again.", "error")
            _reset_captcha()
            return render_template("admin_login.html", setup=setup,
                                   captcha_img=True)

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if setup:
            confirm = request.form.get("confirm_password", "")
            if not username or not password:
                flash("Username and password are required.", "error")
                _reset_captcha()
                return render_template("admin_login.html", setup=True,
                                       captcha_img=True)
            if len(password) < 10:
                flash("Password must be at least 10 characters.", "error")
                _reset_captcha()
                return render_template("admin_login.html", setup=True,
                                       captcha_img=True)
            if password != confirm:
                flash("Passwords do not match.", "error")
                _reset_captcha()
                return render_template("admin_login.html", setup=True,
                                       captcha_img=True)
            create_admin(username, password)
            flash("Admin account created. Please log in.", "success")
            _reset_captcha()
            return redirect(url_for("admin_bp.login"))

        # Normal login
        if verify_admin(username, password):
            _clear_failed_attempts(ip)
            # Regenerate session on login to prevent session fixation
            saved_captcha_solved = True
            session.clear()
            session["admin_logged_in"]   = True
            session["admin_username"]    = username
            session["admin_last_active"] = int(time.time())
            return redirect(url_for("admin_bp.keys"))

        # Failed login
        _record_failed_attempt(ip)
        remaining = _MAX_ATTEMPTS - (
            _db().execute(
                "SELECT COUNT(*) FROM admin_login_attempts WHERE ip = ? AND ts >= ?",
                (ip, int(time.time()) - _BLOCK_WINDOW),
            ).fetchone()[0]
        )
        flash(f"Invalid username or password. {max(0, remaining)} attempt(s) remaining.", "error")
        _reset_captcha()
        return render_template("admin_login.html", setup=False,
                               captcha_img=True)

    return render_template("admin_login.html", setup=setup,
                           captcha_img=True)


@admin_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("admin_bp.login"))


@admin_bp.route("/captcha.png")
def captcha_image():
    """Serve the current session captcha as a PNG (avoids storing image in cookie)."""
    text = session.get("admin_captcha_text")
    if not text:
        return redirect(url_for("admin_bp.login"))
    raw = io.BytesIO()
    _image_gen.write(text, raw)
    raw.seek(0)
    img = ImageOps.invert(Image.open(raw).convert("RGB"))
    out = io.BytesIO()
    img.save(out, format="PNG")
    return Response(out.getvalue(), mimetype="image/png",
                    headers={"Cache-Control": "no-store, no-cache"})


def _list_analyses(limit: int = 200) -> list[dict]:
    con = _db()
    try:
        rows = con.execute(
            "SELECT analyzed_at, filename, sha256, kind, risk_level, confidence, score, ip "
            "FROM web_recents ORDER BY analyzed_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        con.close()


def _delete_analysis(sha256: str) -> int:
    """Delete all web_recents rows for a given sha256. Returns number of rows deleted."""
    con = _db()
    try:
        cur = con.execute("DELETE FROM web_recents WHERE sha256 = ?", (sha256,))
        con.commit()
        return cur.rowcount
    finally:
        con.close()


@admin_bp.route("/keys")
@_require_admin
def keys():
    all_keys = list_keys()
    now = int(time.time())
    for k in all_keys:
        k["created_fmt"]   = _format_ts(k["created_at"])
        k["last_used_fmt"] = _format_ts(k.get("last_used_at"))
        k["expires_fmt"]   = _format_ts(k["expires_at"]) if k.get("expires_at") else "never"
        if k["revoked"]:
            k["status"] = "revoked"
        elif k.get("expires_at") and k["expires_at"] < now:
            k["status"] = "expired"
        else:
            k["status"] = "active"
    return render_template(
        "admin_keys.html",
        keys=all_keys,
        analyses=_list_analyses(),
        username=session.get("admin_username", "admin"),
    )


@admin_bp.route("/keys/create", methods=["POST"])
@_require_admin
def keys_create():
    label = request.form.get("label", "").strip()
    if not label:
        flash("Label is required.", "error")
        return redirect(url_for("admin_bp.keys"))

    try:
        rate_limit = max(1, int(request.form.get("rate_limit", 60)))
    except (TypeError, ValueError):
        rate_limit = 60

    expires_at = None
    raw = request.form.get("expires_days", "").strip()
    if raw:
        try:
            days = int(raw)
            if days > 0:
                expires_at = int(time.time()) + days * 86400
        except (TypeError, ValueError):
            pass

    token, _ = create_key(label, rate_limit_per_hour=rate_limit, expires_at=expires_at)
    flash(token, "key")
    return redirect(url_for("admin_bp.keys"))


@admin_bp.route("/keys/<key_id>/revoke", methods=["POST"])
@_require_admin
def keys_revoke(key_id: str):
    revoke_key(key_id)
    flash("Key revoked.", "success")
    return redirect(url_for("admin_bp.keys"))


@admin_bp.route("/analyses/<sha256>/delete", methods=["POST"])
@_require_admin
def analyses_delete(sha256: str):
    if not sha256 or len(sha256) != 64 or not all(c in "0123456789abcdef" for c in sha256):
        flash("Invalid SHA-256.", "error")
        return redirect(url_for("admin_bp.keys"))
    n = _delete_analysis(sha256)
    flash(f"Analysis deleted ({sha256[:16]}…)." if n else "Entry not found.", "success" if n else "error")
    return redirect(url_for("admin_bp.keys"))


@admin_bp.route("/password", methods=["GET", "POST"])
@_require_admin
def password():
    username = session.get("admin_username", "")
    if request.method == "POST":
        current = request.form.get("current_password", "")
        new_pw  = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")

        if not verify_admin(username, current):
            flash("Current password is incorrect.", "error")
        elif len(new_pw) < 10:
            flash("New password must be at least 10 characters.", "error")
        elif new_pw != confirm:
            flash("New passwords do not match.", "error")
        else:
            change_admin_password(username, new_pw)
            flash("Password updated successfully.", "success")
            return redirect(url_for("admin_bp.keys"))

    return render_template("admin_password.html", username=username)
