"""
Admin blueprint — API key management UI.
URL prefix: /admin
"""
import time
from datetime import datetime
from functools import wraps

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from webapp.api_auth import (
    admin_exists,
    change_admin_password,
    create_admin,
    create_key,
    list_keys,
    revoke_key,
    verify_admin,
)

admin_bp = Blueprint("admin_bp", __name__, url_prefix="/admin")


def _format_ts(ts: int | None) -> str:
    if ts is None:
        return "—"
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")


def _require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("admin_bp.login"))
        return f(*args, **kwargs)
    return decorated


@admin_bp.route("/login", methods=["GET", "POST"])
def login():
    setup = not admin_exists()

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if setup:
            # First-time setup
            confirm = request.form.get("confirm_password", "")
            if not username or not password:
                flash("Username and password are required.", "error")
                return render_template("admin_login.html", setup=True)
            if password != confirm:
                flash("Passwords do not match.", "error")
                return render_template("admin_login.html", setup=True)
            create_admin(username, password)
            flash("Admin account created. Please log in.", "success")
            return redirect(url_for("admin_bp.login"))
        else:
            if verify_admin(username, password):
                session["admin_logged_in"] = True
                session["admin_username"] = username
                session.permanent = True
                return redirect(url_for("admin_bp.keys"))
            flash("Invalid username or password.", "error")
            return render_template("admin_login.html", setup=False)

    return render_template("admin_login.html", setup=setup)


@admin_bp.route("/logout")
def logout():
    session.pop("admin_logged_in", None)
    session.pop("admin_username", None)
    return redirect(url_for("admin_bp.login"))


@admin_bp.route("/keys")
@_require_admin
def keys():
    all_keys = list_keys()
    now = int(time.time())
    for k in all_keys:
        k["created_fmt"] = _format_ts(k["created_at"])
        k["last_used_fmt"] = _format_ts(k["last_used_at"])
        k["expires_fmt"] = _format_ts(k["expires_at"]) if k.get("expires_at") else "never"
        if k["revoked"]:
            k["status"] = "revoked"
        elif k.get("expires_at") and k["expires_at"] < now:
            k["status"] = "expired"
        else:
            k["status"] = "active"
    return render_template(
        "admin_keys.html",
        keys=all_keys,
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
        rate_limit = int(request.form.get("rate_limit", 60))
    except (TypeError, ValueError):
        rate_limit = 60

    expires_days_raw = request.form.get("expires_days", "").strip()
    expires_at = None
    if expires_days_raw:
        try:
            days = int(expires_days_raw)
            if days > 0:
                expires_at = int(time.time()) + days * 86400
        except (TypeError, ValueError):
            pass

    token, key_id = create_key(label, rate_limit_per_hour=rate_limit, expires_at=expires_at)
    flash(token, "key")
    return redirect(url_for("admin_bp.keys"))


@admin_bp.route("/keys/<key_id>/revoke", methods=["POST"])
@_require_admin
def keys_revoke(key_id: str):
    revoke_key(key_id)
    flash("Key revoked.", "success")
    return redirect(url_for("admin_bp.keys"))


@admin_bp.route("/password", methods=["GET", "POST"])
@_require_admin
def password():
    if request.method == "POST":
        current = request.form.get("current_password", "")
        new_pw = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        username = session.get("admin_username", "")

        if not verify_admin(username, current):
            flash("Current password is incorrect.", "error")
            return render_template("admin_password.html", username=username)
        if not new_pw:
            flash("New password cannot be empty.", "error")
            return render_template("admin_password.html", username=username)
        if new_pw != confirm:
            flash("New passwords do not match.", "error")
            return render_template("admin_password.html", username=username)

        change_admin_password(username, new_pw)
        flash("Password updated successfully.", "success")
        return redirect(url_for("admin_bp.keys"))

    return render_template("admin_password.html", username=session.get("admin_username", ""))
