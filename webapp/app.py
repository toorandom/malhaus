import os
import secrets
import sqlite3
import time
from flask import Flask, render_template, request, session, redirect, url_for
from flask_wtf.csrf import CSRFProtect
from PIL import Image, ImageOps
from captcha.image import ImageCaptcha
import random
from webapp.routes import bp, BASE_DIR
import base64
from io import BytesIO
import config

csrf = CSRFProtect()

_CAPTCHA_DB = None

def _captcha_db():
    global _CAPTCHA_DB
    if _CAPTCHA_DB is None:
        _CAPTCHA_DB = str(BASE_DIR / "maltriage.db")
    con = sqlite3.connect(_CAPTCHA_DB)
    con.execute("""
        CREATE TABLE IF NOT EXISTS captcha_challenges (
            token TEXT PRIMARY KEY,
            captcha_text TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
    """)
    con.commit()
    return con

def _captcha_store(token: str, text: str):
    con = _captcha_db()
    try:
        con.execute("INSERT OR REPLACE INTO captcha_challenges(token, captcha_text, created_at) VALUES(?,?,?)",
                    (token, text, int(time.time())))
        # Purge challenges older than 30 minutes
        con.execute("DELETE FROM captcha_challenges WHERE created_at < ?", (int(time.time()) - 1800,))
        con.commit()
    finally:
        con.close()

def _captcha_verify_and_delete(token: str, user_answer: str) -> bool:
    con = _captcha_db()
    try:
        row = con.execute(
            "SELECT captcha_text FROM captcha_challenges WHERE token=? AND created_at >= ?",
            (token, int(time.time()) - 1800),
        ).fetchone()
        if row and user_answer.upper() == row[0].upper():
            con.execute("DELETE FROM captcha_challenges WHERE token=?", (token,))
            con.commit()
            return True
        return False
    finally:
        con.close()

def create_app():
    app = Flask(__name__)

    secret_key = os.environ.get("MALHAUS_SECRET_KEY", "")
    if not secret_key:
        import sys
        print("WARNING: MALHAUS_SECRET_KEY not set. Using a random key (sessions will not survive restarts). Set it in config.source.", file=sys.stderr)
        secret_key = secrets.token_hex(32)
    app.secret_key = secret_key

    csrf.init_app(app)

    # max upload size enforced by Flask
    app.config["MAX_CONTENT_LENGTH"] = config.MAX_UPLOAD_BYTES

    # Session cookie security
    # NOTE: set MALHAUS_HTTPS=1 in config.source once you have TLS in front
    app.config["SESSION_COOKIE_SECURE"] = os.environ.get("MALHAUS_HTTPS", "0") == "1"
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    # Session expires after 20 minutes of inactivity
    app.config["PERMANENT_SESSION_LIFETIME"] = 1200

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:"
        )
        return resp

    def generate_captcha_text(length=6):
        chars = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ'
        return ''.join(random.choices(chars, k=length))

    @app.route("/captcha", methods=["GET", "POST"])
    def captcha():
        error = None
        if request.method == "POST":
            token = session.get("captcha_token", "")
            user_input = request.form.get("captcha_input", "")
            if token and _captcha_verify_and_delete(token, user_input):
                session["captcha_solved"] = True
                session.permanent = True
                session.pop("captcha_token", None)
                return redirect(url_for("bp.index"))
            else:
                error = "Incorrect captcha. Try again."
                # Issue a fresh challenge after a failed attempt
                session.pop("captcha_token", None)
        else:
            if request.args.get("new"):
                session.pop("captcha_token", None)

        # Generate a new challenge if none exists in session
        if "captcha_token" not in session:
            captcha_text = generate_captcha_text()
            token = secrets.token_hex(16)
            _captcha_store(token, captcha_text)
            session["captcha_token"] = token
        else:
            token = session["captcha_token"]
            con = _captcha_db()
            try:
                row = con.execute("SELECT captcha_text FROM captcha_challenges WHERE token=?", (token,)).fetchone()
            finally:
                con.close()
            if row:
                captcha_text = row[0]
            else:
                # Token expired or missing — generate a new one
                captcha_text = generate_captcha_text()
                token = secrets.token_hex(16)
                _captcha_store(token, captcha_text)
                session["captcha_token"] = token

        image = ImageCaptcha(width=280, height=90)
        data = image.generate(captcha_text)
        img = Image.open(data)
        img = ImageOps.invert(img.convert('RGB'))
        buf = BytesIO()
        img.save(buf, format='PNG')
        image_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')
        return render_template("captcha.html", error=error, captcha_image=image_base64)


    @app.before_request
    def require_captcha():
        if not config.CAPTCHA_ENABLED:
            return None
        # Allow static files, captcha route, and API endpoints
        if (request.path.startswith("/static")
                or request.path.startswith("/captcha")
                or request.path.startswith("/api/")):
            return None
        if not session.get("captcha_solved"):
            return redirect(url_for("captcha"))



    @app.errorhandler(413)
    def too_large(e):
        # Friendly error page (redirect home with message)
        return render_template("error.html",
                               title="File too large",
                               message=f"Max file size is {config.MAX_UPLOAD_MB} MB."), 413

    app.register_blueprint(bp)

    from webapp.api_routes import api_bp
    csrf.exempt(api_bp)
    app.register_blueprint(api_bp)

    return app

app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=False)


