"""Secure File Upload System - Flask. Run: flask --app app run"""
import hashlib, logging, os, secrets, shutil, sqlite3, subprocess, sys, uuid
from functools import wraps
from pathlib import Path

from flask import (Flask, abort, flash, g, redirect, render_template,
                   request, send_from_directory, session, url_for)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE = Path(sys.executable).parent if getattr(sys, "frozen", False) else Path(__file__).parent
RESOURCE_BASE = Path(getattr(sys, "_MEIPASS", BASE))
# Allowlist: extension -> (magic bytes, MIME type)
ALLOWED = {
    "pdf": (b"%PDF-", "application/pdf"),
    "png": (b"\x89PNG\r\n\x1a\n", "image/png"),
    "jpg": (b"\xff\xd8\xff", "image/jpeg"),
}
SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, pw_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS files(
  id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL, stored_name TEXT NOT NULL,
  original_name TEXT NOT NULL, size INTEGER NOT NULL, sha256 TEXT NOT NULL,
  uploaded_at TEXT DEFAULT CURRENT_TIMESTAMP);
"""

csrf = CSRFProtect()
limiter = Limiter(get_remote_address, default_limits=["200 per hour"],
                  storage_uri="memory://")


def create_app(test_config=None):
    app = Flask(
        __name__,
        template_folder=str(RESOURCE_BASE / "templates"),
        static_folder=str(RESOURCE_BASE / "static"),
    )
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
        MAX_CONTENT_LENGTH=5 * 1024 * 1024,           # 5 MB hard cap
        UPLOAD_DIR=os.environ.get("UPLOAD_DIR", str(BASE / "uploads")),
        DATABASE=os.environ.get("DATABASE", str(BASE / "app.db")),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("HTTPS") == "1",
        PERMANENT_SESSION_LIFETIME=1800,
    )
    if test_config:
        app.config.update(test_config)
    Path(app.config["UPLOAD_DIR"]).mkdir(parents=True, exist_ok=True)
    csrf.init_app(app)
    limiter.init_app(app)
    logging.basicConfig(filename=str(BASE / "audit.log"), level=logging.INFO,
                        format="%(asctime)s %(message)s")

    # ---------- helpers ----------
    def db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE"])
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(_):
        d = g.pop("db", None)
        if d:
            d.close()

    with app.app_context():
        db().executescript(SCHEMA)

    def audit(event):
        logging.info("%s ip=%s user=%s", event, request.remote_addr, session.get("uid"))

    def login_required(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            if "uid" not in session:
                return redirect(url_for("login"))
            return fn(*a, **kw)
        return wrapper

    def virus_scan(path):
        """Optional ClamAV hook. Returns True if clean or scanner absent."""
        if not shutil.which("clamscan"):
            return True
        return subprocess.run(["clamscan", "--no-summary", str(path)],
                              capture_output=True).returncode == 0

    @app.after_request
    def headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    # ---------- auth ----------
    @app.route("/register", methods=["GET", "POST"])
    @limiter.limit("10 per hour")
    def register():
        if request.method == "POST":
            u = request.form.get("username", "").strip()
            p = request.form.get("password", "")
            if not (3 <= len(u) <= 32 and u.isalnum()):
                flash("Username: 3-32 letters/digits.")
            elif len(p) < 10:
                flash("Password must be at least 10 characters.")
            else:
                try:
                    db().execute("INSERT INTO users(username,pw_hash) VALUES(?,?)",
                                 (u, generate_password_hash(p)))
                    db().commit()
                    audit(f"register {u}")
                    return redirect(url_for("login"))
                except sqlite3.IntegrityError:
                    flash("Username taken.")
        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("5 per minute", methods=["POST"])
    def login():
        if request.method == "POST":
            row = db().execute("SELECT * FROM users WHERE username=?",
                               (request.form.get("username", ""),)).fetchone()
            if row and check_password_hash(row["pw_hash"], request.form.get("password", "")):
                session.clear()                       # prevent session fixation
                session["uid"] = row["id"]
                session.permanent = True
                audit("login ok")
                return redirect(url_for("index"))
            audit("login FAIL")
            flash("Invalid credentials.")             # generic message
        return render_template("login.html")

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    # ---------- files ----------
    @app.get("/")
    @login_required
    def index():
        rows = db().execute("SELECT * FROM files WHERE owner_id=? ORDER BY id DESC",
                            (session["uid"],)).fetchall()
        return render_template("index.html", files=rows,
                               allowed=", ".join(sorted(ALLOWED)))

    @app.post("/upload")
    @login_required
    @limiter.limit("20 per hour")
    def upload():
        f = request.files.get("file")
        if not f or not f.filename:
            flash("No file selected.")
            return redirect(url_for("index"))
        clean = secure_filename(f.filename)           # strips ../ and odd chars
        ext = Path(clean).suffix.lower().lstrip(".")
        if ext not in ALLOWED:
            audit(f"upload REJECT ext={ext!r}")
            flash("File type not allowed.")
            return redirect(url_for("index"))
        magic = ALLOWED[ext][0]
        if f.stream.read(len(magic)) != magic:        # content must match extension
            audit(f"upload REJECT magic ext={ext}")
            flash("File content does not match its type.")
            return redirect(url_for("index"))
        f.stream.seek(0)
        stored = f"{uuid.uuid4().hex}.{ext}"          # random name, never user's
        path = Path(app.config["UPLOAD_DIR"]) / stored
        f.save(path)
        if not virus_scan(path):
            path.unlink(missing_ok=True)
            audit("upload REJECT virus")
            flash("File failed malware scan.")
            return redirect(url_for("index"))
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        db().execute("INSERT INTO files(owner_id,stored_name,original_name,size,sha256)"
                     " VALUES(?,?,?,?,?)",
                     (session["uid"], stored, clean, path.stat().st_size, digest))
        db().commit()
        audit(f"upload ok {stored}")
        flash("Uploaded.")
        return redirect(url_for("index"))

    def owned(fid):
        row = db().execute("SELECT * FROM files WHERE id=? AND owner_id=?",
                           (fid, session["uid"])).fetchone()
        return row or abort(404)                      # 404, not 403: no enumeration

    @app.get("/download/<int:fid>")
    @login_required
    def download(fid):
        row = owned(fid)
        ext = row["stored_name"].rsplit(".", 1)[1]
        audit(f"download {row['stored_name']}")
        return send_from_directory(app.config["UPLOAD_DIR"], row["stored_name"],
                                   as_attachment=True, download_name=row["original_name"],
                                   mimetype=ALLOWED[ext][1])

    @app.post("/delete/<int:fid>")
    @login_required
    def delete(fid):
        row = owned(fid)
        (Path(app.config["UPLOAD_DIR"]) / row["stored_name"]).unlink(missing_ok=True)
        db().execute("DELETE FROM files WHERE id=?", (fid,))
        db().commit()
        audit(f"delete {row['stored_name']}")
        return redirect(url_for("index"))

    @app.errorhandler(413)
    def too_big(_):
        flash("File too large (max 5 MB).")
        return redirect(url_for("index"))

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
