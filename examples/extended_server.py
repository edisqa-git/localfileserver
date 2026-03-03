#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import io
import time
import hmac
import base64
import hashlib
import logging
from datetime import datetime
from pathlib import Path

from flask import (
    Flask, request, send_from_directory, render_template_string,
    jsonify, abort, Response
)
from werkzeug.utils import secure_filename

# =========================
# Config
# =========================
BASE_DIR = Path(__file__).resolve().parent.parent
SHARE_DIR = Path(os.environ.get("FILESERVER_SHARE_DIR", str(BASE_DIR / "data"))).expanduser().resolve()
HOST = "0.0.0.0"
PORT = 8443

# TLS cert/key (self-signed is fine for LAN; still "Not Secure" until trusted)
CERT_FILE = str((BASE_DIR / "cert.pem").resolve())
KEY_FILE = str((BASE_DIR / "key.pem").resolve())

# Basic Auth
AUTH_USER = os.environ.get("FILESERVER_AUTH_USER", "admin")
AUTH_PASS = os.environ.get("FILESERVER_AUTH_PASS", "change-me")

# Allowlist client IPs (empty list = allow all)
# Example: allow only your LAN devices
ALLOWED_IPS = {
    # "192.168.17.103",
    # "192.168.20.174",
}

# If you want simple subnet allow, add prefixes (string) here
ALLOWED_PREFIXES = {
    "192.168.",  # allow all 192.168.x.x
    # "10.0.",
}

# File constraints
ALLOWED_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".txt", ".log", ".pcap", ".pcapng", ".csv", ".json"}
MAX_CONTENT_LENGTH = 200 * 1024 * 1024  # 200MB

# Audit Log
AUDIT_LOG = str((BASE_DIR / "audit.log").resolve())

# =========================
# App init
# =========================
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

# Ensure share directory exists
SHARE_DIR.mkdir(parents=True, exist_ok=True)

# Logging
logging.basicConfig(
    filename=AUDIT_LOG,
    level=logging.INFO,
    format="%(asctime)s %(message)s"
)

# =========================
# Helpers
# =========================
def client_ip() -> str:
    """
    If you have a reverse proxy, you may want to honor X-Forwarded-For.
    For direct LAN use, remote_addr is fine.
    """
    return request.remote_addr or "-"

def ip_allowed(ip: str) -> bool:
    if not ip or ip == "-":
        return False
    if ALLOWED_IPS and ip in ALLOWED_IPS:
        return True
    if ALLOWED_IPS and ip not in ALLOWED_IPS:
        # if explicit allowlist set, block others unless prefix allow is used
        pass
    if ALLOWED_PREFIXES:
        for p in ALLOWED_PREFIXES:
            if ip.startswith(p):
                return True
        # If ALLOWED_IPS is empty and prefixes exist, deny non-matching
        if not ALLOWED_IPS:
            return False
    # If both allowlists are empty → allow all
    return (not ALLOWED_IPS) and (not ALLOWED_PREFIXES)

def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))

def check_basic_auth() -> bool:
    auth = request.authorization
    if not auth:
        return False
    return constant_time_equals(auth.username or "", AUTH_USER) and constant_time_equals(auth.password or "", AUTH_PASS)

def require_auth():
    """
    Enforce Basic Auth and IP allowlist.
    """
    ip = client_ip()
    if not ip_allowed(ip):
        abort(403, description="Forbidden (IP not allowed)")

    if not check_basic_auth():
        return Response(
            "Authentication required",
            401,
            {"WWW-Authenticate": 'Basic realm="FileServer"'}
        )
    return None

def safe_join_share(filename: str) -> Path:
    """
    Prevent path traversal by resolving and enforcing SHARE_DIR prefix.
    """
    # secure_filename removes many dangerous patterns, but we still enforce resolve.
    cleaned = secure_filename(filename)
    target = (SHARE_DIR / cleaned).resolve()
    if SHARE_DIR not in target.parents and target != SHARE_DIR:
        abort(400, description="Invalid path")
    return target

def ext_allowed(filename: str) -> bool:
    ext = Path(filename).suffix.lower()
    return ext in ALLOWED_EXTS

def atomic_write(path: Path, data: bytes):
    """
    Write file atomically to avoid partial writes.
    """
    tmp = path.with_suffix(path.suffix + f".tmp.{os.getpid()}.{int(time.time())}")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)

# =========================
# Security headers
# =========================
@app.after_request
def add_security_headers(resp):
    # minimal but useful headers for an internal tool
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    # If you later put this behind a domain with a trusted cert, you can enable HSTS.
    return resp

# =========================
# Audit logging
# =========================
@app.after_request
def audit_log(resp):
    ip = client_ip()
    method = request.method
    path = request.path
    ua = request.headers.get("User-Agent", "-")
    status = resp.status_code
    length = resp.calculate_content_length()
    length_str = str(length) if length is not None else "-"
    logging.info(f'{ip} {method} {path} {status} bytes={length_str} UA="{ua}"')
    return resp

# =========================
# Routes
# =========================
HTML = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8"/>
<title>LAN File Server</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif; margin: 20px; }
.container { display: flex; flex-wrap: wrap; gap: 14px; }
.card { width: 220px; border: 1px solid #ddd; border-radius: 10px; padding: 10px; }
.thumb { width: 200px; height: 200px; object-fit: cover; border: 1px solid #ccc; border-radius: 8px; }
.small { color: #666; font-size: 12px; word-break: break-all; }
.actions a { margin-right: 8px; font-size: 12px; }
hr { border: 0; border-top: 1px solid #eee; margin: 18px 0; }
</style>
</head>
<body>
<h2>LAN File Server (HTTPS)</h2>

<div class="small">
Share: {{ share_dir }}<br/>
Allowed extensions: {{ exts }}<br/>
Max upload size: {{ max_mb }} MB
</div>

<hr/>

<h3>Upload</h3>
<form action="/upload" method="post" enctype="multipart/form-data">
  <input type="file" name="file" required />
  <button type="submit">Upload</button>
</form>

<hr/>

<h3>Files</h3>
<div class="container">
{% for f in files %}
  <div class="card">
    {% if f.is_image %}
      <a href="/file/{{ f.name }}" target="_blank">
        <img class="thumb" src="/file/{{ f.name }}" alt="{{ f.name }}">
      </a>
    {% else %}
      <div class="thumb" style="display:flex;align-items:center;justify-content:center;">
        <div class="small">No preview</div>
      </div>
    {% endif %}
    <div class="small">{{ f.name }}</div>
    <div class="small">size: {{ f.size }} bytes</div>
    <div class="actions">
      <a href="/download/{{ f.name }}">download</a>
      <a href="/delete_ui/{{ f.name }}" onclick="return confirm('Delete {{ f.name }}?')">delete</a>
    </div>
  </div>
{% endfor %}
</div>

</body>
</html>
"""

def list_files():
    items = []
    for p in sorted(SHARE_DIR.iterdir()):
        if p.is_file():
            ext = p.suffix.lower()
            items.append({
                "name": p.name,
                "size": p.stat().st_size,
                "is_image": ext in {".png", ".jpg", ".jpeg", ".gif"},
            })
    return items

@app.route("/", methods=["GET"])
def index():
    auth_resp = require_auth()
    if auth_resp:
        return auth_resp
    return render_template_string(
        HTML,
        files=list_files(),
        share_dir=str(SHARE_DIR),
        exts=", ".join(sorted(ALLOWED_EXTS)),
        max_mb=int(MAX_CONTENT_LENGTH / (1024 * 1024))
    )

@app.route("/file/<path:filename>", methods=["GET"])
def get_file(filename):
    auth_resp = require_auth()
    if auth_resp:
        return auth_resp
    # send_from_directory already mitigates some traversal, but we still validate extension
    if not ext_allowed(filename):
        abort(415, description="File type not allowed")
    return send_from_directory(str(SHARE_DIR), filename, conditional=True)

@app.route("/download/<path:filename>", methods=["GET"])
def download(filename):
    auth_resp = require_auth()
    if auth_resp:
        return auth_resp
    if not ext_allowed(filename):
        abort(415, description="File type not allowed")
    return send_from_directory(str(SHARE_DIR), filename, as_attachment=True)

@app.route("/upload", methods=["POST"])
def upload():
    auth_resp = require_auth()
    if auth_resp:
        return auth_resp

    if "file" not in request.files:
        abort(400, description="No file part")

    f = request.files["file"]
    if not f.filename:
        abort(400, description="Empty filename")

    if not ext_allowed(f.filename):
        abort(415, description="File type not allowed")

    filename = secure_filename(f.filename)
    target = safe_join_share(filename)

    # Save directly (Werkzeug streams); for very large files you can keep this.
    f.save(str(target))
    return jsonify({"status": "uploaded", "file": filename}), 200

@app.route("/file/<path:filename>", methods=["PUT"])
def put_file(filename):
    auth_resp = require_auth()
    if auth_resp:
        return auth_resp

    if not ext_allowed(filename):
        abort(415, description="File type not allowed")

    target = safe_join_share(filename)
    data = request.get_data()
    atomic_write(target, data)
    return jsonify({"status": "updated", "file": target.name}), 200

@app.route("/file/<path:filename>", methods=["DELETE"])
def delete_file(filename):
    auth_resp = require_auth()
    if auth_resp:
        return auth_resp

    target = safe_join_share(filename)
    if not target.exists():
        abort(404, description="Not found")

    target.unlink()
    return jsonify({"status": "deleted", "file": target.name}), 200

# Convenience UI delete action via GET (so you can click in browser)
@app.route("/delete_ui/<path:filename>", methods=["GET"])
def delete_ui(filename):
    auth_resp = require_auth()
    if auth_resp:
        return auth_resp
    target = safe_join_share(filename)
    if target.exists():
        target.unlink()
    # redirect back to index
    return ("", 302, {"Location": "/"})

# Health check (useful for monitoring)
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "time": datetime.utcnow().isoformat() + "Z"}), 200

# =========================
# Main
# =========================
if __name__ == "__main__":
    # Quick sanity check for TLS files
    if not Path(CERT_FILE).exists() or not Path(KEY_FILE).exists():
        print(f"[ERR] Missing TLS files: {CERT_FILE} / {KEY_FILE}")
        print("Generate with:")
        print("  openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes")
        raise SystemExit(1)

    print(f"[INFO] Serving {SHARE_DIR} on https://0.0.0.0:{PORT}")
    app.run(host=HOST, port=PORT, ssl_context=(CERT_FILE, KEY_FILE))
