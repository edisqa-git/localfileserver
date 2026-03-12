# localfileserver

A small HTTPS file-sharing server for LAN use.

## Project structure

- `server.py`: main server with SQLite (`users.db`) password-hash auth, CIDR allowlisting, TLS auto-generation, and upload/download UI.
- `frontend/`: browser app served by `server.py` at `/app` (login, list/upload/download/delete).
- `examples/extended_server.py`: simpler alternate server that uses environment-based basic auth.
- `scripts/run.sh`: starts the main server from the repo root.
- `scripts/generate_password_hash.py`: interactive helper that sets a user's password hash directly in `users.db`.
- `users.example.json`: optional legacy template for migration into `users.db`.
- `data/`, `cert.pem`, `key.pem`, and `audit.log`: runtime artifacts kept out of git.

## Requirements

- Python 3.10+
- `pip install -r requirements.txt`

## Quick start (initiate project)

Run from repo root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 scripts/generate_password_hash.py -u admin
./scripts/run.sh
```

Then open:

- Frontend app: `https://127.0.0.1:8443/app`
- Legacy UI: `https://127.0.0.1:8443/`

## Setup

1. Set the admin password directly with `python3 scripts/generate_password_hash.py -u admin`.
2. Start the main server with `./scripts/run.sh`.
3. Open `https://<server-ip>:8443/app` for the frontend app.

`server.py` will create `data/` automatically and generate `cert.pem` / `key.pem` if they do not exist.

## Frontend app notes

- `/app` opens with a landing page for existing users to sign in.
- The app uses:
  - Basic Auth for protected APIs.
  - `GET /api/files` for JSON file listing.
  - `POST /signup` is disabled and returns `403`.
  - `POST /admin/users` lets an authenticated admin create a user.
- Existing server-rendered UI at `/` remains available.

## Admin user provisioning

Bootstrap the first admin locally:

```bash
python3 scripts/generate_password_hash.py -u admin
```

Create additional users over HTTPS as an authenticated admin:

```bash
curl -k -u admin:YOUR_ADMIN_PASSWORD \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"replace-me-123","role":"user"}' \
  https://127.0.0.1:8443/admin/users
```

Notes:

- `POST /admin/users` accepts JSON with `username`, `password`, and optional `role`.
- Allowed roles are `user` and `admin`.
- Non-admin callers receive `403`.

## Optional environment variables

- `FILESERVER_SHARE_DIR`: override the storage directory used by `examples/extended_server.py`.
- `FILESERVER_AUTH_USER`: basic-auth username for `examples/extended_server.py`.
- `FILESERVER_AUTH_PASS`: basic-auth password for `examples/extended_server.py`.

## Notes

- `users.db` is intentionally ignored so local credentials are not committed.
- If a legacy `users.json` exists, `server.py` migrates those users into `users.db` automatically.
- Each authenticated user is isolated to their own directory under `data/`.
- The frontend requires manual login (username + password) and does not persist credentials in browser storage.
- New users must be provisioned by an existing admin, either through `POST /admin/users` or direct local database access.
- The nested temporary `fileserver/` repo has been removed; the parent repo is now the single source of truth.
