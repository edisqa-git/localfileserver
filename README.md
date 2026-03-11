# localfileserver

A small HTTPS file-sharing server for LAN use.

## Project structure

- `server.py`: main server with `users.json` password-hash auth, CIDR allowlisting, TLS auto-generation, and upload/download UI.
- `frontend/`: browser app served by `server.py` at `/app` (signup, login, list/upload/download/delete).
- `examples/extended_server.py`: simpler alternate server that uses environment-based basic auth.
- `scripts/run.sh`: starts the main server from the repo root.
- `scripts/generate_password_hash.py`: interactive helper for generating a `users.json` password hash.
- `users.example.json`: template for the root `users.json` file.
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
cp users.example.json users.json
python3 scripts/generate_password_hash.py
./scripts/run.sh
```

Then open:

- Frontend app: `https://127.0.0.1:8443/app`
- Legacy UI: `https://127.0.0.1:8443/`

## Setup

1. Copy `users.example.json` to `users.json`.
2. Generate a password hash with `python3 scripts/generate_password_hash.py`.
3. Replace the example password hash in `users.json`.
4. Start the main server with `./scripts/run.sh`.
5. Open `https://<server-ip>:8443/app` for the frontend app.

`server.py` will create `data/` automatically and generate `cert.pem` / `key.pem` if they do not exist.

## Frontend app notes

- The app uses:
  - `POST /signup` to create a user.
  - Basic Auth for protected APIs.
  - `GET /api/files` for JSON file listing.
- Existing server-rendered UI at `/` remains available.

## Optional environment variables

- `FILESERVER_SHARE_DIR`: override the storage directory used by `examples/extended_server.py`.
- `FILESERVER_AUTH_USER`: basic-auth username for `examples/extended_server.py`.
- `FILESERVER_AUTH_PASS`: basic-auth password for `examples/extended_server.py`.

## Notes

- `users.json` is intentionally ignored so local credentials are not committed.
- The nested temporary `fileserver/` repo has been removed; the parent repo is now the single source of truth.
