# localfileserver

A small HTTPS file-sharing server for LAN use.

## Project structure

- `server.py`: main server with `users.json` password-hash auth, CIDR allowlisting, TLS auto-generation, and upload/download UI.
- `examples/extended_server.py`: simpler alternate server that uses environment-based basic auth.
- `users.example.json`: template for the root `users.json` file.
- `data/`, `cert.pem`, `key.pem`, and `audit.log`: runtime artifacts kept out of git.

## Requirements

- Python 3.10+
- `pip install -r requirements.txt`

## Setup

1. Copy `users.example.json` to `users.json`.
2. Replace the example password hash with your own generated hash.
3. Start the main server with `python3 server.py`.

`server.py` will create `data/` automatically and generate `cert.pem` / `key.pem` if they do not exist.

## Optional environment variables

- `FILESERVER_SHARE_DIR`: override the storage directory used by `examples/extended_server.py`.
- `FILESERVER_AUTH_USER`: basic-auth username for `examples/extended_server.py`.
- `FILESERVER_AUTH_PASS`: basic-auth password for `examples/extended_server.py`.

## Notes

- `users.json` is intentionally ignored so local credentials are not committed.
- The nested temporary `fileserver/` repo has been removed; the parent repo is now the single source of truth.
