# localfileserver

A file-sharing server for LAN use.

## Setup

- `users.json` is intentionally ignored. Copy `users.example.json` to `users.json` and add your own password hashes.
- `cert.pem`, `key.pem`, `audit.log`, and `data/` are runtime files and are not tracked.
- `extended_server.py` reads basic auth credentials from `FILESERVER_AUTH_USER` and `FILESERVER_AUTH_PASS`.
