# Codex README

This file tracks Codex collaboration notes for `localfileserver`.

## Current working rules

- Keep frontend and backend changes minimal and verifiable.
- Run sanity checks after each implementation update.
- Commit and push every modification as a versioned change to GitHub.

## Standard sanity checks

```bash
python3 -m py_compile server.py scripts/generate_password_hash.py
node --check frontend/app.js
```
