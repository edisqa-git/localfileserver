#!/usr/bin/env python3

import argparse
import sqlite3
from getpass import getpass
from pathlib import Path

from werkzeug.security import generate_password_hash


BASE_DIR = Path(__file__).resolve().parent.parent
USERS_DB = BASE_DIR / "users.db"


def normalize_username(value: str) -> str:
    username = (value or "").strip()
    if not username:
        raise SystemExit("Username is required.")
    if len(username) < 3 or len(username) > 64:
        raise SystemExit("Username length must be 3-64.")
    if ":" in username:
        raise SystemExit("Username cannot contain ':'.")
    return username


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a password hash and update users.db directly."
    )
    parser.add_argument(
        "-u", "--username",
        help="Username to create/update in users.db.",
    )
    parser.add_argument(
        "--db-file",
        default=str(USERS_DB),
        help=f"Path to sqlite database file (default: {USERS_DB}).",
    )
    parser.add_argument(
        "--role",
        default="admin",
        help="Role for newly created users (default: admin). Existing user role is preserved.",
    )
    parser.add_argument(
        "--print-only",
        action="store_true",
        help="Only print password hash, do not edit users.db.",
    )
    return parser.parse_args()


def upsert_user(db_file: Path, username: str, password_hash: str, role: str) -> None:
    conn = sqlite3.connect(str(db_file))
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            INSERT INTO users (username, password_hash, role, created_at)
            VALUES (?, ?, ?, datetime('now'))
            ON CONFLICT(username) DO UPDATE SET password_hash = excluded.password_hash
            """,
            (username, password_hash, role or "admin"),
        )
        conn.commit()
    finally:
        conn.close()


def main() -> None:
    args = parse_args()
    password = getpass("Password: ")
    confirm = getpass("Confirm password: ")

    if not password:
        raise SystemExit("Password cannot be empty.")
    if len(password) < 8:
        raise SystemExit("Password length must be at least 8.")

    if password != confirm:
        raise SystemExit("Passwords do not match.")

    password_hash = generate_password_hash(password)
    if args.print_only:
        print(password_hash)
        return

    username_input = args.username if args.username else input("Username: ")
    username = normalize_username(username_input)
    db_file = Path(args.db_file).expanduser().resolve()
    upsert_user(db_file, username, password_hash, args.role)
    print(f"Updated password hash for '{username}' in {db_file}")


if __name__ == "__main__":
    main()
