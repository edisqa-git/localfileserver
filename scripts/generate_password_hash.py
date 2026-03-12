#!/usr/bin/env python3

import argparse
import json
import os
import time
from getpass import getpass
from pathlib import Path

from werkzeug.security import generate_password_hash


BASE_DIR = Path(__file__).resolve().parent.parent
USERS_DB = BASE_DIR / "users.json"


def atomic_write(path: Path, payload: bytes) -> None:
    tmp = path.with_suffix(path.suffix + f".tmp.{os.getpid()}.{int(time.time())}")
    with open(tmp, "wb") as f:
        f.write(payload)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def load_users(path: Path) -> dict:
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise SystemExit(f"{path} must contain a JSON object.")
    return data


def save_users(path: Path, users: dict) -> None:
    payload = json.dumps(users, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
    atomic_write(path, payload)


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
        description="Generate a password hash and update users.json directly."
    )
    parser.add_argument(
        "-u", "--username",
        help="Username to create/update in users.json.",
    )
    parser.add_argument(
        "--users-file",
        default=str(USERS_DB),
        help=f"Path to users database JSON (default: {USERS_DB}).",
    )
    parser.add_argument(
        "--print-only",
        action="store_true",
        help="Only print password hash (legacy behavior), do not edit users.json.",
    )
    return parser.parse_args()


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
    users_file = Path(args.users_file).expanduser().resolve()
    users = load_users(users_file)
    user_record = users.get(username)
    if user_record is None:
        user_record = {}
    elif not isinstance(user_record, dict):
        raise SystemExit(f"User record for '{username}' must be an object.")

    user_record["password_hash"] = password_hash
    users[username] = user_record
    save_users(users_file, users)
    print(f"Updated password hash for '{username}' in {users_file}")


if __name__ == "__main__":
    main()
