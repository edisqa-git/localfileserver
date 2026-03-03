#!/usr/bin/env python3

from getpass import getpass

from werkzeug.security import generate_password_hash


def main() -> None:
    password = getpass("Password: ")
    confirm = getpass("Confirm password: ")

    if not password:
        raise SystemExit("Password cannot be empty.")

    if password != confirm:
        raise SystemExit("Passwords do not match.")

    print(generate_password_hash(password))


if __name__ == "__main__":
    main()
