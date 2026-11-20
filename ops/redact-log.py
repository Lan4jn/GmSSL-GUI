#!/usr/bin/env python3
"""Bound and redact known deployment secrets before writing private dev logs."""
import os
from pathlib import Path
import sys

SECRET_NAMES = (
    "GMSSL_ENGINE_TOKEN", "GMSSL_VAULT_MASTER_KEY", "GMSSL_BOOTSTRAP_PASSWORD",
    "SPRING_DATASOURCE_PASSWORD",
)


def main():
    path = Path(sys.argv[1])
    secrets = sorted(
        {os.environ[name].encode() for name in SECRET_NAMES if os.environ.get(name)},
        key=len, reverse=True,
    )
    overlap = max([len(value) for value in secrets] + [1]) - 1
    flags = os.O_CREAT | os.O_WRONLY | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    limit = 10 * 1024 * 1024
    written = 0
    truncated = False

    def write(data):
        nonlocal written, truncated
        for secret in secrets:
            data = data.replace(secret, b"[REDACTED]")
        room = max(0, limit - written)
        selected = data[:room]
        if selected:
            os.write(fd, selected)
            written += len(selected)
        if len(data) > room and not truncated:
            os.write(fd, b"\n[Log retention limit reached; remaining output drained]\n")
            truncated = True

    pending = b""
    try:
        while True:
            chunk = os.read(sys.stdin.fileno(), 8192)
            if not chunk:
                write(pending)
                break
            pending += chunk
            boundary = max(0, len(pending) - overlap)
            for secret in secrets:
                start = 0
                while True:
                    index = pending.find(secret, start)
                    if index < 0:
                        break
                    if index < boundary < index + len(secret):
                        boundary = index
                    start = index + len(secret)
            write(pending[:boundary])
            pending = pending[boundary:]
    finally:
        os.close(fd)


if __name__ == "__main__":
    main()
