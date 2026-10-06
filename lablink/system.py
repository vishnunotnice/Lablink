"""Explicit subprocess execution; never invokes a shell."""
import os
import re
import subprocess
from pathlib import Path


def identifier(value):
    if not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_-]{0,31}", value):
        raise ValueError("Names must start with a letter and use 1–32 letters, digits, _ or -")
    return value


def run(argv, input=None, timeout=60):
    result = subprocess.run([str(x) for x in argv], input=input, text=True,
                            capture_output=True, timeout=timeout, check=False)
    if result.returncode:
        # Do not echo stdin: it may contain private key material.
        raise RuntimeError(f"{argv[0]} failed (exit {result.returncode}): {result.stderr.strip()}")
    return result.stdout.strip()


def private_write(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp = path.with_name(path.name + ".tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        os.chmod(path, 0o600)
    finally:
        if temp.exists():
            temp.unlink()


def keypair():
    private = run(["wg", "genkey"])
    return private, run(["wg", "pubkey"], input=private + "\n")
