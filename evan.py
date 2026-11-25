#!/usr/bin/env python3
"""Evan CLI tool."""

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


def non_negative_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid number: {value!r}") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be a non-negative number")
    return parsed


def encrypt_file(
    target_path: Path, output_path: Path, key_path: Path | None = None
) -> bytes:
    """Encrypt target_path with AES-256-GCM, write ciphertext to output_path, and save hex key to key_path."""
    plaintext = target_path.read_bytes()
    key = get_random_bytes(KEY_SIZE)
    nonce = get_random_bytes(NONCE_SIZE)

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    if key_path is None:
        key_path = Path(f"{output_path}.key")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(nonce + tag + ciphertext)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_text(f"{key.hex()}\n", encoding="utf-8")
    return key


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
        key_output = Path(f"{output}.key")
        encrypt_file(target, output, key_output)
        print(f"Encrypted {target} -> {output}")
        print(f"Key saved -> {key_output}")
        return 0

    print("Parsed arguments:")
    print(f"  encrypt : {args.encrypt}")
    print(f"  output  : {args.output}")
    print(f"  add_size: {args.add_size}")
    print(f"  delay   : {args.delay}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
