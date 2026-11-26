#!/usr/bin/env python3
"""Decrypt a file encrypted with AES-256-GCM (nonce + tag + ciphertext)."""

import argparse
from pathlib import Path
import sys

from Crypto.Cipher import AES

KEY_SIZE = 32    # AES-256 (32 bytes = 64 hex chars)
NONCE_SIZE = 12  # Standard GCM nonce size
TAG_SIZE = 16    # Standard GCM authentication tag size


def parse_hex_key(hex_key: str) -> bytes:
    try:
        key = bytes.fromhex(hex_key.strip())
    except ValueError as exc:
        raise argparse.ArgumentTypeError("key must be a valid hex string") from exc
    if len(key) != KEY_SIZE:
        raise argparse.ArgumentTypeError(
            f"key must be {KEY_SIZE} bytes ({KEY_SIZE * 2} hex characters), got {len(key)} bytes"
        )
    return key


def decrypt_file(input_path: Path, output_path: Path, key: bytes) -> None:
    """Decrypt input_path (nonce + tag + ciphertext) using AES-256-GCM."""
    data = input_path.read_bytes()
    header_size = NONCE_SIZE + TAG_SIZE
    if len(data) < header_size:
        raise ValueError("input file is too short to contain a valid AES-GCM header")

    nonce = data[:NONCE_SIZE]
    tag = data[NONCE_SIZE:header_size]
    ciphertext = data[header_size:]

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(plaintext)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="decrypt",
        description="Decrypt a file encrypted with AES-256-GCM.",
    )
    parser.add_argument(
        "--input",
        "-i",
        required=True,
        metavar="<encrypted-file>",
        help="Path to the encrypted file.",
    )
    parser.add_argument(
        "--key",
        "-k",
        required=True,
        type=parse_hex_key,
        metavar="<hex-key>",
        help="64-character hex-encoded AES-256 key.",
    )
    parser.add_argument(
        "--output",
        "-o",
        metavar="<output-file>",
        help="Path to write the decrypted file (defaults to stripping .enc or adding .dec).",
    )
    return parser


def default_output_path(input_path: Path) -> Path:
    if input_path.suffix == ".enc":
        return input_path.with_suffix("")
    return Path(f"{input_path}.dec")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    input_path = Path(args.input)
    if not input_path.is_file():
        print(f"Error: input file not found: {input_path}", file=sys.stderr)
        return 1

    output_path = Path(args.output) if args.output else default_output_path(input_path)

    try:
        decrypt_file(input_path, output_path, args.key)
    except ValueError as exc:
        print(f"Error: decryption failed ({exc})", file=sys.stderr)
        return 1

    print(f"Decrypted {input_path} -> {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
