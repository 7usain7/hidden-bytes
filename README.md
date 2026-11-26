# hidden-bytes

A collection of Go-based cybersecurity tools for studying binary entropy, AES-256-GCM payload encryption/evasion, and polymorphic binary generation.

> **Disclaimer:** This repository is intended strictly for educational and authorized security research purposes.

## Prerequisites

- [Go](https://go.dev/dl/) (1.20+ recommended)

## Project Structure

```text
hidden-bytes/
├── entropy/                 # Shannon entropy calculator
│   └── main.go
├── evasion/                 # Payload encryptor & self-contained binary builder
│   ├── cmd/
│   │   └── evasion/         # CLI entrypoint
│   └── internal/
│       ├── builder/         # Self-contained binary compiler
│       ├── crypto/          # AES-256-GCM encryption & key management
│       └── runner/          # Runtime decryption & execution
└── polymorph/               # Polymorphic binary generator
    ├── main.go
    └── builder/
        ├── builder.go       # Code generation & compilation
        └── runner.go.tmpl   # Go template for generated binaries
```

---

## 1. Entropy (`entropy`)

Computes the Shannon entropy of a file in bits per byte (`0.0` to `8.0`) by streaming the file in 32 KB chunks and building a 256-entry byte frequency table.

- **High entropy (~7.0–8.0):** Typical of encrypted, compressed, or packed payloads.
- **Low entropy (~0.0–2.0):** Typical of plain text, sparse data, or heavily padded binaries.

### Build & Usage

```zsh
cd entropy
go build -o entropy .
./entropy --calculate <file>
```

### Example

```zsh
./entropy --calculate ../mal-track.exe
```

---

## 2. Evasion

Encrypts a target binary using **AES-256-GCM** (32-byte random key, 12-byte random nonce, 16-byte authentication tag) and compiles a self-contained executable that decrypts and runs the payload at runtime.

When encrypting, it also writes `<target>.enc` (`nonce || tag || ciphertext`) and a `.key` file next to the target for standalone `--run` testing.

### Build

```zsh
cd evasion
go build -o evasion ./cmd/evasion
```

### Flags

| Flag                      | Description                                                         |
| :------------------------ | :------------------------------------------------------------------ |
| `--encrypt <target-file>` | Encrypt a file and produce a self-contained binary                  |
| `--output <name>`         | Name of the produced binary (default: `<target>_enc`)               |
| `--run <enc> <key>`       | Decrypt and execute a payload using `.enc` and `.key` files on disk |
| `--add-size <size-in-mb>` | Pad the produced binary by `N` MB (reduces overall file entropy)    |
| `--delay <seconds>`       | Delay payload execution by `N` seconds                              |
| `--help`                  | Show usage information                                              |

### Examples

Encrypt a binary into a self-contained executable:

```zsh
./evasion --encrypt ../mal-track.exe --output mal-track-encrypted.exe
```

Encrypt with 101 MB of padding and a 2-second execution delay:

```zsh
./evasion --encrypt ../mal-track.exe --output mal-track-encrypted.exe --add-size 101 --delay 2
```

Decrypt and run from `.enc` and `.key` files on disk:

```zsh
./evasion --run ../mal-track.exe.enc ../mal-track.exe.key
```

---

## 3. Polymorph

Generates a polymorphic self-contained binary from a text payload using the template in `polymorph/builder/runner.go.tmpl`.

### Build & Usage

```zsh
cd polymorph
go build -o poly .
./poly --generate <output-binary> --payload "<text>"
```

### Example

```zsh
./poly --generate ./out.exe --payload "hello world"
```
