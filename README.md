# abe

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Reference](https://pkg.go.dev/badge/github.com/garudaproject/abe.svg)](https://pkg.go.dev/github.com/garudaproject/abe)
[![Go version](https://img.shields.io/badge/Go-1.26.4-blue)](https://go.dev)

A command-line tool for extracting and creating [Android Debug Bridge (ADB)](https://developer.android.com/tools/adb) backup files (`.ab`). Supports both unencrypted and AES-256 encrypted backups with zlib compression.

## Features

- **Unpack** Android `.ab` backup files into `.tar` archives
- **Pack** `.tar` archives into Android-compatible `.ab` backup files
- Supports **no encryption** and **AES-256-CBC** encrypted backups
- **Zlib compression** of backup data
- PBKDF2-based key derivation (10,000 rounds, SHA-1)
- Cross-platform builds (Linux, macOS, Windows — amd64 & arm64)

## Installation

### From Source

Requires [Go 1.26.4](https://go.dev/dl/) or later.

```sh
go install github.com/garudaproject/abe/cmd/abe@latest
```

### Pre-built Binaries

Download the latest release for your platform from the [releases page](https://github.com/garudaproject/abe/releases).

## Usage

```
Usage: abe <command> <file> [password]

Commands:
  unpack    Extract an Android backup (.ab) to a tar archive
  pack      Create an Android backup (.ab) from a tar archive

Flags:
  -h, -help   Show help message
```

### Unpack

Extract an `.ab` backup file into a `.tar` archive.

```sh
abe unpack backup.ab
```

For encrypted backups, provide the password:

```sh
abe unpack backup.ab MyP@ssw0rd
```

> **Note:** If the backup is not encrypted, the password is ignored. If omitted for an encrypted backup, extraction will fail with a checksum mismatch error.

**Example output:**

```
Unpacking: successfully
```

### Pack

Create an `.ab` backup file from a `.tar` archive.

```sh
abe pack backup.tar
```

To encrypt the backup with AES-256:

```sh
abe pack backup.tar MyP@ssw0rd
```

> **Note:** Leave the password empty (`""`) for an unencrypted backup.

**Example output:**

```
Packing: successfully
```

## How It Works

The `.ab` file format consists of:

| Component    | Description                                                      |
|--------------|------------------------------------------------------------------|
| Magic Header | `ANDROID BACKUP` — identifies the file as an ADB backup          |
| Version      | Format version (max 5)                                           |
| Compression  | `1` indicates zlib-compressed data                               |
| Encryption   | `none` or `AES-256`                                              |
| Key Header   | PBKDF2-derived key material (salt, IV, encrypted master key)     |
| Data         | Zlib-compressed tar archive, optionally AES-256-CBC encrypted    |

For encrypted backups:

1. A random **master key** and **IV** are generated.
2. The master key is encrypted with a **PBKDF2-SHA1** derived key from the user password.
3. A checksum (also PBKDF2-SHA1) is used to verify password correctness on unpack.
4. The compressed tar data is encrypted with **AES-256-CBC** using the master key.

## License

Copyright (c) 2026 Garuda Project. All Rights Reserved.

Distributed under the [Apache License, Version 2.0](LICENSE). See `LICENSE` for more information.
