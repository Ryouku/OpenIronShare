# IronShare Documentation

Zero-knowledge secret sharing API. The server stores only encrypted blobs — all encryption and decryption happens client-side using PBKDF2-SHA256 (600,000 iterations) and AES-256-GCM.

## Contents

- **[API Reference](./api-reference.md)** — HTTP endpoints, request/response formats
- **[Architecture](./architecture.md)** — System design, data flow, component overview
- **[Security](./security.md)** — Threat model, cryptographic design, entropy analysis, known limitations
- **[Development](./development.md)** — Building, testing, contributing
- **[Deployment](./deployment.md)** — Docker, systemd, reverse proxy setup
- **[MCP Integration](./mcp-integration.md)** — AI assistant integration (Claude, Cursor, Cline)

## Quick Start

```bash
# Docker (recommended)
docker compose up -d

# From source
cargo build --release
./target/release/ironshare
```

API available at `http://localhost:3000`.

## Reference Implementation

[`/crypto.js`](../static/crypto.js) — complete client-side crypto using WebCrypto API. Passphrase minimum: 8 characters. Default `generatePassphrase()`: 16 characters (~92 bits entropy).

## Key Technologies

- **Backend**: Rust 1.93+, Axum, SQLx, Tokio
- **Crypto**: WebCrypto API (AES-256-GCM, PBKDF2-SHA256, 600k iterations)
- **Database**: SQLite
- **Deployment**: Single binary + SQLite file
