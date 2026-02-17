# IronShare API Documentation

IronShare is a zero-knowledge secret sharing API service built with Rust and Axum.

## Core Principle

The server stores only encrypted blobs. All encryption/decryption operations are performed client-side. The server never has access to plaintext content, PINs, or encryption keys.

## Documentation

- **[API Reference](./api-reference.md)** - HTTP endpoints, request/response formats
- **[Architecture](./architecture.md)** - System design, data flow, encryption process
- **[Security](./security.md)** - Threat model, cryptography details, best practices
- **[Development](./development.md)** - Building, testing, contributing
- **[Deployment](./deployment.md)** - Production setup (systemd, nginx, Docker)
- **[MCP Integration](./mcp-integration.md)** - AI assistant integration guide

## Quick Start

```bash
# Docker (recommended)
docker compose up -d

# From source
cargo build --release
./target/release/ironshare
```

API available at `http://localhost:3000`

## Reference Implementation

[`/crypto.js`](../static/crypto.js) provides a complete client-side encryption/decryption implementation using WebCrypto API (PBKDF2 + AES-256-GCM).

## Key Technologies

- **Backend**: Rust 1.93+, Axum, SQLx, Tokio
- **Crypto**: WebCrypto API (AES-256-GCM, PBKDF2-SHA256)
- **Database**: SQLite
- **Deployment**: Single binary (~10MB)

## License

MIT License - See [LICENSE](../LICENSE)
