# IronShare

Zero-knowledge secret sharing API built with Rust and Axum. Clients encrypt secrets locally; the server stores only the encrypted blob and never has access to plaintext, PINs, or keys.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.93%2B-orange.svg)](https://www.rust-lang.org/)

## Quick Start

### Docker (recommended)

```bash
git clone https://github.com/Ryouku/OpenIronShare.git
cd OpenIronShare
docker compose up -d
```

### From Source

```bash
git clone https://github.com/Ryouku/OpenIronShare.git
cd OpenIronShare
cargo build --release
./target/release/ironshare
```

API available at `http://localhost:3000`.

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `sqlite:./ironshare.db` | SQLite connection string |
| `IRONSHARE_HOST` | `0.0.0.0` | Bind address |
| `IRONSHARE_PORT` | `3000` | Server port |

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | API info |
| `GET` | `/health` | Health check |
| `GET` | `/crypto.js` | Reference crypto implementation |
| `POST` | `/api/secret` | Store encrypted secret |
| `GET` | `/api/secret/:id/check` | Check existence (no view consumed) |
| `POST` | `/api/secret/:id` | Retrieve encrypted secret |

## How It Works

```
Client: encrypt(plaintext, pin) → {ciphertext, iv, salt}
Client: POST /api/secret {ciphertext, iv, salt, ttl_minutes, max_views}
Server: stores encrypted blob → returns {id, expires_at}

Client: POST /api/secret/:id → receives {ciphertext, iv, salt}
Client: decrypt(ciphertext, iv, salt, pin) → plaintext
```

The server cannot decrypt secrets. Wrong PIN fails silently client-side via AES-GCM authentication.

## Client Implementation

[`static/crypto.js`](static/crypto.js) is a complete WebCrypto API reference implementation (PBKDF2-SHA256 + AES-256-GCM). Use it directly or port to any language.

```javascript
// Encrypt
const { ciphertext, iv, salt } = await IronCrypto.encrypt("my secret", "pin");

// Store
const { id } = await fetch("/api/secret", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ ciphertext, iv, salt, max_views: 1, ttl_minutes: 60 })
}).then(r => r.json());

// Retrieve and decrypt
const data = await fetch(`/api/secret/${id}`, { method: "POST" }).then(r => r.json());
const plaintext = await IronCrypto.decrypt(data.ciphertext, data.iv, data.salt, "pin");
```

## Project Structure

```
ironshare/
├── src/
│   ├── main.rs        # Entry point, DB setup, background cleanup
│   ├── handlers.rs    # HTTP route handlers
│   ├── models.rs      # Request/response types, validation
│   ├── db.rs          # Database operations
│   └── config.rs      # Environment configuration
├── static/
│   └── crypto.js      # Reference crypto implementation
├── migrations/        # SQLite schema migrations
├── tests/             # Integration tests
├── docs/              # Documentation
├── nginx/             # Nginx config example
├── deploy/            # Systemd service and install scripts
├── Dockerfile
└── docker-compose.yml
```

## Documentation

- [API Reference](./docs/api-reference.md)
- [Architecture](./docs/architecture.md)
- [Security](./docs/security.md)
- [Deployment](./docs/deployment.md)
- [Development](./docs/development.md)
- [MCP Integration](./docs/mcp-integration.md)

## Contributing

1. Fork and create a feature branch
2. Make changes and run `cargo test`
3. Run `cargo fmt` and `cargo clippy`
4. Open a pull request

See [Development Guide](./docs/development.md) for full details.

## License

[MIT](LICENSE)
