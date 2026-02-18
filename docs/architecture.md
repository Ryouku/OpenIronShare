# Architecture

## Overview

IronShare is a **zero-knowledge** secret sharing API. The server stores only encrypted blobs — all cryptographic operations (key derivation, encryption, decryption) happen client-side.

## System Diagram

```
         Creation Flow

┌──────────────────────────────────────────────┐
│                    Client                     │
│  1. Generate salt (16 bytes) + IV (12 bytes) │
│  2. Derive AES key: deriveKey(passphrase,    │
│     salt) → PBKDF2-SHA256, 600k iterations   │
│  3. Encrypt plaintext with AES-256-GCM       │
│  4. POST {ciphertext, iv, salt, ttl,         │
│     max_views}                                │
└──────────────────────────────────────────────┘
                      ↓ HTTPS
┌──────────────────────────────────────────────┐
│               Axum API Server                 │
│  1. Validate payload sizes and limits        │
│  2. Generate unique ID (NanoID, 12 chars)    │
│  3. Store {id, ciphertext, iv, salt,         │
│     metadata} in SQLite                       │
│  4. Return {id, expires_at}                  │
└──────────────────────────────────────────────┘
                      ↓
┌──────────────────────────────────────────────┐
│                   SQLite                      │
│  Table: secrets                              │
│  id | ciphertext | iv | salt | max_views |   │
│  views | expires_at | created_at             │
└──────────────────────────────────────────────┘

         Retrieval Flow

┌──────────────────────────────────────────────┐
│                    Client                     │
│  1. POST /api/secret/{id}                    │
│  2. Receive {ciphertext, iv, salt}           │
│  3. Derive AES key: deriveKey(passphrase,    │
│     salt) → PBKDF2-SHA256, 600k iterations   │
│  4. Decrypt ciphertext with AES-256-GCM      │
│  5. Return plaintext to application          │
└──────────────────────────────────────────────┘
```

## Components

### 1. Client-Side Crypto (`static/crypto.js`)

Reference implementation using the WebCrypto API.

Key functions:

```javascript
IronCrypto.encrypt(plaintext, passphrase)
// → { ciphertext, iv, salt } (URL-safe Base64)

IronCrypto.decrypt(ciphertext, iv, salt, passphrase)
// → plaintext string or null (wrong passphrase)

IronCrypto.deriveKey(passphrase, salt)
// → PBKDF2-SHA256, 600,000 iterations → AES-256 key

IronCrypto.generatePassphrase(length = 16)
// → random alphanumeric string (~92 bits entropy)
```

Passphrase minimum: 8 characters (enforced by `encrypt()`).

### 2. API Server (`src/handlers.rs`)

Axum router with rate-limited route groups:

| Method | Path | Rate Limit | Purpose |
|--------|------|-----------|---------|
| GET | `/` | none | API info |
| GET | `/health` | none | Liveness probe |
| GET | `/crypto.js` | none | Reference crypto (embedded via `rust-embed`) |
| POST | `/api/secret` | 10/s, burst 20 | Store encrypted secret |
| GET | `/api/secret/:id/check` | 5/s, burst 10 | Check existence (no view consumed) |
| POST | `/api/secret/:id` | 5/s, burst 10 | Retrieve encrypted secret |

Global middleware: body limit (128 KB), tracing, security headers (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy).

### 3. Database Layer (`src/db.rs`)

All mutations use explicit SQLite transactions:

- **`store_secret()`** — insert with circuit-breaker check (max 100k active secrets)
- **`fetch_and_increment_view()`** — atomic fetch + increment + conditional delete (burn-after-reading)
- **`check_secret_exists()`** — read-only, no view consumed
- **`purge_expired()`** — background cleanup, runs every 15 minutes

### 4. Data Models (`src/models.rs`)

```
StoreRequest  → { ciphertext, iv, salt, max_views, ttl_minutes }
StoreResponse → { id, expires_at }
ViewResponse  → { ciphertext, iv, salt, expires_at, remaining_views, total_views }
SecretRow     → database row
```

Validation constants: max ciphertext 50 KB, max TTL 7 days, max views 100.

### 5. Configuration (`src/config.rs`)

| Variable | Default | Purpose |
|----------|---------|---------|
| `DATABASE_URL` | `sqlite:./ironshare.db` | SQLite connection string |
| `IRONSHARE_HOST` | `0.0.0.0` | Bind address |
| `IRONSHARE_PORT` | `3000` | Server port |

## Security Properties

- **Zero-knowledge**: server stores only ciphertext + public parameters
- **Burn-after-reading**: atomic delete inside the retrieval transaction
- **Time-limited**: expiry checked on every fetch; background purge cleans up
- **Tamper-evident**: AES-GCM authentication tag rejects modified ciphertext

## Dependencies

### Core
- `axum` — HTTP server and routing
- `tokio` — async runtime
- `tower-http` — middleware (tracing, headers, body limits)
- `tower_governor` — per-IP rate limiting

### Data
- `sqlx` — compile-time verified SQLite queries
- `serde` / `serde_json` — serialization
- `time` — timestamps

### Crypto
- `ring` — server-side RNG and hashing utilities
- `nanoid` — URL-safe unique ID generation
- `base64` — encoding

### Embedded Assets
- `rust-embed` — compiles `static/` into the binary

## Deployment

Single statically-linked binary + SQLite file. No external services required.

```
┌──────────────┐
│ Reverse Proxy│  ← Nginx / Caddy (TLS termination)
│ (HTTPS)      │
└──────┬───────┘
       │
┌──────▼───────┐
│  IronShare   │  ← Rust binary on port 3000
│   (HTTP)     │
└──────┬───────┘
       │
┌──────▼───────┐
│    SQLite    │  ← Local file database
└──────────────┘
```
