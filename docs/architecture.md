# Architecture

## Overview

IronShare follows a **zero-knowledge architecture** where the server never has access to plaintext secrets or encryption keys. All cryptographic operations are performed client-side.

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                          Client                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  1. Generate Salt (16 bytes) + IV (12 bytes)          │ │
│  │  2. Derive AES key from PIN + Salt (PBKDF2)           │ │
│  │  3. Encrypt plaintext with AES-256-GCM                │ │
│  │  4. POST {ciphertext, iv, salt, ttl, max_views}      │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                             ↓ HTTPS
┌─────────────────────────────────────────────────────────────┐
│                     Axum API Server                          │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  1. Receive encrypted payload                         │ │
│  │  2. Generate unique ID (NanoID, 12 chars)             │ │
│  │  3. Store {id, ciphertext, iv, salt, metadata}       │ │
│  │  4. Return {id, expires_at}                           │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                             ↓
┌─────────────────────────────────────────────────────────────┐
│                      SQLite Database                         │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  Table: secrets                                        │ │
│  │  - id (NanoID, 12 chars)                              │ │
│  │  - ciphertext (Base64)                                │ │
│  │  - iv (Base64)                                        │ │
│  │  - salt (Base64)                                      │ │
│  │  - max_views, views, expires_at, created_at          │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘

         Retrieval Flow
┌─────────────────────────────────────────────────────────────┐
│                          Client                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  1. POST /api/secret/{id}                             │ │
│  │  2. Receive {ciphertext, iv, salt}                    │ │
│  │  3. Derive AES key from PIN + salt (PBKDF2)           │ │
│  │  4. Decrypt ciphertext with AES-256-GCM               │ │
│  │  5. Return plaintext to application                   │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Components

### 1. Client-Side Crypto

**Reference Implementation**: `static/crypto.js`

**Responsibilities**:
- Generate cryptographic randomness (salt, IV)
- Derive encryption keys from PINs using PBKDF2
- Encrypt secrets with AES-256-GCM
- Decrypt secrets with provided PINs
- Handle encryption failures gracefully

**Key Functions**:

```javascript
IronCrypto.encrypt(plaintext, pin)
// → Returns { ciphertext, iv, salt } (all Base64)

IronCrypto.decrypt(ciphertext, iv, salt, pin)
// → Returns plaintext or null (wrong PIN)

IronCrypto.deriveKeyFromPin(pin, salt)
// → PBKDF2-SHA256 with 100,000 iterations
```

**WebCrypto API Usage**:
- **PBKDF2**: Key derivation from PIN
- **AES-GCM**: Authenticated encryption (256-bit keys)
- **RandomValues**: Secure random number generation

### 2. API Server (Axum)

**File**: `src/handlers.rs`

**Responsibilities**:
- Serve crypto.js reference implementation
- Handle API requests for storing/retrieving secrets
- Enforce expiration and view limits
- Track view counts
- Delete burned secrets

**Routes**:

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/` | API info and endpoint list |
| GET | `/health` | Health check |
| GET | `/crypto.js` | Reference crypto implementation |
| POST | `/api/secret` | Store encrypted secret |
| GET | `/api/secret/:id/check` | Check existence (no view consumed) |
| POST | `/api/secret/:id` | Retrieve encrypted secret |

**Static Assets**:
- `/crypto.js` embedded via `rust-embed`
- No other UI assets served

### 3. Database Layer

**File**: `src/db.rs`

**Functions**:

#### `store_secret()`
Stores encrypted secret metadata in SQLite.

**Parameters**:
- `id`: Unique NanoID (12 characters)
- `ciphertext`: Base64 encrypted data
- `iv`: Base64 initialization vector
- `salt`: Base64 PBKDF2 salt
- `max_views`: Maximum allowed views (0 = unlimited)
- `expires_at`: Unix timestamp for expiration

#### `fetch_and_increment_view()`
Atomically retrieves secret and increments view counter.

**Logic**:
1. Begin transaction
2. Fetch secret if not expired
3. Check if view limit reached → delete if true
4. Increment view counter
5. Commit transaction
6. Return encrypted data or None

#### `delete_secret()`
Manually deletes a secret by ID.

#### `purge_expired()`
Removes all expired secrets (for periodic cleanup).

### 4. Cryptography Module

**File**: `src/crypto.rs`

**Server-Side Utilities**:
- `generate_iv()`: Create random IVs (not used in current flow)
- `encode_base64()`: URL-safe Base64 encoding
- `decode_base64()`: URL-safe Base64 decoding
- `generate_pin()`: Generate secure 6-digit PINs

**Note**: Heavy cryptography (AES, PBKDF2) happens client-side. Server utilities are helpers.

### 5. Data Models

**File**: `src/models.rs`

**StoreRequest**: Client → Server
```rust
{
    ciphertext: String,  // Base64
    iv: String,          // Base64
    salt: String,        // Base64
    max_views: i64,      // 0 = unlimited, 1 = burn
    ttl_minutes: i64     // Expiration in minutes
}
```

**StoreResponse**: Server → Client
```rust
{
    id: String,          // NanoID
    expires_at: i64      // Unix timestamp
}
```

**ViewResponse**: Server → Client
```rust
{
    ciphertext: String,
    iv: String,
    salt: String,
    expires_at: i64,
    remaining_views: i64,
    total_views: i64
}
```

**SecretRow**: Database row
```rust
{
    id: String,
    ciphertext: String,
    iv: String,
    salt: String,
    max_views: i64,
    views: i64,
    expires_at: i64
}
```

## Encryption Flow Details

### Key Derivation (PBKDF2)

```
Input:
  - PIN: User-provided passphrase (any length)
  - Salt: 16 random bytes

Process:
  - Algorithm: PBKDF2-SHA256
  - Iterations: 100,000
  - Output: 256-bit AES key

Result:
  - AES-256 key (non-extractable)
```

### Encryption (AES-256-GCM)

```
Input:
  - Plaintext: Secret content
  - Key: Derived from PIN
  - IV: 12 random bytes

Process:
  - Algorithm: AES-GCM
  - Key size: 256 bits
  - Authentication: Built into GCM

Output:
  - Ciphertext + Authentication Tag
  - Base64 encoded for transmission
```

### Storage Format

All data stored as Base64 strings:

```
ciphertext = Base64(AES-GCM output)
iv = Base64(12 random bytes)
salt = Base64(16 random bytes)
```

## Security Properties

### Zero-Knowledge
The server architecture ensures:
- **No plaintext access**: Only encrypted data stored
- **No key access**: PIN never transmitted to server
- **No key derivation**: Server cannot derive encryption keys
- **No decryption capability**: Server cannot read secrets

### Burn After Reading
Implemented atomically with database transactions:
1. Fetch secret
2. Check view count
3. Increment counter
4. Delete if limit reached
5. Commit (all-or-nothing)

### Time-Limited Secrets
- Expiration checked on every fetch
- Expired secrets not returned
- Background cleanup possible with `purge_expired()`

### Tamper Detection
- AES-GCM provides authentication
- Any modification to ciphertext → decryption fails
- Wrong PIN → decryption fails (same error)

## Scalability Considerations

### Current Architecture
- **Single-server**: No distributed concerns
- **SQLite**: Simple, embedded database
- **No caching**: Direct database access
- **Stateless**: No session management

## Monitoring and Observability

### Logging
Uses `tracing` for structured logging:
- Secret creation events (with ID)
- Secret access events (with view count)
- Secret deletion events
- Error events with context

### Health Check
`GET /health` endpoint returns:
```json
{
    "status": "ok",
    "message": "IronShare is secure"
}
```

## Dependencies

### Core Framework
- `axum`: HTTP server and routing
- `tokio`: Async runtime
- `tower-http`: Middleware (CORS, tracing, static files)

### Data Handling
- `serde`: Serialization/deserialization
- `serde_json`: JSON support
- `sqlx`: Database access with compile-time verification

### Cryptography
- `ring`: Crypto primitives (RNG, hashing)
- `argon2`: Password hashing (not currently used)
- `nanoid`: Unique ID generation

### Utilities
- `uuid`: UUID generation (not actively used)
- `time`: Timestamp handling
- `tracing`: Structured logging
- `base64`: Base64 encoding
- `rust-embed`: Asset embedding

## Deployment Architecture

### Single Binary
- All assets embedded
- No external files needed (except database)
- Portable across platforms

### Resource Requirements
- **Memory**: ~10-50MB (minimal)
- **CPU**: Low (I/O bound)
- **Disk**: Depends on secret volume
- **Network**: Stateless, horizontal scaling possible

### Recommended Setup
```
┌──────────────┐
│ Reverse Proxy│  ← Nginx/Caddy (TLS termination)
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
