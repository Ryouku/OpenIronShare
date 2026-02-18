# API Reference

## Overview

IronShare exposes a minimal REST API for storing and retrieving encrypted secrets. All encryption happens client-side, and the server only handles encrypted blobs.

**Base URL**: `http://localhost:3000` (default)

**Content-Type**: `application/json`

## Endpoints

### 1. Health Check

Check if the server is running.

**Endpoint**: `GET /health`

**Response**: `200 OK`

```json
{
  "status": "ok",
  "message": "IronShare is secure"
}
```

**Example**:
```bash
curl http://localhost:3000/health
```

---

### 2. Store Secret

Store an encrypted secret on the server.

**Endpoint**: `POST /api/secret`

**Request Headers**:
```
Content-Type: application/json
```

**Request Body**:
```json
{
  "ciphertext": "base64_encoded_encrypted_data",
  "iv": "base64_encoded_initialization_vector",
  "salt": "base64_encoded_salt",
  "max_views": 1,
  "ttl_minutes": 60
}
```

**Parameters**:

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `ciphertext` | string | Yes | - | Base64-encoded AES-GCM ciphertext |
| `iv` | string | Yes | - | Base64-encoded initialization vector (12 bytes) |
| `salt` | string | Yes | - | Base64-encoded PBKDF2 salt (16 bytes) |
| `max_views` | integer | No | 1 | Maximum views before deletion (0 = unlimited) |
| `ttl_minutes` | integer | No | 60 | Time-to-live in minutes |

**Response**: `201 Created`

```json
{
  "id": "abc123xyz789",
  "expires_at": 1704067200
}
```

**Response Fields**:

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique secret identifier (NanoID, 12 chars) |
| `expires_at` | integer | Unix timestamp when secret expires |

**Error Responses**:

- `500 Internal Server Error`: Database error

**Example**:
```bash
curl -X POST http://localhost:3000/api/secret \
  -H "Content-Type: application/json" \
  -d '{
    "ciphertext": "k8j2l3kj4l2k3j4lk23j4l23kj4l23kj4",
    "iv": "a1b2c3d4e5f6g7h8i9j0",
    "salt": "s1a2l3t4s5a6l7t8s9a0",
    "max_views": 1,
    "ttl_minutes": 60
  }'
```

---

### 3. Retrieve Secret

Retrieve an encrypted secret by ID and increment view counter.

**Endpoint**: `POST /api/secret/:id`

**Path Parameters**:

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Secret identifier returned from store operation |

**Request Body**: Empty

**Response**: `200 OK`

```json
{
  "ciphertext": "base64_encoded_encrypted_data",
  "iv": "base64_encoded_initialization_vector",
  "salt": "base64_encoded_salt",
  "expires_at": 1704067200,
  "remaining_views": 0,
  "total_views": 1
}
```

**Response Fields**:

| Field | Type | Description |
|-------|------|-------------|
| `ciphertext` | string | Base64-encoded encrypted data |
| `iv` | string | Base64-encoded initialization vector |
| `salt` | string | Base64-encoded PBKDF2 salt |
| `expires_at` | integer | Unix timestamp when secret expires |
| `remaining_views` | integer | Views remaining (-1 = unlimited) |
| `total_views` | integer | Total times viewed |

**Error Responses**:

- `410 Gone`: Secret expired, burned, or never existed
- `500 Internal Server Error`: Database error

**Example**:
```bash
curl -X POST http://localhost:3000/api/secret/abc123xyz789
```

**Gone Response** (`410`):
```json
{
  "status": "gone",
  "message": "Secret has expired or been burned"
}
```

---

### 4. Get API Info

Get service information and available endpoints.

**Endpoint**: `GET /`

**Response**: `200 OK`

```json
{
  "name": "IronShare API",
  "version": "0.3.0",
  "description": "Zero-knowledge secret sharing API",
  "endpoints": {
    "health": "GET /health",
    "crypto_reference": "GET /crypto.js",
    "create_secret": "POST /api/secret",
    "check_secret": "GET /api/secret/:id/check",
    "retrieve_secret": "POST /api/secret/:id"
  },
  "documentation": "https://github.com/Ryouku/OpenIronShare"
}
```

**Example**:
```bash
curl http://localhost:3000/
```

---

### 5. Get Crypto Reference

Download the reference client-side encryption implementation.

**Endpoint**: `GET /crypto.js`

**Response**: `200 OK` (JavaScript file)

Complete WebCrypto API implementation for PBKDF2 + AES-256-GCM.

**Example**:
```bash
curl http://localhost:3000/crypto.js -o crypto.js
```

---

## Client-Side Crypto API

The reference implementation (`crypto.js`) provides `IronCrypto` with these functions:

### Encryption

```javascript
const encrypted = await IronCrypto.encrypt(plaintext, passphrase);
// Throws if passphrase < 8 characters
// Returns: { ciphertext, iv, salt } (URL-safe Base64)
```

### Decryption

```javascript
const plaintext = await IronCrypto.decrypt(
  ciphertext,
  iv,
  salt,
  passphrase
);
// Returns: plaintext string or null (wrong passphrase)
```

### Passphrase Generation

```javascript
const passphrase = IronCrypto.generatePassphrase();
// Returns: 16-char random alphanumeric string (~92 bits entropy)

const shorter = IronCrypto.generatePassphrase(12);
// Returns: 12-char random string (~69 bits entropy)
```

---

## Rate Limiting

Built-in via `tower_governor`:

- **Secret creation** (`POST /api/secret`): 10 requests/second per IP (burst: 20)
- **Secret retrieval** (`POST /api/secret/:id`, `GET /api/secret/:id/check`): 5 requests/second per IP (burst: 10)

HTTP `429 Too Many Requests` is returned when limits are exceeded.

---

## CORS Configuration

**Not enabled by default.**

To enable CORS for API-only usage, modify `src/handlers.rs`:

```rust
use tower_http::cors::CorsLayer;

.layer(
    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST])
)
```

---

## Error Handling

All API errors follow this format:

```json
{
  "status": "error",
  "message": "Human-readable error description"
}
```

**Common HTTP Status Codes**:

| Code | Meaning | When It Occurs |
|------|---------|----------------|
| `200` | OK | Successful retrieval |
| `201` | Created | Secret stored successfully |
| `410` | Gone | Secret expired, burned, or doesn't exist |
| `500` | Internal Server Error | Database or server error |

---

## Complete Workflow Example

### 1. Encrypt and Store a Secret (JavaScript/Node.js)

```javascript
import IronCrypto from './crypto.js';

const secret = "my-api-key-12345";
const passphrase = IronCrypto.generatePassphrase(); // 16-char, ~92 bits

// Encrypt
const encrypted = await IronCrypto.encrypt(secret, passphrase);

// Store
const response = await fetch('http://localhost:3000/api/secret', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    ciphertext: encrypted.ciphertext,
    iv: encrypted.iv,
    salt: encrypted.salt,
    max_views: 1,
    ttl_minutes: 60
  })
});

const result = await response.json();
console.log(`Secret ID: ${result.id}`);
console.log(`Passphrase: ${passphrase}`);
// Share the ID and passphrase via separate channels
```

### 2. Retrieve and Decrypt a Secret (JavaScript/Node.js)

```javascript
const secretId = "abc123xyz789";
const passphrase = "..."; // received out-of-band

const response = await fetch(`http://localhost:3000/api/secret/${secretId}`, {
  method: 'POST'
});

if (response.status === 410) {
  console.error("Secret has been burned or expired");
} else {
  const data = await response.json();

  const plaintext = await IronCrypto.decrypt(
    data.ciphertext,
    data.iv,
    data.salt,
    passphrase
  );

  if (plaintext) {
    console.log("Decrypted:", plaintext);
  } else {
    console.error("Wrong passphrase or corrupted data");
  }
}
```

---

## Security Considerations

### What the API Receives

✅ **Stored on Server**:
- Encrypted ciphertext (unreadable)
- Initialization vector (public)
- PBKDF2 salt (public)
- Metadata (view counts, expiration)

❌ **Never Sent to Server**:
- Plaintext content
- Encryption PIN/passphrase
- Derived AES keys

### Best Practices

1. **Always use HTTPS** in production
2. **Share ID and passphrase separately** (different channels)
3. **Use burn-after-reading** for sensitive data (`max_views: 1`)
4. **Set short TTLs** (minutes/hours, not days)
5. **Never log passphrases** on client or server
6. **Use `generatePassphrase()`** instead of short or predictable passwords
7. **Enable CORS** only for trusted origins

---

## Testing the API

### Using cURL

**Store a secret**:
```bash
curl -X POST http://localhost:3000/api/secret \
  -H "Content-Type: application/json" \
  -d '{
    "ciphertext": "test_cipher",
    "iv": "test_iv",
    "salt": "test_salt",
    "max_views": 1,
    "ttl_minutes": 15
  }'
```

**Retrieve a secret**:
```bash
curl -X POST http://localhost:3000/api/secret/abc123xyz789
```

### Using Rust Tests

```bash
cargo test
```

See `tests/api_tests.rs` for complete integration tests.

---
