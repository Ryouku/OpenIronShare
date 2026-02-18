# MCP Integration Guide

IronShare supports [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) for secure secret retrieval by AI assistants. This allows sharing sensitive information with AI tools (Claude, Cursor, Cline) while maintaining zero-knowledge security.

---

## Overview

An MCP server can retrieve and decrypt secrets from IronShare by:
1. **Checking** if a secret exists (without consuming views)
2. **Retrieving** the encrypted blob from the server
3. **Decrypting** locally using the user-provided passphrase

The server never sees plaintext — decryption happens client-side using WebCrypto-compatible algorithms.

---

## API Endpoints

### 1. Check Secret Existence

```http
GET /api/secret/{id}/check
```

**Purpose:** Verify a secret exists without consuming a view.

**Response:**
```json
{
  "exists": true,
  "remaining_views": 1,
  "expires_at": 1709251200
}
```

**Errors:**
- `410` — Secret not found or expired
- `429` — Rate limit exceeded

---

### 2. Retrieve Secret

```http
POST /api/secret/{id}
```

**Purpose:** Retrieve encrypted blob and increment view counter.

**Response:**
```json
{
  "ciphertext": "base64-encoded-encrypted-data",
  "iv": "base64-encoded-iv",
  "salt": "base64-encoded-salt",
  "expires_at": 1709251200,
  "remaining_views": 0,
  "total_views": 1
}
```

**Notes:**
- This **consumes a view** — counter increments
- If `remaining_views` reaches 0, secret is deleted immediately
- Returns `410` if secret doesn't exist or view limit exceeded

---

## Encryption Specification

### Key Derivation (PBKDF2-SHA256)
```
iterations: 600,000
hash: SHA-256
salt: 16 bytes (base64-encoded, stored with secret)
output: 256-bit key
```

### Encryption (AES-256-GCM)
```
algorithm: AES-GCM
key size: 256 bits
iv: 12 bytes (96 bits, base64-encoded)
tag length: 128 bits (included in ciphertext)
```

### Data Flow
```
Passphrase + Salt → PBKDF2-SHA256 (600k iterations) → Encryption Key
Plaintext + Key + IV → AES-256-GCM → Ciphertext
```

---

## MCP Server Implementation

### Tool Definition

```typescript
{
  name: "retrieve_ironshare_secret",
  description: "Retrieve and decrypt a secret from IronShare. User must provide both the secret ID and passphrase.",
  inputSchema: {
    type: "object",
    properties: {
      url: {
        type: "string",
        description: "The IronShare API base URL with secret ID (e.g., https://your-domain.com/api/secret/abc123)"
      },
      passphrase: {
        type: "string",
        description: "The passphrase to decrypt the secret"
      }
    },
    required: ["url", "passphrase"]
  }
}
```

---

### Example Implementation (Node.js)

```javascript
import { webcrypto } from 'crypto';

async function retrieveIronShareSecret(baseUrl, secretId, passphrase) {
  // 1. Check if secret exists (optional, doesn't consume view)
  const checkResponse = await fetch(`${baseUrl}/api/secret/${secretId}/check`);
  if (!checkResponse.ok) {
    throw new Error(`Secret not found or expired (${checkResponse.status})`);
  }
  const checkData = await checkResponse.json();
  console.log(`Secret exists. Remaining views: ${checkData.remaining_views}`);

  // 2. Retrieve encrypted blob (consumes a view)
  const retrieveResponse = await fetch(`${baseUrl}/api/secret/${secretId}`, {
    method: 'POST'
  });

  if (!retrieveResponse.ok) {
    throw new Error(`Failed to retrieve secret (${retrieveResponse.status})`);
  }

  const encryptedData = await retrieveResponse.json();

  // 3. Decrypt locally
  const plaintext = await decryptSecret(
    encryptedData.ciphertext,
    encryptedData.iv,
    encryptedData.salt,
    passphrase
  );

  return {
    plaintext,
    remaining_views: encryptedData.remaining_views,
    expires_at: new Date(encryptedData.expires_at * 1000).toISOString()
  };
}

async function decryptSecret(ciphertext, ivBase64, saltBase64, passphrase) {
  const crypto = webcrypto.subtle;

  const iv = Buffer.from(ivBase64, 'base64');
  const salt = Buffer.from(saltBase64, 'base64');
  const encryptedBytes = Buffer.from(ciphertext, 'base64');

  const encoder = new TextEncoder();
  const keyMaterial = await crypto.importKey(
    'raw',
    encoder.encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  const key = await crypto.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 600000,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  const decryptedBuffer = await crypto.decrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    encryptedBytes
  );

  return new TextDecoder().decode(decryptedBuffer);
}

// Usage
const result = await retrieveIronShareSecret(
  'https://your-domain.com',
  'abc123xyz',
  'MyStrongPassphrase2024'
);

console.log('Decrypted secret:', result.plaintext);
console.log('Remaining views:', result.remaining_views);
```

---

### Example Implementation (Python)

```python
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import requests

def retrieve_ironshare_secret(base_url: str, secret_id: str, passphrase: str) -> dict:
    """Retrieve and decrypt a secret from IronShare."""
    # 1. Check if secret exists (optional)
    check_response = requests.get(f"{base_url}/api/secret/{secret_id}/check")
    check_response.raise_for_status()

    # 2. Retrieve encrypted blob
    retrieve_response = requests.post(f"{base_url}/api/secret/{secret_id}")
    retrieve_response.raise_for_status()
    encrypted_data = retrieve_response.json()

    # 3. Decrypt locally
    plaintext = decrypt_secret(
        encrypted_data['ciphertext'],
        encrypted_data['iv'],
        encrypted_data['salt'],
        passphrase
    )

    return {
        'plaintext': plaintext,
        'remaining_views': encrypted_data['remaining_views'],
        'expires_at': encrypted_data['expires_at']
    }

def decrypt_secret(ciphertext_b64: str, iv_b64: str, salt_b64: str, passphrase: str) -> str:
    """Decrypt an IronShare secret using PBKDF2 + AES-256-GCM."""
    iv = base64.b64decode(iv_b64)
    salt = base64.b64decode(salt_b64)
    ciphertext = base64.b64decode(ciphertext_b64)

    kdf = PBKDF2HMAC(
        algorithm=hashlib.sha256(),
        length=32,
        salt=salt,
        iterations=600000
    )
    key = kdf.derive(passphrase.encode('utf-8'))

    aesgcm = AESGCM(key)
    plaintext_bytes = aesgcm.decrypt(iv, ciphertext, None)

    return plaintext_bytes.decode('utf-8')

# Usage
result = retrieve_ironshare_secret(
    'https://your-domain.com',
    'abc123xyz',
    'MyStrongPassphrase2024'
)

print(f"Decrypted secret: {result['plaintext']}")
```

---

## Rate Limiting

### Application Layer (tower_governor)
- **Create:** 10 requests/second per IP (burst: 20)
- **Retrieve:** 5 requests/second per IP (burst: 10)

HTTP `429` is returned when limits are exceeded. Implement exponential backoff in your MCP server.

---

## Security Considerations

### Zero-Knowledge
- Server stores only encrypted blobs — never plaintext
- Passphrase never leaves the client (browser or MCP server)
- Decryption happens locally using WebCrypto-compatible APIs

### View Consumption
- Each retrieval consumes a view
- Secret is deleted when `remaining_views` reaches 0
- Check endpoint (`/check`) does NOT consume views

### Wrong Passphrase Behavior
- Wrong passphrase decryption **still consumes a view**
- Server cannot verify passphrase correctness — this is by design
- Rate limiting slows brute-force retrieval attempts

### HTTPS Required
Always use HTTPS in production to prevent MITM attacks.

---

## Error Handling

| Status Code | Meaning | Action |
|-------------|---------|--------|
| `410` | Secret not found, expired, or burned | Inform user |
| `429` | Rate limit exceeded | Retry with exponential backoff |
| `500` | Server error | Retry once, then fail |

---

## MCP Libraries

- Node.js: `@modelcontextprotocol/sdk`
- Python: `mcp` (official Python SDK)

---

## License

IronShare is open source — see [LICENSE](../LICENSE).
