# MCP Integration Guide

IronShare supports [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) for secure secret retrieval by AI assistants. This allows you to share sensitive information with AI tools like Claude, Cursor, and Cline while maintaining zero-knowledge security.

---

## Overview

An MCP server can retrieve and decrypt secrets from IronShare by:
1. **Checking** if a secret exists (without consuming views)
2. **Retrieving** the encrypted blob from the server
3. **Decrypting** locally using the user-provided PIN

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
  "max_views": 1,
  "views": 0,
  "remaining_views": 1,
  "expires_at": 1709251200
}
```

**Errors:**
- `404` - Secret not found or expired
- `429` - Rate limit exceeded

---

### 2. Retrieve Secret

```http
POST /api/secret/{id}
Content-Type: application/json
Body: {}
```

**Purpose:** Retrieve encrypted blob and increment view counter.

**Response:**
```json
{
  "id": "abc123xyz",
  "ciphertext": "base64-encoded-encrypted-data",
  "iv": "base64-encoded-iv",
  "salt": "base64-encoded-salt",
  "max_views": 1,
  "views": 1,
  "remaining_views": 0,
  "expires_at": 1709251200
}
```

**Notes:**
- This **consumes a view** — counter increments
- If `remaining_views` reaches 0, secret is deleted immediately
- Returns `404` if secret doesn't exist or max views exceeded

**Errors:**
- `404` - Secret not found, expired, or burned
- `429` - Rate limit exceeded

---

## Encryption Specification

IronShare uses the following cryptographic primitives:

### Key Derivation (PBKDF2-SHA256)
```
iterations: 100,000
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
PIN + Salt → PBKDF2-SHA256 → Encryption Key
Plaintext + Key + IV → AES-256-GCM → Ciphertext
```

---

## MCP Server Implementation

### Tool Definition

```typescript
{
  name: "retrieve_ironshare_secret",
  description: "Retrieve and decrypt a secret from IronShare. User must provide both the URL and PIN.",
  inputSchema: {
    type: "object",
    properties: {
      url: {
        type: "string",
        description: "The IronShare secret URL (e.g., https://your-domain.com/view/abc123)"
      },
      pin: {
        type: "string",
        description: "The PIN or passphrase to decrypt the secret"
      }
    },
    required: ["url", "pin"]
  }
}
```

---

### Example Implementation (Node.js)

```javascript
import { webcrypto } from 'crypto';

async function retrieveIronShareSecret(url, pin) {
  // 1. Parse secret ID from URL
  const match = url.match(/\/view\/([a-zA-Z0-9_-]+)/);
  if (!match) throw new Error('Invalid IronShare URL');
  const secretId = match[1];
  
  // 2. Extract base URL
  const baseUrl = new URL(url).origin;
  
  // 3. Check if secret exists (optional, doesn't consume view)
  const checkResponse = await fetch(`${baseUrl}/api/secret/${secretId}/check`);
  if (!checkResponse.ok) {
    throw new Error(`Secret not found or expired (${checkResponse.status})`);
  }
  const checkData = await checkResponse.json();
  console.log(`Secret exists. Remaining views: ${checkData.remaining_views}`);
  
  // 4. Retrieve encrypted blob (consumes a view)
  const retrieveResponse = await fetch(`${baseUrl}/api/secret/${secretId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({})
  });
  
  if (!retrieveResponse.ok) {
    throw new Error(`Failed to retrieve secret (${retrieveResponse.status})`);
  }
  
  const encryptedData = await retrieveResponse.json();
  
  // 5. Decrypt locally
  const plaintext = await decryptSecret(
    encryptedData.ciphertext,
    encryptedData.iv,
    encryptedData.salt,
    pin
  );
  
  return {
    plaintext,
    remaining_views: encryptedData.remaining_views,
    expires_at: new Date(encryptedData.expires_at * 1000).toISOString()
  };
}

async function decryptSecret(ciphertext, ivBase64, saltBase64, pin) {
  const crypto = webcrypto.subtle;
  
  // Decode base64
  const iv = Buffer.from(ivBase64, 'base64');
  const salt = Buffer.from(saltBase64, 'base64');
  const encryptedBytes = Buffer.from(ciphertext, 'base64');
  
  // Derive key from PIN using PBKDF2
  const encoder = new TextEncoder();
  const pinKey = await crypto.importKey(
    'raw',
    encoder.encode(pin),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  
  const key = await crypto.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    pinKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
  
  // Decrypt
  const decryptedBuffer = await crypto.decrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    encryptedBytes
  );
  
  const decoder = new TextDecoder();
  return decoder.decode(decryptedBuffer);
}

// Usage
const result = await retrieveIronShareSecret(
  'https://your-domain.com/view/abc123',
  'MySecretPin123'
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
from urllib.parse import urlparse

def retrieve_ironshare_secret(url: str, pin: str) -> dict:
    """
    Retrieve and decrypt a secret from IronShare.
    
    Args:
        url: IronShare secret URL (e.g., https://your-domain.com/view/abc123)
        pin: PIN or passphrase to decrypt the secret
        
    Returns:
        dict: {
            'plaintext': str,
            'remaining_views': int,
            'expires_at': int
        }
    """
    # 1. Parse secret ID
    parts = url.rstrip('/').split('/')
    secret_id = parts[-1]
    
    # 2. Extract base URL
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    
    # 3. Check if secret exists (optional)
    check_response = requests.get(f"{base_url}/api/secret/{secret_id}/check")
    check_response.raise_for_status()
    check_data = check_response.json()
    print(f"Secret exists. Remaining views: {check_data['remaining_views']}")
    
    # 4. Retrieve encrypted blob
    retrieve_response = requests.post(
        f"{base_url}/api/secret/{secret_id}",
        json={}
    )
    retrieve_response.raise_for_status()
    encrypted_data = retrieve_response.json()
    
    # 5. Decrypt locally
    plaintext = decrypt_secret(
        encrypted_data['ciphertext'],
        encrypted_data['iv'],
        encrypted_data['salt'],
        pin
    )
    
    return {
        'plaintext': plaintext,
        'remaining_views': encrypted_data['remaining_views'],
        'expires_at': encrypted_data['expires_at']
    }

def decrypt_secret(ciphertext_b64: str, iv_b64: str, salt_b64: str, pin: str) -> str:
    """Decrypt an IronShare secret using PBKDF2 + AES-256-GCM."""
    # Decode base64
    iv = base64.b64decode(iv_b64)
    salt = base64.b64decode(salt_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    
    # Derive key from PIN using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashlib.sha256(),
        length=32,  # 256 bits
        salt=salt,
        iterations=100000
    )
    key = kdf.derive(pin.encode('utf-8'))
    
    # Decrypt using AES-256-GCM
    aesgcm = AESGCM(key)
    plaintext_bytes = aesgcm.decrypt(iv, ciphertext, None)
    
    return plaintext_bytes.decode('utf-8')

# Usage
result = retrieve_ironshare_secret(
    'https://your-domain.com/view/abc123',
    'MySecretPin123'
)

print(f"Decrypted secret: {result['plaintext']}")
print(f"Remaining views: {result['remaining_views']}")
```

---

## Rate Limiting

IronShare enforces rate limits at both the application and Nginx levels:

### Application Layer (tower_governor)
- **Create:** 10 requests/second per IP (burst: 20)
- **Retrieve:** 5 requests/second per IP (burst: 10)

### Nginx Layer (if behind reverse proxy)
- **Create:** 10 requests/minute per IP (burst: 5)
- **Retrieve:** 30 requests/minute per IP (burst: 10)

**HTTP 429 Response:**
```json
{
  "status": "error",
  "message": "Rate limit exceeded"
}
```

---

## Security Considerations

### Zero-Knowledge Architecture
- Server stores only encrypted blobs — never plaintext
- PIN never leaves the client (browser or MCP server)
- Decryption happens locally using WebCrypto APIs

### View Consumption
- Each retrieval consumes a view (counter increments)
- Secret is deleted when `remaining_views` reaches 0
- Check endpoint (`/check`) does NOT consume views

### Wrong PIN Behavior
- Wrong PIN decryption **still consumes a view**
- This is intentional — server cannot verify PIN correctness
- Rate limiting prevents brute-force attacks

### HTTPS Required
- Always use HTTPS in production
- IronShare behind Cloudflare with Full (Strict) SSL mode
- Origin certificates for Cloudflare → Origin encryption

---

## Error Handling

### Common Errors

| Status Code | Meaning | Action |
|-------------|---------|--------|
| `404` | Secret not found, expired, or burned | Inform user |
| `429` | Rate limit exceeded | Retry with exponential backoff |
| `500` | Server error | Retry once, then fail |

### Retry Strategy

```javascript
async function fetchWithRetry(url, options, maxRetries = 3) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      const response = await fetch(url, options);
      if (response.status === 429) {
        // Rate limited - exponential backoff
        await new Promise(r => setTimeout(r, 1000 * Math.pow(2, i)));
        continue;
      }
      return response;
    } catch (err) {
      if (i === maxRetries - 1) throw err;
      await new Promise(r => setTimeout(r, 1000));
    }
  }
}
```

---

## Testing

### Test Secret Creation

```bash
# Create a test secret via CLI
curl -X POST https://your-domain.com/api/secret \
  -H "Content-Type: application/json" \
  -d '{
    "ciphertext": "test-ciphertext-base64",
    "iv": "test-iv-base64",
    "salt": "test-salt-base64",
    "max_views": 3,
    "ttl_minutes": 60
  }'
```

**Note:** For real secrets, use the web UI to ensure proper client-side encryption.

### Test Retrieval

```bash
# Check secret
curl https://your-domain.com/api/secret/abc123/check

# Retrieve secret (consumes view)
curl -X POST https://your-domain.com/api/secret/abc123 \
  -H "Content-Type: application/json" \
  -d '{}'
```

---

## MCP Server Template

Full working MCP server template: [Coming Soon]

**Recommended MCP Libraries:**
- Node.js: `@modelcontextprotocol/sdk`
- Python: `mcp` (official Python SDK)

---

## Support

- **API Base URL:** `https://your-domain.com`
- **GitHub:** [Link to repo]
- **Documentation:** `https://your-domain.com/` (this page)

---

## License

IronShare is open source. Check the repository for license details.
