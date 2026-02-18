# Security

## Threat Model

IronShare protects secrets from:

1. **Server compromise** — secrets remain encrypted; the server never holds keys
2. **Database leaks** — stolen dumps contain only ciphertext + public parameters
3. **Network eavesdropping** — only encrypted blobs transit the wire (+ HTTPS)
4. **Unauthorized access** — burn-after-reading and TTL restrict the attack window

**Out of scope**: client-side compromise (malware, keyloggers), phishing, compromised browsers, physical device access.

## Zero-Knowledge Architecture

The server has zero knowledge of:
- Plaintext content
- Encryption passphrase
- Derived encryption keys

All cryptographic operations run client-side via the WebCrypto API. The passphrase never leaves the client.

```
┌──────────────────────────────────────────────┐
│  TRUSTED: Client Application + Device        │
│  - Key derivation (PBKDF2)                   │
│  - Encryption / Decryption (AES-256-GCM)     │
│  - Passphrase storage (temporary, in-memory) │
└──────────────────────────────────────────────┘
                    ↓
┌──────────────────────────────────────────────┐
│  UNTRUSTED: Server + Network + Database      │
│  - Stores only encrypted blobs               │
│  - Cannot derive keys                        │
│  - Cannot decrypt                            │
└──────────────────────────────────────────────┘
```

## Cryptographic Design

### Encryption: AES-256-GCM

- **Key size**: 256 bits
- **IV size**: 96 bits (12 bytes), random per encryption
- **Authentication**: built-in GCM tag (128 bits) — tamper-evident
- **Standard**: NIST SP 800-38D

### Key Derivation: PBKDF2-SHA256

| Parameter | Value |
|-----------|-------|
| Algorithm | PBKDF2 |
| Hash | SHA-256 |
| Iterations | 600,000 |
| Salt | 128 bits (16 bytes), random per secret |
| Output | 256-bit AES key |

**Why 600,000 iterations**: NIST SP 800-132 (2023 revision) recommends a minimum of 600,000 for PBKDF2-SHA256. The previous default of 100,000 is no longer considered adequate given modern GPU throughput.

**Why PBKDF2 instead of Argon2**: The WebCrypto API (W3C standard) does not expose Argon2. PBKDF2 is the strongest KDF available in browsers without importing external libraries. Argon2 would be preferable for server-side hashing but is not applicable here since key derivation happens client-side.

### Passphrase Entropy vs. Brute-Force Cost

The table below estimates offline brute-force time against a single secret, assuming an attacker has the ciphertext, salt, and IV (i.e., full database dump), using a high-end GPU rig capable of ~1 million PBKDF2-SHA256 (600k iterations) hashes/second.

| Passphrase type | Entropy (bits) | Keyspace | Estimated time |
|-----------------|---------------|----------|---------------|
| 6-digit numeric PIN | ~20 | 1,000,000 | **< 1 second** |
| 8-char alphanumeric | ~46 | ~2×10^14 | ~7 years |
| 12-char mixed | ~71 | ~4×10^21 | infeasible |
| 16-char random (default `generatePassphrase()`) | ~92 | ~5×10^27 | infeasible |
| 4-word diceware passphrase | ~51 | ~2×10^15 | ~65 years |

**Takeaway**: Short numeric PINs are trivially brute-forced offline. The `encrypt()` function enforces a minimum 8-character passphrase. The `generatePassphrase()` function produces 16-character random strings (~92 bits) by default.

### Random Number Generation

- Source: `crypto.getRandomValues()` (WebCrypto API)
- OS-backed CSPRNG
- Used for: IVs, salts, passphrase generation

### Base64 Encoding

URL-safe Base64 (RFC 4648 §5): `A-Za-z0-9-_`, no padding.

## Attack Surface

### 1. Offline Brute-Force

**Threat**: Attacker downloads ciphertext and tries passphrases offline.

**Mitigations**:
- 600,000 PBKDF2 iterations raise the cost per guess
- 8-character minimum passphrase enforced client-side
- Burn-after-reading limits ciphertext exposure
- TTL reduces the window for obtaining ciphertext

**Residual risk**: An attacker with a database dump and a weak user-chosen passphrase can brute-force it. PBKDF2 is GPU-friendly — it lacks the memory-hardness of Argon2/scrypt. Strong passphrases are the primary defense.

### 2. Database Compromise

**Threat**: Attacker obtains the SQLite file.

**Attacker gets**: ciphertext, IVs, salts (public parameters), metadata (view counts, expiry).

**Attacker cannot get**: plaintext, passphrases, derived keys.

**Residual risk**: Low. Equivalent to the offline brute-force scenario above.

### 3. Man-in-the-Middle

**Threat**: Attacker intercepts client ↔ server traffic.

**With HTTPS**: negligible risk (transport-layer encryption).

**Without HTTPS**: attacker sees encrypted blobs (still secure) but could serve malicious JavaScript to exfiltrate passphrases.

**Mitigation**: always deploy behind HTTPS. The server sets `Content-Security-Policy: default-src 'none'; script-src 'self'; connect-src 'self'`.

### 4. Malicious JavaScript Injection

**Threat**: Compromised server serves modified `crypto.js` to steal passphrases.

**Mitigations**:
- `crypto.js` is embedded in the binary at compile time via `rust-embed` — modifying it requires rebuilding the binary
- CSP restricts script sources to `'self'`
- No external CDN dependencies

**Residual risk**: If the binary itself is replaced on the server, all bets are off. Standard server hardening applies.

### 5. Timing / Side-Channel

AES-GCM and PBKDF2 operations run inside the browser's WebCrypto implementation, which is typically constant-time. The server never performs any passphrase-dependent operations, so server-side timing attacks are not applicable.

## Best Practices

### For Users

1. Use `generatePassphrase()` or a strong passphrase (12+ characters)
2. Share the link and passphrase via **separate channels** (e.g., link over Slack, passphrase over Signal)
3. Use burn-after-reading (`max_views: 1`) for sensitive data
4. Set short TTLs — minutes or hours, not days

### For Operators

1. **HTTPS required** — deploy behind Nginx/Caddy with a valid certificate
2. **Security headers** — the server sets CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy automatically
3. **Rate limiting** — built-in via `tower_governor` (10 req/s create, 5 req/s retrieve per IP)
4. **Firewall** — block external access to port 3000; only the reverse proxy should reach it
5. **Updates** — run `cargo audit` regularly, keep dependencies current

## Known Limitations

1. **No server-side passphrase validation** — the server cannot enforce complexity because the passphrase never leaves the client. Client-side enforcement can be bypassed.
2. **PBKDF2 is GPU-friendly** — unlike Argon2 or scrypt, PBKDF2 has no memory-hardness. A well-funded attacker with GPU clusters can attempt more guesses per second. This is a WebCrypto API constraint.
3. **No client-side rate limiting on decryption** — once an attacker has the ciphertext, they can attempt offline decryption without any throttling. Burn-after-reading is the only mitigation.
4. **No audit trail** — intentional (privacy-focused), but means unauthorized access attempts cannot be detected.
5. **No user authentication** — anyone with the link can attempt retrieval. Security relies on ID obscurity (12-char NanoID ≈ 2^71) + passphrase.

## Compliance Notes

- **GDPR**: encrypted data, auto-deletion, no PII stored — generally compatible
- **HIPAA / PCI DSS**: not compliant out-of-the-box (no audit logs, no user auth, no key management infrastructure)

## Reporting Security Issues

Do not open a public GitHub issue. Email details to the maintainers with:
- Description of the vulnerability
- Steps to reproduce
- Potential impact

## References

- [NIST SP 800-132](https://csrc.nist.gov/publications/detail/sp/800-132/final) — PBKDF Recommendations
- [NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final) — AES-GCM Specification
- [RFC 4648](https://tools.ietf.org/html/rfc4648) — Base64 Encoding
- [WebCrypto API](https://www.w3.org/TR/WebCryptoAPI/)
