# Security

## Threat Model

IronShare is designed to protect secrets from:

1. **Server compromise**: Even if the server is fully compromised, secrets remain encrypted
2. **Database leaks**: Stolen database dumps contain only encrypted data
3. **Network eavesdropping**: Secrets transmitted only in encrypted form (+ use HTTPS)
4. **Unauthorized access**: Burn-after-reading and time limits restrict access

**Out of Scope**:
- Client-side compromise (malware, keyloggers)
- Phishing attacks targeting PINs
- Compromised browsers or browser extensions
- Physical access to recipient's device

## Zero-Knowledge Architecture

### What This Means

**Zero-Knowledge** = Server has zero knowledge of:
- The plaintext content
- The encryption PIN/passphrase
- The derived encryption keys

### How It's Achieved

1. **Client-Side Encryption**: All crypto happens client-side via WebCrypto API
2. **No Key Transmission**: PIN never leaves the client
3. **No Server-Side Decryption**: Server cannot decrypt even if compromised
4. **Separate Communication**: Secret ID and PIN shared via different channels

### Trust Boundaries

```
┌─────────────────────────────────────────────┐
│  TRUSTED: Client Application + Device      │
│  - Encryption/Decryption                    │
│  - Key derivation                           │
│  - PIN storage (temporary)                  │
└─────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│  UNTRUSTED: Server + Network + Database     │
│  - Only sees encrypted blobs                │
│  - Cannot derive keys                       │
│  - Cannot decrypt                           │
└─────────────────────────────────────────────┘
```

## Cryptographic Design

### Encryption Algorithm

**AES-256-GCM** (Galois/Counter Mode)

- **Key Size**: 256 bits (maximum AES security)
- **Mode**: GCM (provides authentication + encryption)
- **Authentication**: Built-in tamper detection
- **IV Size**: 96 bits (12 bytes) - recommended for GCM

**Properties**:
- ✅ AEAD (Authenticated Encryption with Associated Data)
- ✅ Tamper-evident (any modification → decryption fails)
- ✅ Industry standard (NIST approved)
- ✅ Hardware acceleration on modern CPUs

### Key Derivation

**PBKDF2-SHA256**

- **Algorithm**: PBKDF2 (Password-Based Key Derivation Function 2)
- **Hash**: SHA-256
- **Iterations**: 100,000
- **Salt Size**: 128 bits (16 bytes)
- **Output**: 256-bit AES key

**Why PBKDF2**:
- ✅ Widely supported (WebCrypto API)
- ✅ Proven security track record
- ✅ Adjustable iteration count
- ✅ NIST recommended (SP 800-132)

**Iteration Count Rationale**:
- 100,000 iterations balance security vs. performance
- Acceptable delay (~100ms on modern devices)
- Raises cost of brute-force attacks
- Can be increased in future versions

### Random Number Generation

**Source**: `crypto.getRandomValues()` (WebCrypto API)

- Cryptographically secure PRNG
- OS-backed entropy source
- Used for: IVs, salts, PIN generation

### Base64 Encoding

**URL-Safe Base64** (RFC 4648)

- Character set: `A-Za-z0-9-_`
- No padding (`=` removed)
- Safe for URLs and JSON

## Attack Surface Analysis

### 1. Brute-Force PIN Attacks

**Threat**: Attacker tries all possible PINs to decrypt a secret.

**Mitigations**:
- PBKDF2 makes each attempt expensive (~100ms)
- No server-side PIN verification (attacker must download ciphertext)
- Burn-after-reading limits attempts
- Time-based expiration reduces attack window

**Risk Level**: 🟡 Medium (depends on PIN strength)

**Recommendations**:
- Use long PINs (10+ characters)
- Use passphrases instead of numeric PINs
- Implement client-side rate limiting

### 2. Database Compromise

**Threat**: Attacker gains access to SQLite database.

**Impact**: None (data is encrypted)

**What Attacker Gets**:
- Encrypted ciphertext (unusable without PIN)
- IVs and salts (public parameters)
- Metadata (view counts, expiration times)

**What Attacker Cannot Get**:
- Plaintext secrets
- Encryption PINs
- Derived keys

**Risk Level**: 🟢 Low (zero-knowledge design)

### 3. Man-in-the-Middle (MITM)

**Threat**: Attacker intercepts traffic between client and server.

**Without HTTPS**:
- Attacker sees encrypted ciphertext (still secure)
- Attacker could modify or block requests
- Attacker could serve malicious JavaScript

**With HTTPS**:
- Traffic encrypted at transport layer
- Certificate pinning possible for enhanced security

**Risk Level**: 🟡 Medium without HTTPS, 🟢 Low with HTTPS

**Mitigation**: **Always use HTTPS in production** (see deployment guide)

### 4. Malicious JavaScript Injection

**Threat**: Attacker serves modified `crypto.js` to steal PINs or plaintext.

**Attack Vectors**:
- Compromised server
- DNS hijacking
- CDN compromise (if using external CDN)

**Mitigations**:
- Subresource Integrity (SRI) for external scripts
- Content Security Policy (CSP)
- Self-hosted JavaScript (no external dependencies)

**Risk Level**: 🔴 High (requires server compromise)

**Current Implementation**: JavaScript is embedded in binary (cannot be modified without rebuilding)

### 5. Timing Attacks

**Threat**: Attacker infers information from operation timings.

**Relevant Operations**:
- PIN verification (constant-time comparison)
- PBKDF2 key derivation (consistent timing)
- AES decryption (hardware-accelerated, minimal variance)

**Risk Level**: 🟢 Low (WebCrypto API handles this)

### 6. Side-Channel Attacks

**Threat**: Information leakage via power consumption, EM emissions, etc.

**Scope**: Requires physical access to client device during decryption.

**Risk Level**: 🟢 Low (out of scope for web applications)

### 7. Phishing

**Threat**: Attacker tricks user into revealing PIN on fake site.

**Mitigations**:
- User education
- Domain verification
- HTTPS with valid certificates

**Risk Level**: 🟡 Medium (social engineering)

## Security Best Practices

### For Users

1. **Use Strong PINs**
   - Minimum 6 characters (longer is better)
   - Use passphrases: "correct-horse-battery-staple"
   - Avoid common patterns (123456, password, etc.)

2. **Share Securely**
   - Send link via one channel (email, Slack)
   - Send PIN via different channel (SMS, Signal)
   - Never send both in the same message

3. **Use Short TTLs**
   - Default: 1 hour (sufficient for most cases)
   - For highly sensitive data: 15 minutes
   - Avoid 7-day expiration unless necessary

4. **Enable Burn-After-Reading**
   - Default: ON (recommended)
   - Ensures secret is deleted after first view
   - Prevents replay attacks

5. **Verify Before Sharing**
   - Test decryption before sharing link
   - Ensure recipient has correct PIN
   - Confirm secret displays correctly

### For Operators

1. **Always Use HTTPS**
   ```bash
   # Use a reverse proxy like Caddy or Nginx
   # Never run IronShare directly exposed to internet
   ```

2. **Enable Security Headers**
   ```nginx
   add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
   add_header X-Frame-Options "DENY" always;
   add_header X-Content-Type-Options "nosniff" always;
   add_header Referrer-Policy "no-referrer" always;
   add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' cdn.tailwindcss.com unpkg.com; style-src 'self' 'unsafe-inline'" always;
   ```

3. **Implement Rate Limiting**
   ```nginx
   # Nginx example
   limit_req_zone $binary_remote_addr zone=api:10m rate=10r/m;
   
   location /api/ {
       limit_req zone=api burst=5;
   }
   ```

4. **Monitor Logs**
   ```bash
   # Watch for suspicious patterns
   tail -f /var/log/ironshare.log | grep -i "error\|failed"
   ```

5. **Regular Updates**
   ```bash
   # Keep Rust and dependencies updated
   rustup update
   cargo update
   cargo audit
   ```

6. **Database Security**
   ```bash
   # Restrict permissions
   chmod 600 ironshare.db
   
   # Regular backups (encrypted data, but prevents data loss)
   sqlite3 ironshare.db ".backup ironshare-backup.db"
   ```

7. **Firewall Configuration**
   ```bash
   # Only expose port 3000 to reverse proxy
   ufw allow from 127.0.0.1 to any port 3000
   ufw deny 3000
   ```

## Known Limitations

### 1. No Server-Side PIN Validation

**Limitation**: Server cannot enforce PIN complexity requirements.

**Reason**: PIN never sent to server (zero-knowledge design).

**Mitigation**: Client-side validation (can be bypassed).

### 2. No Rate Limiting on Decryption

**Limitation**: Attacker can attempt unlimited decryptions client-side if they download the ciphertext.

**Reason**: Decryption happens in browser, not on server.

**Mitigation**: Burn-after-reading limits attempts. Consider adding client-side delays.

### 3. No User Authentication

**Limitation**: Anyone with the link can attempt decryption.

**Design Choice**: Intentional (simpler, no account management).

**Mitigation**: Link obscurity (12-char NanoID = 2^71 possible IDs) + PIN.

### 4. No Audit Trail

**Limitation**: No record of who accessed secrets or when.

**Design Choice**: Intentional (privacy-focused).

**Tradeoff**: Cannot detect unauthorized access attempts.

### 5. Single-Server Architecture

**Limitation**: No redundancy or high availability.

**Scope**: Current version designed for simplicity.

**Future**: Could be extended with distributed database.

## Compliance Considerations

### GDPR (General Data Protection Regulation)

- ✅ Data minimization: Only encrypted data stored
- ✅ Purpose limitation: Secrets auto-deleted
- ✅ Storage limitation: Time-based expiration
- ✅ Security: Strong encryption
- ⚠️ Data portability: Not applicable (ephemeral data)
- ⚠️ Right to erasure: Automatic (burn-after-reading)

### HIPAA (Health Insurance Portability and Accountability Act)

- ⚠️ **Not HIPAA compliant out-of-the-box**
- Additional requirements:
  - Audit logs (not implemented)
  - User authentication (not implemented)
  - Access controls (not implemented)
  - Business Associate Agreement (BAA)

**Recommendation**: Do not use for PHI without significant modifications.

### PCI DSS (Payment Card Industry Data Security Standard)

- ⚠️ **Not suitable for credit card data**
- Reason: PCI requires specific key management practices
- Alternative: Use Stripe, Plaid, or PCI-compliant services

## Security Audit Checklist

- [ ] HTTPS enabled with valid certificate
- [ ] Security headers configured (CSP, HSTS, etc.)
- [ ] Rate limiting implemented
- [ ] Reverse proxy configured (not directly exposed)
- [ ] Database file permissions restricted (600)
- [ ] Server logs monitored
- [ ] Dependencies up to date (`cargo audit`)
- [ ] Regular database backups
- [ ] Firewall rules configured
- [ ] Incident response plan documented

## Reporting Security Issues

If you discover a security vulnerability, please:

1. **Do not** open a public GitHub issue
2. Email security details to: [security@yourdomain.com]
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We aim to respond within 120 hours.

## References

- [NIST SP 800-132](https://csrc.nist.gov/publications/detail/sp/800-132/final): PBKDF Recommendations
- [NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final): AES-GCM Specification
- [RFC 4648](https://tools.ietf.org/html/rfc4648): Base64 Encoding
- [WebCrypto API Specification](https://www.w3.org/TR/WebCryptoAPI/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
