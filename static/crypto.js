/**
 * IronShare Client-Side Crypto
 *
 * All encryption happens client-side. The server NEVER sees
 * the passphrase or plaintext.
 *
 * - PBKDF2-SHA256 with 600,000 iterations (NIST SP 800-132)
 * - AES-256-GCM authenticated encryption
 * - Minimum 8-character passphrase enforced on encrypt
 */

const PBKDF2_ITERATIONS = 600_000;
const MIN_PASSPHRASE_LENGTH = 8;

const IronCrypto = {
    /**
     * Derive a 256-bit AES key from a passphrase using PBKDF2-SHA256.
     */
    async deriveKey(passphrase, salt) {
        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode(passphrase),
            'PBKDF2',
            false,
            ['deriveBits', 'deriveKey']
        );

        return await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: PBKDF2_ITERATIONS,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    },

    /**
     * Generate a random 16-byte salt for PBKDF2.
     */
    generateSalt() {
        return crypto.getRandomValues(new Uint8Array(16));
    },

    /**
     * Generate a random 12-byte IV for AES-GCM.
     */
    generateIV() {
        return crypto.getRandomValues(new Uint8Array(12));
    },

    /**
     * Encrypt plaintext with a passphrase.
     * Throws if passphrase is shorter than MIN_PASSPHRASE_LENGTH.
     * Returns { ciphertext, iv, salt } as URL-safe Base64 strings.
     */
    async encrypt(plaintext, passphrase) {
        if (!passphrase || passphrase.length < MIN_PASSPHRASE_LENGTH) {
            throw new Error(`Passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters`);
        }

        const salt = this.generateSalt();
        const iv = this.generateIV();
        const key = await this.deriveKey(passphrase, salt);
        const encoder = new TextEncoder();

        const ciphertext = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            encoder.encode(plaintext)
        );

        return {
            ciphertext: this.arrayBufferToBase64(ciphertext),
            iv: this.arrayBufferToBase64(iv),
            salt: this.arrayBufferToBase64(salt)
        };
    },

    /**
     * Decrypt ciphertext with a passphrase.
     * Returns plaintext string, or null if the passphrase is wrong
     * or the data has been tampered with.
     */
    async decrypt(ciphertextB64, ivB64, saltB64, passphrase) {
        try {
            const salt = this.base64ToArrayBuffer(saltB64);
            const iv = this.base64ToArrayBuffer(ivB64);
            const ciphertext = this.base64ToArrayBuffer(ciphertextB64);

            const key = await this.deriveKey(passphrase, salt);

            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: iv },
                key,
                ciphertext
            );

            return new TextDecoder().decode(decrypted);
        } catch (e) {
            return null; // Wrong passphrase or tampered data
        }
    },

    /**
     * ArrayBuffer → URL-safe Base64 (no padding).
     */
    arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');
    },

    /**
     * URL-safe Base64 → ArrayBuffer.
     */
    base64ToArrayBuffer(base64) {
        const normalized = base64
            .replace(/-/g, '+')
            .replace(/_/g, '/');

        const pad = normalized.length % 4;
        const padded = pad ? normalized + '='.repeat(4 - pad) : normalized;

        const binary = atob(padded);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    },

    /**
     * Generate a cryptographically random passphrase.
     * Default length 16 characters (~92 bits entropy).
     */
    generatePassphrase(length = 16) {
        const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
        const array = new Uint32Array(length);
        crypto.getRandomValues(array);
        let passphrase = '';
        for (let i = 0; i < length; i++) {
            passphrase += chars[array[i] % chars.length];
        }
        return passphrase;
    }
};

// Browser global
if (typeof window !== 'undefined') {
    window.IronCrypto = IronCrypto;
}

// CommonJS
if (typeof module !== 'undefined' && module.exports) {
    module.exports = IronCrypto;
}

// ESM default export
if (typeof globalThis !== 'undefined') {
    globalThis.IronCrypto = IronCrypto;
}
