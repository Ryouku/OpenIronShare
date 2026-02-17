/**
 * IronShare Client-Side Crypto
 * 
 * This module handles ALL encryption in the browser.
 * The server NEVER sees the PIN or plaintext.
 */

const IronCrypto = {
    /**
     * Derive a 256-bit key from a PIN using PBKDF2
     */
    async deriveKeyFromPin(pin, salt) {
        const encoder = new TextEncoder();
        const pinData = encoder.encode(pin);
        
        // Import as raw key material
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            pinData,
            'PBKDF2',
            false,
            ['deriveBits', 'deriveKey']
        );
        
        // Derive AES-GCM key
        return await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 100000,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false, // Not extractable
            ['encrypt', 'decrypt']
        );
    },

    /**
     * Generate a random salt for PBKDF2
     */
    generateSalt() {
        return crypto.getRandomValues(new Uint8Array(16));
    },

    /**
     * Generate a random IV for AES-GCM
     */
    generateIV() {
        return crypto.getRandomValues(new Uint8Array(12));
    },

    /**
     * Encrypt plaintext with PIN
     * Returns: { ciphertext, iv, salt } as base64 strings
     */
    async encrypt(plaintext, pin) {
        const salt = this.generateSalt();
        const iv = this.generateIV();
        
        const key = await this.deriveKeyFromPin(pin, salt);
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
     * Decrypt ciphertext with PIN
     * Returns: plaintext string or null if failed
     */
    async decrypt(ciphertextB64, ivB64, saltB64, pin) {
        try {
            const salt = this.base64ToArrayBuffer(saltB64);
            const iv = this.base64ToArrayBuffer(ivB64);
            const ciphertext = this.base64ToArrayBuffer(ciphertextB64);
            
            const key = await this.deriveKeyFromPin(pin, salt);
            
            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: iv },
                key,
                ciphertext
            );
            
            return new TextDecoder().decode(decrypted);
        } catch (e) {
            console.error('Decryption failed:', e);
            return null; // Wrong PIN or tampered data
        }
    },

    /**
     * Helper: ArrayBuffer to Base64
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
     * Helper: Base64 to ArrayBuffer
     */
    base64ToArrayBuffer(base64) {
        // Restore standard base64 characters
        const normalized = base64
            .replace(/-/g, '+')
            .replace(/_/g, '/');
        
        // Add padding if needed
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
     * Generate a secure random PIN
     * Returns an 8-character alphanumeric PIN for better security
     */
    generatePin() {
        const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789'; // Removed ambiguous chars
        const array = new Uint32Array(8);
        crypto.getRandomValues(array);
        let pin = '';
        for (let i = 0; i < 8; i++) {
            pin += chars[array[i] % chars.length];
        }
        return pin;
    }
};

// Make available globally
window.IronCrypto = IronCrypto;