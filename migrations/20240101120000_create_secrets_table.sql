-- Migration: Create secrets table for IronShare
CREATE TABLE IF NOT EXISTS secrets (
    id TEXT PRIMARY KEY NOT NULL,
    ciphertext TEXT NOT NULL,        -- AES-GCM ciphertext (Base64)
    iv TEXT NOT NULL,                -- Initialization Vector (Base64)
    salt TEXT NOT NULL,              -- PBKDF2 Salt (Base64)
    max_views INTEGER NOT NULL DEFAULT 1, -- 1 = Burn after read
    views INTEGER NOT NULL DEFAULT 0,
    expires_at INTEGER NOT NULL,     -- Unix Timestamp (epoch seconds)
    created_at INTEGER NOT NULL      -- Unix Timestamp
);

-- Index for cleaning up expired secrets
CREATE INDEX IF NOT EXISTS idx_expiry ON secrets(expires_at);