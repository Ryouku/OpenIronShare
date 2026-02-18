use serde::{Deserialize, Serialize};

/// What the Client POSTs to store a secret
#[derive(Debug, Deserialize)]
pub struct StoreRequest {
    /// Base64 encoded ciphertext (AES output)
    pub ciphertext: String,
    /// Base64 encoded IV (12 bytes)
    pub iv: String,
    /// Base64-encoded PBKDF2 salt (16 bytes)
    pub salt: String,
    /// Maximum number of views allowed
    #[serde(default = "default_max_views")]
    pub max_views: i64,
    /// TTL in minutes from now
    #[serde(default = "default_ttl")]
    pub ttl_minutes: i64,
}

impl StoreRequest {
    /// Maximum ciphertext size in bytes (~50 KB — sufficient for passwords, keys, configs).
    pub const MAX_CIPHERTEXT_SIZE: usize = 50_000;
    /// Maximum base64-encoded IV length.
    pub const MAX_IV_SIZE: usize = 200;
    /// Maximum base64-encoded salt length.
    pub const MAX_SALT_SIZE: usize = 200;
    /// Maximum TTL in minutes (3 hours).
    pub const MAX_TTL_MINUTES: i64 = 180;
    /// Maximum allowed views per secret.
    pub const MAX_VIEWS: i64 = 5;
    /// Circuit-breaker limit on total active secrets (~5 GB at maximum ciphertext size).
    pub const MAX_TOTAL_SECRETS: i64 = 100_000;

    /// Validates all fields before the secret is stored.
    ///
    /// Returns `Err` with a human-readable message on the first failing check.
    pub fn validate(&self) -> Result<(), &'static str> {
        // Validate ciphertext size
        if self.ciphertext.is_empty() {
            return Err("Ciphertext cannot be empty");
        }
        if self.ciphertext.len() > Self::MAX_CIPHERTEXT_SIZE {
            return Err("Secret too large (max 50KB)");
        }

        // Validate IV
        if self.iv.is_empty() || self.iv.len() > Self::MAX_IV_SIZE {
            return Err("Invalid IV");
        }

        // Validate salt
        if self.salt.is_empty() || self.salt.len() > Self::MAX_SALT_SIZE {
            return Err("Invalid salt");
        }

        // Validate TTL
        if self.ttl_minutes < 1 {
            return Err("TTL must be at least 1 minute");
        }
        if self.ttl_minutes > Self::MAX_TTL_MINUTES {
            return Err("TTL cannot exceed 3 hours");
        }

        // Validate max_views
        if self.max_views < 0 {
            return Err("Max views cannot be negative");
        }
        if self.max_views > Self::MAX_VIEWS {
            return Err("Max views cannot exceed 5");
        }

        Ok(())
    }
}

/// Serde default: burn after one view.
fn default_max_views() -> i64 { 1 }
/// Serde default: expire after 60 minutes.
fn default_ttl() -> i64 { 60 }

/// JSON response returned to the client after a successful `POST /api/secret`.
#[derive(Debug, Serialize)]
pub struct StoreResponse {
    /// 12-character NanoID used to retrieve the secret.
    pub id: String,
    /// Unix timestamp at which the secret expires.
    pub expires_at: i64,
}

/// JSON response returned by `POST /api/secret/:id`.
///
/// Contains the encrypted blob that the client decrypts locally using the
/// passphrase (never sent to the server).
#[derive(Debug, Serialize)]
pub struct ViewResponse {
    /// Base64-encoded AES-GCM ciphertext.
    pub ciphertext: String,
    /// Base64-encoded 12-byte IV.
    pub iv: String,
    /// Base64-encoded 16-byte PBKDF2 salt.
    pub salt: String,
    /// Unix timestamp at which the secret expires.
    pub expires_at: i64,
    /// Views remaining; `-1` means unlimited.
    pub remaining_views: i64,
    /// Total times this secret has been viewed (including this request).
    pub total_views: i64,
}

/// Raw row returned by SQLx queries against the `secrets` table.
#[derive(Debug, sqlx::FromRow)]
pub struct SecretRow {
    #[allow(dead_code)]
    pub id: String,
    pub ciphertext: String,
    pub iv: String,
    pub salt: String,
    pub max_views: i64,
    /// Current view count (post-increment after retrieval).
    pub views: i64,
    pub expires_at: i64,
}

/// Lightweight row for `check_secret_exists` — avoids fetching the full ciphertext.
#[derive(Debug, sqlx::FromRow)]
pub struct SecretCheckData {
    pub max_views: i64,
    pub views: i64,
    pub expires_at: i64,
}

/// Simple Status Response
#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub status: &'static str,
    pub message: String,
}