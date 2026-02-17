//! Database operations for IronShare.
//!
//! All functions operate on a shared SQLite connection pool.
//! Mutations use explicit transactions to ensure atomicity.

use crate::models::{SecretRow, SecretCheckData};
use sqlx::{Pool, Sqlite};
use tracing::info;

/// Checks whether a secret exists and is still valid, without consuming a view.
///
/// Returns `Ok(Some(data))` if the secret exists, is not expired, and has
/// remaining views (or is unlimited). Returns `Ok(None)` if not found,
/// expired, or fully consumed.
pub async fn check_secret_exists(
    pool: &Pool<Sqlite>,
    id: &str,
) -> Result<Option<SecretCheckData>, sqlx::Error> {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    
    let row: Option<SecretCheckData> = sqlx::query_as::<_, SecretCheckData>(
        "SELECT max_views, views, expires_at FROM secrets WHERE id = ? AND expires_at > ?"
    )
    .bind(id)
    .bind(now)
    .fetch_optional(pool)
    .await?;

    if let Some(ref r) = row {
        // Secret exists but view limit already reached — treat as gone
        if r.max_views > 0 && r.views >= r.max_views {
            return Ok(None);
        }
        Ok(row)
    } else {
        Ok(None)
    }
}

/// Stores an encrypted secret in the database inside a transaction.
///
/// Enforces a circuit-breaker limit (`max_total`) on the number of active
/// (non-expired) secrets. If the limit is reached the secret is not stored
/// and `Ok(false)` is returned so the handler can return `503`.
///
/// # Returns
/// - `Ok(true)` — secret stored successfully
/// - `Ok(false)` — service at capacity
/// - `Err(_)` — database error
pub async fn store_secret(
    pool: &Pool<Sqlite>,
    id: &str,
    ciphertext: &str,
    iv: &str,
    salt: &str,
    max_views: i64,
    expires_at: i64,
    max_total: i64,
) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();

    // Count active (non-expired) secrets inside the transaction to avoid TOCTOU races
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM secrets WHERE expires_at > ?")
        .bind(now)
        .fetch_one(&mut *tx)
        .await?;

    if count.0 >= max_total {
        tx.commit().await?;
        return Ok(false); // At capacity
    }

    sqlx::query!(
        "INSERT INTO secrets (id, ciphertext, iv, salt, max_views, views, expires_at, created_at) VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, strftime('%s', 'now'))",
        id,
        ciphertext,
        iv,
        salt,
        max_views,
        expires_at
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    info!("Stored secret ID: {}", id);
    Ok(true)
}

/// Atomically fetches a secret and increments its view counter.
///
/// The fetch and update are performed inside a single transaction to prevent
/// race conditions where two concurrent requests both see a remaining view
/// and both return data that should have been burned.
///
/// If the secret has reached its `max_views` limit it is deleted and
/// `Ok(None)` is returned. The returned [`SecretRow`] reflects the
/// post-increment view count.
///
/// # Returns
/// - `Ok(Some(row))` — secret found and view count incremented
/// - `Ok(None)` — not found, expired, or view limit reached (and deleted)
/// - `Err(_)` — database error
pub async fn fetch_and_increment_view(
    pool: &Pool<Sqlite>,
    id: &str,
) -> Result<Option<SecretRow>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    
    let row: Option<SecretRow> = sqlx::query_as::<_, SecretRow>(
        "SELECT id, ciphertext, iv, salt, max_views, views, expires_at FROM secrets WHERE id = ? AND expires_at > ?"
    )
    .bind(id)
    .bind(now)
    .fetch_optional(&mut *tx)
    .await?;

    if let Some(mut r) = row {
        if r.max_views > 0 && r.views >= r.max_views {
            // View limit reached — delete and return gone
            sqlx::query!("DELETE FROM secrets WHERE id = ?", id)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            return Ok(None);
        }

        sqlx::query!("UPDATE secrets SET views = views + 1 WHERE id = ?", id)
            .execute(&mut *tx)
            .await?;
        
        // Reflect the increment in the returned data so callers see accurate counts
        r.views += 1;
        
        tx.commit().await?;
        info!("Secret {} accessed. View count incremented.", id);
        Ok(Some(r))
    } else {
        tx.commit().await?;
        Ok(None)
    }
}

/// Deletes all secrets whose expiry timestamp is in the past.
///
/// Called by the background cleanup task in `main` every 15 minutes.
/// Returns the number of rows deleted.
pub async fn purge_expired(pool: &Pool<Sqlite>) -> Result<u64, sqlx::Error> {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    
    let result = sqlx::query!("DELETE FROM secrets WHERE expires_at < ?", now)
        .execute(pool)
        .await;
    
    match result {
        Ok(r) => {
            info!("Purged {} expired secrets", r.rows_affected());
            Ok(r.rows_affected())
        }
        Err(e) => Err(e)
    }
}
