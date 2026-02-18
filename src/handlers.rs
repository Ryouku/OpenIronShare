//! HTTP route handlers for IronShare.
//!
//! Routes are grouped by rate-limit tier:
//! - Static routes (`/`, `/health`, `/crypto.js`) — no rate limit
//! - Creation routes (`POST /api/secret`) — 10 req/sec, burst 20
//! - Retrieval routes (`GET|POST /api/secret/:id*`) — 5 req/sec, burst 10
//!
//! All API handlers return JSON. The server never receives or stores
//! plaintext secrets or encryption keys — only the encrypted blob.

use std::sync::Arc;

use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Path, State},
    http::{StatusCode, HeaderValue, header},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use nanoid::nanoid;
use sqlx::Pool;
use time::OffsetDateTime;
use tower::ServiceBuilder;
use tower_governor::{
    governor::GovernorConfigBuilder, 
    GovernorLayer,
};
use tracing::{error, info};

use crate::{db, models::*};

// Embedded static assets compiled into the binary via rust-embed
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "static/"]
struct StaticAssets;

/// Builds the application router with all routes and middleware layers.
///
/// Middleware applied globally (innermost → outermost):
/// - `DefaultBodyLimit` — rejects bodies over 128 KB before reaching handlers
/// - `TraceLayer` — structured request/response tracing
/// - Security headers — `X-Frame-Options`, `X-Content-Type-Options`,
///   `Referrer-Policy`, `Content-Security-Policy`
pub fn router(pool: Arc<Pool<sqlx::Sqlite>>) -> Router {
    // Rate limiting: 10 requests per second per IP for secret creation
    let api_rate_limit = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(10)
            .burst_size(20)
            .finish()
            .unwrap()
    );

    // Stricter rate limit for retrieval to slow brute-force passphrase attempts
    let retrieval_rate_limit = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(5)
            .burst_size(10)
            .finish()
            .unwrap()
    );

    let static_routes = Router::new()
        .route("/", get(api_root))
        .route("/crypto.js", get(crypto_js_page))
        .route("/health", get(health_check));

    let creation_routes = Router::new()
        .route("/api/secret", post(store_secret_handler))
        .layer(GovernorLayer {
            config: api_rate_limit,
        });

    let retrieval_routes = Router::new()
        .route("/api/secret/:id/check", get(check_secret_handler))
        .route("/api/secret/:id", post(get_secret_handler))
        .layer(GovernorLayer {
            config: retrieval_rate_limit,
        });

    Router::new()
        .merge(static_routes)
        .merge(creation_routes)
        .merge(retrieval_routes)
        .with_state(pool)
        .layer(
            ServiceBuilder::new()
                .layer(DefaultBodyLimit::max(128 * 1024))
                .layer(tower_http::trace::TraceLayer::new_for_http())
                .layer(tower_http::set_header::SetResponseHeaderLayer::if_not_present(
                    header::X_FRAME_OPTIONS,
                    HeaderValue::from_static("DENY"),
                ))
                .layer(tower_http::set_header::SetResponseHeaderLayer::if_not_present(
                    header::X_CONTENT_TYPE_OPTIONS,
                    HeaderValue::from_static("nosniff"),
                ))
                .layer(tower_http::set_header::SetResponseHeaderLayer::if_not_present(
                    header::REFERRER_POLICY,
                    HeaderValue::from_static("no-referrer"),
                ))
                .layer(tower_http::set_header::SetResponseHeaderLayer::if_not_present(
                    header::CONTENT_SECURITY_POLICY,
                    HeaderValue::from_static(
                        "default-src 'none'; script-src 'self'; connect-src 'self'"
                    ),
                ))
        )
}

// --- Static handlers ---

/// `GET /` — returns API metadata as JSON.
async fn api_root() -> impl IntoResponse {
    Json(serde_json::json!({
        "name": "IronShare API",
        "version": env!("CARGO_PKG_VERSION"),
        "description": "Zero-knowledge secret sharing API",
        "endpoints": {
            "health": "GET /health",
            "crypto_reference": "GET /crypto.js",
            "create_secret": "POST /api/secret",
            "check_secret": "GET /api/secret/:id/check",
            "retrieve_secret": "POST /api/secret/:id"
        },
        "documentation": "https://github.com/Ryouku/OpenIronShare"
    }))
}

/// `GET /crypto.js` — serves the reference client-side crypto implementation.
async fn crypto_js_page() -> impl IntoResponse {
    serve_static("crypto.js", "application/javascript")
}

/// Serves a file embedded in the binary via [`StaticAssets`].
///
/// Returns `404` if the file was not included at compile time.
fn serve_static(file_name: &str, content_type: &str) -> Response<Body> {
    match StaticAssets::get(file_name) {
        Some(content) => {
            let body = Body::from(content.data);
            Response::builder()
                .header("Content-Type", content_type)
                .body(body)
                .unwrap()
        }
        None => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("Not Found"))
            .unwrap(),
    }
}

// --- API handlers ---

/// `GET /health` — liveness probe.
async fn health_check() -> impl IntoResponse {
    Json(StatusResponse {
        status: "ok",
        message: "IronShare is secure".to_string(),
    })
}

/// `POST /api/secret` — stores an encrypted secret.
///
/// The request body must be a [`StoreRequest`] JSON object containing the
/// AES-GCM ciphertext, IV, and PBKDF2 salt produced by the client.
/// The server performs no decryption and has no access to the plaintext.
///
/// # Responses
/// - `201 Created` — secret stored, returns [`StoreResponse`] with `id` and `expires_at`
/// - `400 Bad Request` — validation failed
/// - `503 Service Unavailable` — circuit breaker at capacity
/// - `500 Internal Server Error` — database error
async fn store_secret_handler(
    State(pool): State<Arc<Pool<sqlx::Sqlite>>>,
    Json(req): Json<StoreRequest>,
) -> impl IntoResponse {
    if let Err(e) = req.validate() {
        return (
            StatusCode::BAD_REQUEST,
            Json(StatusResponse {
                status: "error",
                message: e.to_string(),
            }),
        ).into_response();
    }

    // 12-char NanoID: URL-safe, short enough to share, hard enough to guess
    let id = nanoid!(12);
    
    let expires_at = (OffsetDateTime::now_utc() + 
        time::Duration::minutes(req.ttl_minutes))
        .unix_timestamp();

    match db::store_secret(&pool, &id, &req.ciphertext, &req.iv, &req.salt, req.max_views, expires_at, StoreRequest::MAX_TOTAL_SECRETS).await {
        Ok(true) => {
            info!("Secret stored with ID: {}", id);
            (
                StatusCode::CREATED,
                Json(StoreResponse { id, expires_at }),
            ).into_response()
        }
        Ok(false) => {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(StatusResponse {
                    status: "error",
                    message: "Service at capacity. Try again later.".to_string(),
                }),
            ).into_response()
        }
        Err(e) => {
            error!("Failed to store secret: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(StatusResponse {
                    status: "error",
                    message: "Internal server error".to_string(),
                }),
            ).into_response()
        }
    }
}

/// `GET /api/secret/:id/check` — checks existence without consuming a view.
///
/// Safe to call before presenting a decrypt UI to the end-user: it returns
/// metadata (`exists`, `expires_at`, `remaining_views`) without incrementing
/// the view counter or returning any encrypted data.
///
/// # Responses
/// - `200 OK` — secret exists and has remaining views
/// - `400 Bad Request` — `id` exceeds maximum length
/// - `410 Gone` — secret not found, expired, or fully consumed
/// - `500 Internal Server Error` — database error
async fn check_secret_handler(
    State(pool): State<Arc<Pool<sqlx::Sqlite>>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if id.len() > 50 {
        return (
            StatusCode::BAD_REQUEST,
            Json(StatusResponse {
                status: "error",
                message: "Invalid secret ID".to_string(),
            }),
        ).into_response();
    }

    match db::check_secret_exists(&pool, &id).await {
        Ok(Some(exists_data)) => {
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "exists": true,
                    "expires_at": exists_data.expires_at,
                    "remaining_views": if exists_data.max_views > 0 {
                        exists_data.max_views - exists_data.views
                    } else {
                        -1 // unlimited
                    }
                })),
            ).into_response()
        }
        Ok(None) => {
            (
                StatusCode::GONE,
                Json(StatusResponse {
                    status: "gone",
                    message: "Secret has expired or been burned".to_string(),
                }),
            ).into_response()
        }
        Err(e) => {
            error!("Database error checking {}: {}", id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(StatusResponse {
                    status: "error",
                    message: "Internal server error".to_string(),
                }),
            ).into_response()
        }
    }
}

/// `POST /api/secret/:id` — retrieves the encrypted payload and increments the view counter.
///
/// The client is responsible for decrypting the returned ciphertext using the
/// passphrase and the returned `iv`/`salt`. Passphrase verification happens
/// client-side — the server has no way to validate it.
///
/// If this was the last allowed view the secret is deleted atomically inside
/// the database transaction before this response is sent.
///
/// # Responses
/// - `200 OK` — returns [`ViewResponse`] with ciphertext, iv, salt, and view metadata
/// - `400 Bad Request` — `id` exceeds maximum length
/// - `410 Gone` — secret not found, expired, or view limit reached
/// - `500 Internal Server Error` — database error
async fn get_secret_handler(
    State(pool): State<Arc<Pool<sqlx::Sqlite>>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if id.len() > 50 {
        return (
            StatusCode::BAD_REQUEST,
            Json(StatusResponse {
                status: "error",
                message: "Invalid secret ID".to_string(),
            }),
        ).into_response();
    }

    match db::fetch_and_increment_view(&pool, &id).await {
        Ok(Some(row)) => {
            let remaining = if row.max_views > 0 {
                row.max_views - row.views
            } else {
                -1 // unlimited
            };

            (
                StatusCode::OK,
                Json(ViewResponse {
                    ciphertext: row.ciphertext,
                    iv: row.iv,
                    salt: row.salt,
                    expires_at: row.expires_at,
                    remaining_views: remaining,
                    total_views: row.views,
                }),
            ).into_response()
        }
        Ok(None) => {
            (
                StatusCode::GONE,
                Json(StatusResponse {
                    status: "gone",
                    message: "Secret has expired or been burned".to_string(),
                }),
            ).into_response()
        }
        Err(e) => {
            error!("Database error fetching {}: {}", id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(StatusResponse {
                    status: "error",
                    message: "Internal server error".to_string(),
                }),
            ).into_response()
        }
    }
}
