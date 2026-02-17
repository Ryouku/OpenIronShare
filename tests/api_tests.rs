use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use ironshare::models::StoreRequest;
use serde_json::{json, Value};
use sqlx::sqlite::SqlitePoolOptions;
use std::sync::Arc;
use tower::ServiceExt;

async fn setup_app() -> axum::Router {
    let pool = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();

    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    ironshare::handlers::router(Arc::new(pool))
}

use std::net::SocketAddr;

fn post_json(uri: &str, body: Value) -> Request<Body> {
    let mut req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("Content-Type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));
    req
}

fn get(uri: &str) -> Request<Body> {
    let mut req = Request::builder()
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));
    req
}

fn post_empty(uri: &str) -> Request<Body> {
    let mut req = Request::builder()
        .method("POST")
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));
    req
}

async fn body_json(response: axum::http::Response<Body>) -> Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

fn valid_secret() -> Value {
    json!({
        "ciphertext": "dGVzdF9jaXBoZXJ0ZXh0X2RhdGFfaGVyZQ==",
        "iv": "dGVzdF9pdl8xMjM=",
        "salt": "dGVzdF9zYWx0XzQ1Ng==",
        "max_views": 1,
        "ttl_minutes": 60
    })
}

async fn store_secret(app: &axum::Router) -> String {
    let resp: axum::http::Response<Body> = app
        .clone()
        .oneshot(post_json("/api/secret", valid_secret()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let json = body_json(resp).await;
    json["id"].as_str().unwrap().to_string()
}

// ─── Health ───

#[tokio::test]
async fn health_returns_ok() {
    let app = setup_app().await;
    let resp: axum::http::Response<Body> = app.oneshot(get("/health")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["status"], "ok");
}

// ─── Store: Happy Path ───

#[tokio::test]
async fn store_secret_returns_201_with_id() {
    let app = setup_app().await;
    let resp: axum::http::Response<Body> = app
        .oneshot(post_json("/api/secret", valid_secret()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let json = body_json(resp).await;
    assert!(json["id"].is_string());
    assert_eq!(json["id"].as_str().unwrap().len(), 12);
    assert!(json["expires_at"].is_i64());
}

// ─── Store: Validation ───

#[tokio::test]
async fn store_rejects_empty_ciphertext() {
    let app = setup_app().await;
    let payload = json!({
        "ciphertext": "",
        "iv": "abc",
        "salt": "def",
        "max_views": 1,
        "ttl_minutes": 60
    });
    let resp: axum::http::Response<Body> = app.oneshot(post_json("/api/secret", payload)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn store_rejects_oversized_ciphertext() {
    let app = setup_app().await;
    let big = "A".repeat(StoreRequest::MAX_CIPHERTEXT_SIZE + 1);
    let payload = json!({
        "ciphertext": big,
        "iv": "abc",
        "salt": "def",
        "max_views": 1,
        "ttl_minutes": 60
    });
    let resp: axum::http::Response<Body> = app.oneshot(post_json("/api/secret", payload)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = body_json(resp).await;
    assert!(json["message"].as_str().unwrap().contains("50KB"));
}

#[tokio::test]
async fn store_rejects_zero_ttl() {
    let app = setup_app().await;
    let payload = json!({
        "ciphertext": "abc",
        "iv": "abc",
        "salt": "def",
        "max_views": 1,
        "ttl_minutes": 0
    });
    let resp: axum::http::Response<Body> = app.oneshot(post_json("/api/secret", payload)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn store_rejects_excessive_ttl() {
    let app = setup_app().await;
    let payload = json!({
        "ciphertext": "abc",
        "iv": "abc",
        "salt": "def",
        "max_views": 1,
        "ttl_minutes": 99999
    });
    let resp: axum::http::Response<Body> = app.oneshot(post_json("/api/secret", payload)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn store_rejects_negative_max_views() {
    let app = setup_app().await;
    let payload = json!({
        "ciphertext": "abc",
        "iv": "abc",
        "salt": "def",
        "max_views": -1,
        "ttl_minutes": 60
    });
    let resp: axum::http::Response<Body> = app.oneshot(post_json("/api/secret", payload)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn store_rejects_excessive_max_views() {
    let app = setup_app().await;
    let payload = json!({
        "ciphertext": "abc",
        "iv": "abc",
        "salt": "def",
        "max_views": 101,
        "ttl_minutes": 60
    });
    let resp: axum::http::Response<Body> = app.oneshot(post_json("/api/secret", payload)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn store_rejects_empty_iv() {
    let app = setup_app().await;
    let payload = json!({
        "ciphertext": "abc",
        "iv": "",
        "salt": "def",
        "max_views": 1,
        "ttl_minutes": 60
    });
    let resp: axum::http::Response<Body> = app.oneshot(post_json("/api/secret", payload)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn store_rejects_empty_salt() {
    let app = setup_app().await;
    let payload = json!({
        "ciphertext": "abc",
        "iv": "abc",
        "salt": "",
        "max_views": 1,
        "ttl_minutes": 60
    });
    let resp: axum::http::Response<Body> = app.oneshot(post_json("/api/secret", payload)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ─── Retrieve: Happy Path ───

#[tokio::test]
async fn retrieve_returns_secret_data() {
    let app = setup_app().await;
    let id = store_secret(&app).await;

    let resp: axum::http::Response<Body> = app
        .clone()
        .oneshot(post_empty(&format!("/api/secret/{}", id)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["ciphertext"], "dGVzdF9jaXBoZXJ0ZXh0X2RhdGFfaGVyZQ==");
    assert_eq!(json["iv"], "dGVzdF9pdl8xMjM=");
    assert_eq!(json["salt"], "dGVzdF9zYWx0XzQ1Ng==");
    assert!(json["remaining_views"].is_i64());
    assert!(json["total_views"].is_i64());
}

// ─── Burn After Reading ───

#[tokio::test]
async fn burn_after_read_deletes_on_second_access() {
    let app = setup_app().await;
    let id = store_secret(&app).await;

    let resp: axum::http::Response<Body> = app
        .clone()
        .oneshot(post_empty(&format!("/api/secret/{}", id)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp: axum::http::Response<Body> = app
        .oneshot(post_empty(&format!("/api/secret/{}", id)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::GONE);
}

// ─── Multi-View ───

#[tokio::test]
async fn multi_view_secret_allows_n_reads() {
    let app = setup_app().await;
    let payload = json!({
        "ciphertext": "test",
        "iv": "test_iv",
        "salt": "test_salt",
        "max_views": 3,
        "ttl_minutes": 60
    });
    let resp: axum::http::Response<Body> = app
        .clone()
        .oneshot(post_json("/api/secret", payload))
        .await
        .unwrap();
    let json = body_json(resp).await;
    let id = json["id"].as_str().unwrap().to_string();

    for i in 1..=3i64 {
        let resp: axum::http::Response<Body> = app
            .clone()
            .oneshot(post_empty(&format!("/api/secret/{}", id)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "View {} should succeed", i);
        let json = body_json(resp).await;
        assert_eq!(json["total_views"], i);
        assert_eq!(json["remaining_views"], 3 - i);
    }

    let resp: axum::http::Response<Body> = app
        .oneshot(post_empty(&format!("/api/secret/{}", id)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::GONE);
}

// ─── Nonexistent / Missing ───

#[tokio::test]
async fn retrieve_nonexistent_returns_gone() {
    let app = setup_app().await;
    let resp: axum::http::Response<Body> = app
        .oneshot(post_empty("/api/secret/doesnotexist1"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::GONE);
}

#[tokio::test]
async fn check_nonexistent_returns_gone() {
    let app = setup_app().await;
    let resp: axum::http::Response<Body> = app
        .oneshot(get("/api/secret/doesnotexist1/check"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::GONE);
}

// ─── Check Endpoint ───

#[tokio::test]
async fn check_returns_metadata_without_consuming_view() {
    let app = setup_app().await;
    let id = store_secret(&app).await;

    for _ in 0..2 {
        let resp: axum::http::Response<Body> = app
            .clone()
            .oneshot(get(&format!("/api/secret/{}/check", id)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["exists"], true);
        assert_eq!(json["remaining_views"], 1);
    }

    let resp: axum::http::Response<Body> = app
        .oneshot(post_empty(&format!("/api/secret/{}", id)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ─── Unlimited Views ───

#[tokio::test]
async fn unlimited_views_secret_survives_many_reads() {
    let app = setup_app().await;
    let payload = json!({
        "ciphertext": "test",
        "iv": "test_iv",
        "salt": "test_salt",
        "max_views": 0,
        "ttl_minutes": 60
    });
    let resp: axum::http::Response<Body> = app
        .clone()
        .oneshot(post_json("/api/secret", payload))
        .await
        .unwrap();
    let json = body_json(resp).await;
    let id = json["id"].as_str().unwrap().to_string();

    for _ in 0..10 {
        let resp: axum::http::Response<Body> = app
            .clone()
            .oneshot(post_empty(&format!("/api/secret/{}", id)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}

// ─── Default Values ───

#[tokio::test]
async fn store_uses_defaults_when_optional_fields_omitted() {
    let app = setup_app().await;
    let payload = json!({
        "ciphertext": "test",
        "iv": "test_iv",
        "salt": "test_salt"
    });
    let resp: axum::http::Response<Body> = app
        .clone()
        .oneshot(post_json("/api/secret", payload))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let json = body_json(resp).await;
    let id = json["id"].as_str().unwrap().to_string();

    // Default max_views=1 — burn after read
    let resp: axum::http::Response<Body> = app
        .clone()
        .oneshot(post_empty(&format!("/api/secret/{}", id)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp: axum::http::Response<Body> = app
        .oneshot(post_empty(&format!("/api/secret/{}", id)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::GONE);
}

// ─── API Root ───

#[tokio::test]
async fn api_root_returns_json_info() {
    let app = setup_app().await;
    let resp: axum::http::Response<Body> = app.oneshot(get("/")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["name"], "IronShare API");
    assert!(json["endpoints"].is_object());
}

// ─── Circuit Breaker ───

#[tokio::test]
async fn circuit_breaker_rejects_at_capacity() {
    let pool = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();

    for i in 0..5 {
        let id = format!("test_id_{:04}", i);
        let expires_at = (time::OffsetDateTime::now_utc() + time::Duration::hours(1)).unix_timestamp();
        let stored = ironshare::db::store_secret(
            &pool, &id, "ct", "iv", "salt", 1, expires_at, 5,
        )
        .await
        .unwrap();
        assert!(stored, "Secret {} should be stored", i);
    }

    // 6th should be rejected
    let expires_at = (time::OffsetDateTime::now_utc() + time::Duration::hours(1)).unix_timestamp();
    let stored = ironshare::db::store_secret(
        &pool, "overflow", "ct", "iv", "salt", 1, expires_at, 5,
    )
    .await
    .unwrap();
    assert!(!stored, "Should be rejected at capacity");
}

// ─── Circuit Breaker: Expired Don't Count ───

#[tokio::test]
async fn circuit_breaker_ignores_expired_secrets() {
    let pool = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();

    // Store 5 secrets that are already expired (insert directly, bypassing store_secret)
    let expired_at = time::OffsetDateTime::now_utc().unix_timestamp() - 100;
    for i in 0..5 {
        let id = format!("expired_{:04}", i);
        sqlx::query(
            "INSERT INTO secrets (id, ciphertext, iv, salt, max_views, views, expires_at, created_at) VALUES (?, 'ct', 'iv', 'salt', 1, 0, ?, strftime('%s', 'now'))"
        )
        .bind(&id)
        .bind(expired_at)
        .execute(&pool)
        .await
        .unwrap();
    }

    // Should still be able to store (expired ones don't count)
    let expires_at = (time::OffsetDateTime::now_utc() + time::Duration::hours(1)).unix_timestamp();
    let stored = ironshare::db::store_secret(
        &pool, "new_one", "ct", "iv", "salt", 1, expires_at, 5,
    )
    .await
    .unwrap();
    assert!(stored, "Expired secrets should not count toward limit");
}
