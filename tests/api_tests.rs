use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use ironshare::models::StoreRequest;
use serde_json::{json, Value};
use sqlx::sqlite::SqlitePoolOptions;
use std::sync::Arc;
use tower::ServiceExt;
use sqlx::{Pool, Sqlite};

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

// ─── Expiration ───

#[tokio::test]
async fn expired_secret_returns_gone_on_retrieve() {
    let pool = setup_pool().await;
    let expired_at = time::OffsetDateTime::now_utc().unix_timestamp() - 1;
    sqlx::query(
        "INSERT INTO secrets (id, ciphertext, iv, salt, max_views, views, expires_at, created_at) VALUES ('exp_ret', 'ct', 'iv', 'salt', 1, 0, ?, strftime('%s', 'now'))"
    )
    .bind(expired_at)
    .execute(&pool)
    .await
    .unwrap();

    let app = ironshare::handlers::router(Arc::new(pool));
    let resp = app.oneshot(post_empty("/api/secret/exp_ret")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::GONE);
}

#[tokio::test]
async fn expired_secret_returns_gone_on_check() {
    let pool = setup_pool().await;
    let expired_at = time::OffsetDateTime::now_utc().unix_timestamp() - 1;
    sqlx::query(
        "INSERT INTO secrets (id, ciphertext, iv, salt, max_views, views, expires_at, created_at) VALUES ('exp_chk', 'ct', 'iv', 'salt', 1, 0, ?, strftime('%s', 'now'))"
    )
    .bind(expired_at)
    .execute(&pool)
    .await
    .unwrap();

    let app = ironshare::handlers::router(Arc::new(pool));
    let resp = app.oneshot(get("/api/secret/exp_chk/check")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::GONE);
}

// ─── Purge Expired (db layer) ───

#[tokio::test]
async fn purge_deletes_expired_and_keeps_active() {
    let pool = setup_pool().await;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();

    sqlx::query(
        "INSERT INTO secrets (id, ciphertext, iv, salt, max_views, views, expires_at, created_at) VALUES ('keep', 'ct', 'iv', 'salt', 1, 0, ?, ?)"
    )
    .bind(now + 3600)
    .bind(now)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO secrets (id, ciphertext, iv, salt, max_views, views, expires_at, created_at) VALUES ('purge1', 'ct', 'iv', 'salt', 1, 0, ?, ?)"
    )
    .bind(now - 100)
    .bind(now - 200)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO secrets (id, ciphertext, iv, salt, max_views, views, expires_at, created_at) VALUES ('purge2', 'ct', 'iv', 'salt', 1, 0, ?, ?)"
    )
    .bind(now - 50)
    .bind(now - 200)
    .execute(&pool)
    .await
    .unwrap();

    let deleted = ironshare::db::purge_expired(&pool).await.unwrap();
    assert_eq!(deleted, 2);

    let remaining: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM secrets")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(remaining.0, 1);

    let row = ironshare::db::check_secret_exists(&pool, "keep").await.unwrap();
    assert!(row.is_some());
}

// ─── Security Headers ───

#[tokio::test]
async fn responses_include_security_headers() {
    let app = setup_app().await;
    let resp = app.oneshot(get("/health")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let headers = resp.headers();
    assert_eq!(
        headers.get("x-frame-options").unwrap(),
        "DENY"
    );
    assert_eq!(
        headers.get("x-content-type-options").unwrap(),
        "nosniff"
    );
    assert_eq!(
        headers.get("referrer-policy").unwrap(),
        "no-referrer"
    );
    assert!(
        headers.get("content-security-policy").is_some(),
        "CSP header must be present"
    );
    let csp = headers.get("content-security-policy").unwrap().to_str().unwrap();
    assert!(csp.contains("default-src 'none'"));
    assert!(csp.contains("script-src 'self'"));
}

// ─── Static Asset: /crypto.js ───

#[tokio::test]
async fn crypto_js_returns_javascript() {
    let app = setup_app().await;
    let resp = app.oneshot(get("/crypto.js")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let ct = resp.headers().get("content-type").unwrap().to_str().unwrap();
    assert!(ct.contains("javascript"), "Expected JavaScript content-type, got: {}", ct);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(text.contains("IronCrypto"), "crypto.js must define IronCrypto");
    assert!(text.contains("600"), "crypto.js must reference 600k iterations");
}

// ─── Oversized ID Rejection ───

#[tokio::test]
async fn retrieve_rejects_oversized_id() {
    let app = setup_app().await;
    let long_id = "A".repeat(51);
    let resp = app
        .clone()
        .oneshot(post_empty(&format!("/api/secret/{}", long_id)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = body_json(resp).await;
    assert!(json["message"].as_str().unwrap().contains("Invalid"));
}

#[tokio::test]
async fn check_rejects_oversized_id() {
    let app = setup_app().await;
    let long_id = "A".repeat(51);
    let resp = app
        .oneshot(get(&format!("/api/secret/{}/check", long_id)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ─── Malformed Input ───

#[tokio::test]
async fn store_rejects_invalid_json() {
    let app = setup_app().await;
    let mut req = Request::builder()
        .method("POST")
        .uri("/api/secret")
        .header("Content-Type", "application/json")
        .body(Body::from("not valid json {{{"))
        .unwrap();
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));

    let resp = app.oneshot(req).await.unwrap();
    assert!(
        resp.status() == StatusCode::BAD_REQUEST || resp.status() == StatusCode::UNPROCESSABLE_ENTITY,
        "Expected 400 or 422 for malformed JSON, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn store_rejects_missing_required_fields() {
    let app = setup_app().await;
    let payload = json!({ "ciphertext": "abc" });
    let resp = app.oneshot(post_json("/api/secret", payload)).await.unwrap();
    assert!(
        resp.status() == StatusCode::BAD_REQUEST || resp.status() == StatusCode::UNPROCESSABLE_ENTITY,
        "Expected 400 or 422 for missing fields, got {}",
        resp.status()
    );
}

// ─── Concurrent View Counting ───

#[tokio::test]
async fn concurrent_reads_never_exceed_max_views() {
    let pool = setup_pool().await;
    let pool = Arc::new(pool);
    let expires_at = (time::OffsetDateTime::now_utc() + time::Duration::hours(1)).unix_timestamp();

    ironshare::db::store_secret(
        &pool, "race_test", "ct", "iv", "salt", 3, expires_at, 1000,
    )
    .await
    .unwrap();

    let mut handles = Vec::new();
    for _ in 0..20 {
        let p = pool.clone();
        handles.push(tokio::spawn(async move {
            ironshare::db::fetch_and_increment_view(&p, "race_test").await
        }));
    }

    let results: Vec<_> = futures::future::join_all(handles).await;
    let successes = results
        .iter()
        .filter(|r| matches!(r.as_ref().unwrap(), Ok(Some(_))))
        .count();

    assert_eq!(
        successes, 3,
        "Exactly max_views (3) requests should succeed, got {}",
        successes
    );
}

// ─── DB Layer: check_secret_exists ───

#[tokio::test]
async fn check_exists_returns_none_when_views_exhausted() {
    let pool = setup_pool().await;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();

    sqlx::query(
        "INSERT INTO secrets (id, ciphertext, iv, salt, max_views, views, expires_at, created_at) VALUES ('used_up', 'ct', 'iv', 'salt', 2, 2, ?, ?)"
    )
    .bind(now + 3600)
    .bind(now)
    .execute(&pool)
    .await
    .unwrap();

    let result = ironshare::db::check_secret_exists(&pool, "used_up").await.unwrap();
    assert!(result.is_none(), "Should return None when views exhausted");
}

#[tokio::test]
async fn check_exists_returns_data_for_unlimited_views() {
    let pool = setup_pool().await;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();

    sqlx::query(
        "INSERT INTO secrets (id, ciphertext, iv, salt, max_views, views, expires_at, created_at) VALUES ('unlim', 'ct', 'iv', 'salt', 0, 999, ?, ?)"
    )
    .bind(now + 3600)
    .bind(now)
    .execute(&pool)
    .await
    .unwrap();

    let result = ironshare::db::check_secret_exists(&pool, "unlim").await.unwrap();
    assert!(result.is_some(), "Unlimited secret should always be available");
}

// ─── Validation Error Messages ───

#[tokio::test]
async fn validation_errors_include_descriptive_messages() {
    let app = setup_app().await;

    let cases = vec![
        (json!({"ciphertext": "", "iv": "x", "salt": "x", "max_views": 1, "ttl_minutes": 60}), "empty"),
        (json!({"ciphertext": "x", "iv": "x", "salt": "x", "max_views": -1, "ttl_minutes": 60}), "negative"),
        (json!({"ciphertext": "x", "iv": "x", "salt": "x", "max_views": 1, "ttl_minutes": 0}), "TTL"),
    ];

    for (payload, label) in cases {
        let resp = app
            .clone()
            .oneshot(post_json("/api/secret", payload))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "Case: {}", label);
        let json = body_json(resp).await;
        assert!(
            json["message"].is_string() && !json["message"].as_str().unwrap().is_empty(),
            "Error for '{}' should have a non-empty message",
            label
        );
        assert_eq!(json["status"], "error");
    }
}

// ─── Helper: shared pool setup ───

async fn setup_pool() -> Pool<Sqlite> {
    let pool = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    pool
}
