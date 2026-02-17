//! IronShare — Zero-knowledge secret sharing API.
//!
//! Entry point: initialises tracing, connects to SQLite, runs migrations,
//! spawns the background cleanup task, and starts the Axum HTTP server.

use std::net::SocketAddr;

use sqlx::sqlite::SqlitePoolOptions;
use std::sync::Arc;
use std::time::Duration;
use tracing_subscriber;

mod config;
mod db;
mod handlers;
mod models;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt::init();

    let config = config::Config::from_env();
    
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&config.database_url)
        .await?;

    // Run migrations
    sqlx::migrate!("./migrations").run(&pool).await?;

    let shared_state = Arc::new(pool.clone());

    // Spawn background task to purge expired secrets every 15 minutes
    let cleanup_pool = pool.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(900)); // 15 minutes
        loop {
            interval.tick().await;
            match db::purge_expired(&cleanup_pool).await {
                Ok(count) => {
                    if count > 0 {
                        tracing::info!("Cleaned up {} expired secrets", count);
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to purge expired secrets: {}", e);
                }
            }
        }
    });

    let app = handlers::router(shared_state);

    let bind_addr = format!("{}:{}", config.host, config.port);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    tracing::info!("IronShare listening on http://{}", bind_addr);
    
    // Graceful shutdown
    // into_make_service_with_connect_info provides peer SocketAddr
    // Required by tower_governor for per-IP rate limiting
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received Ctrl+C, shutting down gracefully...");
        },
        _ = terminate => {
            tracing::info!("Received SIGTERM, shutting down gracefully...");
        },
    }
}