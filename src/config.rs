//! Configuration module for IronShare
//!
//! Loads from environment variables:
//! - DATABASE_URL: SQLite connection string (default: "sqlite:./ironshare.db")
//! - IRONSHARE_PORT: Server port (default: 3000)
//! - IRONSHARE_HOST: Bind address (default: "0.0.0.0")

use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub host: String,
    pub port: u16,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "sqlite:./ironshare.db".to_string()),
            host: env::var("IRONSHARE_HOST")
                .unwrap_or_else(|_| "0.0.0.0".to_string()),
            port: env::var("IRONSHARE_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(3000),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::from_env()
    }
}