# Development Guide

## Development Environment Setup

### Prerequisites

- Rust 1.70+ with Cargo
- SQLite 3
- Git
- A code editor (VS Code, RustRover, etc.)

### Clone and Build

```bash
git clone <repository-url>
cd ironshare
```

**Before building**, you must generate the sqlx offline query cache. The `sqlx::query!` macros verify SQL against the database schema at compile time. Without the cache, `cargo build` fails with:

```
error: set `DATABASE_URL` to use query macros online, or run `cargo sqlx prepare` to update the query cache
```

Generate it once after cloning:

```bash
# Install sqlx-cli if you don't have it
cargo install sqlx-cli --no-default-features --features sqlite

# Generate the offline query cache (requires the db file to exist)
DATABASE_URL="sqlite:./ironshare.db" cargo sqlx prepare
```

This writes `.sqlx/*.json` files that must be committed to version control so the build works without a live database. The `.gitignore` in this repo currently excludes them — if you clone a fresh copy and the `.sqlx/` directory is missing or empty, re-run the command above.

Once the cache exists, build normally:

```bash
# Build in development mode (uses SQLX_OFFLINE automatically via the .sqlx cache)
SQLX_OFFLINE=true cargo build

# Run development server
cargo run

# Run with auto-reload (requires cargo-watch)
cargo install cargo-watch
cargo watch -x run
```

### Project Structure

```
ironshare/
├── src/
│   ├── main.rs          # Application entry, DB setup, server start
│   ├── lib.rs           # Module exports for testing
│   ├── handlers.rs      # HTTP routes and handlers
│   ├── models.rs        # Data structures and serialization
│   ├── db.rs            # Database operations
│   ├── crypto.rs        # Server-side crypto utilities
│   └── config.rs        # Configuration management
├── static/
│   └── crypto.js        # Client-side crypto reference
├── migrations/
│   └── 20240101120000_create_secrets_table.sql
├── tests/
│   └── api_tests.rs     # Integration tests
├── Cargo.toml           # Dependencies and metadata
├── Dockerfile           # Container build
├── docker-compose.yml   # Local dev environment
└── docs/                # Documentation
```

## Code Organization

### Module Overview

#### `main.rs`
- Application entry point
- Database connection pool setup
- SQLx migration runner
- Axum server initialization

```rust
#[tokio::main]
async fn main() -> Result<()> {
    // 1. Initialize logging
    // 2. Connect to database
    // 3. Run migrations
    // 4. Create router with shared state
    // 5. Start HTTP server
}
```

#### `handlers.rs`
- HTTP route definitions
- Request/response handling
- Crypto reference serving (via rust-embed)

**Key Functions**:
- `router()`: Defines all routes
- `store_secret_handler()`: POST /api/secret
- `get_secret_handler()`: POST /api/secret/:id
- `health_check()`: GET /health
- `serve_static()`: Embedded asset serving

#### `db.rs`
- Database CRUD operations
- Transaction management
- SQLx query execution

**Key Functions**:
- `store_secret()`: Insert encrypted secret
- `fetch_and_increment_view()`: Atomic fetch + increment
- `delete_secret()`: Manual deletion
- `purge_expired()`: Cleanup expired secrets

#### `models.rs`
- Request/response structures
- Database row structures
- Serde serialization/deserialization

**Key Types**:
- `StoreRequest`: Client → Server
- `StoreResponse`: Server → Client
- `ViewResponse`: Encrypted secret data
- `SecretRow`: Database row representation

#### `crypto.rs`
- Server-side crypto utilities (minimal)
- Base64 encoding/decoding
- Random generation helpers

**Note**: Heavy crypto (AES, PBKDF2) is client-side.

#### `config.rs`
- Environment variable loading
- Configuration structure
- Default values

## Development Workflow

### 1. Make Code Changes

Edit Rust files in `src/` or crypto implementation in `static/crypto.js`.

### 2. Check Compilation

```bash
# Fast syntax check
cargo check

# Full compilation
cargo build

# With optimizations
cargo build --release
```

### 3. Run Tests

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test
cargo test test_store_and_retrieve_secret

# Run with logging
RUST_LOG=debug cargo test
```

### 4. Format Code

```bash
# Format all Rust code
cargo fmt

# Check formatting without changing files
cargo fmt -- --check
```

### 5. Lint Code

```bash
# Run Clippy (Rust linter)
cargo clippy

# With warnings as errors
cargo clippy -- -D warnings
```

### 6. Run Server

```bash
# Development mode (debug build)
cargo run

# Production mode (release build)
cargo run --release

# With custom configuration
DATABASE_URL="sqlite:./test.db" cargo run
```

## Testing

### Unit Tests

Located in the same file as the code being tested:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_example() {
        assert_eq!(2 + 2, 4);
    }
}
```

### Integration Tests

Located in `tests/api_tests.rs`:

```rust
#[tokio::test]
async fn test_store_and_retrieve_secret() {
    let app = test_app();
    
    // Store secret
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), 201);
    
    // Retrieve secret
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), 200);
}
```

### Running Tests with Coverage

```bash
# Install tarpaulin
cargo install cargo-tarpaulin

# Run tests with coverage
cargo tarpaulin --out Html
```

### Manual Testing

```bash
# Start server
cargo run

# In another terminal:
# Test health endpoint
curl http://localhost:3000/health

# Test storing a secret
curl -X POST http://localhost:3000/api/secret \
  -H "Content-Type: application/json" \
  -d '{
    "ciphertext": "test_cipher",
    "iv": "test_iv",
    "salt": "test_salt",
    "max_views": 1,
    "ttl_minutes": 60
  }'

# Test retrieving (use ID from above)
curl -X POST http://localhost:3000/api/secret/abc123xyz
```

## Database Development

### Migrations

SQLx uses migration files in `migrations/`:

```
migrations/
└── 20240101120000_create_secrets_table.sql
```

#### Creating a New Migration

```bash
# Install sqlx-cli
cargo install sqlx-cli --no-default-features --features sqlite

# Create migration
sqlx migrate add create_new_table

# Edit the generated file in migrations/
```

#### Running Migrations

```bash
# Apply all pending migrations
sqlx migrate run

# Revert last migration
sqlx migrate revert

# Check migration status
sqlx migrate info
```

Migrations run automatically on application startup via:

```rust
sqlx::migrate!("./migrations").run(&pool).await?;
```

### Database Schema

Current schema (see `migrations/20240101120000_create_secrets_table.sql`):

```sql
CREATE TABLE secrets (
    id TEXT PRIMARY KEY,
    ciphertext TEXT NOT NULL,
    iv TEXT NOT NULL,
    salt TEXT NOT NULL,
    max_views INTEGER NOT NULL DEFAULT 1,
    views INTEGER NOT NULL DEFAULT 0,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
```

### Querying the Database

#### Using SQLx Macros (Compile-Time Checked)

```rust
// Compile-time verified query
let row = sqlx::query!(
    "SELECT * FROM secrets WHERE id = ?",
    id
)
.fetch_one(&pool)
.await?;
```

#### Using Query Builder

```rust
// Runtime query
let row: SecretRow = sqlx::query_as(
    "SELECT * FROM secrets WHERE id = ?"
)
.bind(id)
.fetch_one(&pool)
.await?;
```

### Database Inspection

```bash
# Open SQLite CLI
sqlite3 ironshare.db

# List tables
.tables

# Describe schema
.schema secrets

# Query data
SELECT id, expires_at, views FROM secrets;

# Exit
.quit
```

## Crypto Implementation

### Modifying crypto.js

Edit `static/crypto.js` to modify the reference encryption implementation.

**Key functions to preserve**:
- `IronCrypto.encrypt(plaintext, passphrase)` — PBKDF2 + AES-256-GCM, enforces 8-char minimum
- `IronCrypto.decrypt(ciphertext, iv, salt, passphrase)` — decrypts and validates
- `IronCrypto.deriveKey(passphrase, salt)` — PBKDF2-SHA256, 600k iterations
- `IronCrypto.generatePassphrase(length)` — random alphanumeric, default 16 chars (~92 bits)

**After editing**: restart server to reload embedded assets (they're compiled into the binary via `rust-embed`).

### Testing Crypto Implementation

Test in a Node.js environment or browser console:

```javascript
import IronCrypto from './crypto.js';

// Test encryption
const encrypted = await IronCrypto.encrypt("test secret", "mypassphrase");
console.log(encrypted);
// { ciphertext: "...", iv: "...", salt: "..." }

// Test decryption with correct passphrase
const plaintext = await IronCrypto.decrypt(
  encrypted.ciphertext,
  encrypted.iv,
  encrypted.salt,
  "mypassphrase"
);
console.log(plaintext); // "test secret"

// Test decryption with wrong passphrase
const wrong = await IronCrypto.decrypt(
  encrypted.ciphertext,
  encrypted.iv,
  encrypted.salt,
  "wrongpass"
);
console.log(wrong); // null

// Test passphrase generation
const passphrase = IronCrypto.generatePassphrase();
console.log(passphrase); // e.g. "Kx4mN7pR2sVwYz8b" (16 chars)

// Test minimum enforcement
try {
  await IronCrypto.encrypt("test", "short");
} catch (e) {
  console.log(e.message); // "Passphrase must be at least 8 characters"
}
```

## Adding New Features

### Example: Adding Maximum Secret Size

**1. Update Model** (`src/models.rs`):

```rust
#[derive(Debug, Deserialize)]
pub struct StoreRequest {
    pub ciphertext: String,
    pub iv: String,
    pub salt: String,
    pub max_views: i64,
    pub ttl_minutes: i64,
}

// Add validation
impl StoreRequest {
    const MAX_CIPHERTEXT_SIZE: usize = 1_000_000; // 1MB
    
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.ciphertext.len() > Self::MAX_CIPHERTEXT_SIZE {
            return Err("Secret too large");
        }
        Ok(())
    }
}
```

**2. Update Handler** (`src/handlers.rs`):

```rust
async fn store_secret_handler(
    State(pool): State<Arc<Pool<sqlx::Sqlite>>>,
    Json(req): Json<StoreRequest>,
) -> impl IntoResponse {
    // Validate request
    if let Err(e) = req.validate() {
        return (
            StatusCode::BAD_REQUEST,
            Json(StatusResponse {
                status: "error",
                message: e.to_string(),
            })
        ).into_response();
    }
    
    // ... rest of handler
}
```

**3. Add Test** (`tests/api_tests.rs`):

```rust
#[tokio::test]
async fn test_secret_size_limit() {
    let app = test_app();
    
    let large_secret = "A".repeat(2_000_000);
    let payload = json!({
        "ciphertext": large_secret,
        "iv": "test_iv",
        "salt": "test_salt",
        "max_views": 1,
        "ttl_minutes": 60
    });
    
    let response = app
        .oneshot(build_request("/api/secret", payload))
        .await
        .unwrap();
    
    assert_eq!(response.status(), 400); // Bad Request
}
```

## Debugging

### Enable Verbose Logging

```bash
# Set log level
RUST_LOG=debug cargo run

# More granular
RUST_LOG=ironshare=debug,sqlx=info cargo run

# Trace level (very verbose)
RUST_LOG=trace cargo run
```

### Debug Database Queries

SQLx logs queries when `RUST_LOG=sqlx=debug`:

```bash
RUST_LOG=sqlx=debug cargo run
```

### Inspect HTTP Requests

Use `tracing` in handlers:

```rust
use tracing::{debug, info, error};

async fn store_secret_handler(...) -> impl IntoResponse {
    debug!("Received store request: {:?}", req);
    // ... rest of handler
}
```

### Use Rust Debugger

**VS Code** with `rust-analyzer`:

1. Set breakpoint in code
2. Press F5 to start debugging
3. Inspect variables, step through code

**RustRover**:

1. Right-click on `main.rs`
2. Select "Debug 'main'"
3. Use debugger UI

## Performance Optimization

### Profiling

```bash
# Install flamegraph
cargo install flamegraph

# Profile application
cargo flamegraph
```

### Database Optimization

```rust
// Use connection pooling (already configured)
SqlitePoolOptions::new()
    .max_connections(5)
    .connect(&db_url)
    .await?;

// Use transactions for multiple operations
let mut tx = pool.begin().await?;
// ... multiple queries
tx.commit().await?;
```

### Reducing Binary Size

```toml
# Add to Cargo.toml
[profile.release]
opt-level = "z"     # Optimize for size
lto = true          # Link-time optimization
codegen-units = 1   # Better optimization
strip = true        # Strip symbols
```

```bash
cargo build --release
```

## Common Development Tasks

### Add a New Dependency

```bash
# Add to Cargo.toml
cargo add <crate-name>

# Example: Add uuid support
cargo add uuid --features v4

# Update dependencies
cargo update
```

### Check for Outdated Dependencies

```bash
cargo install cargo-outdated
cargo outdated
```

### Security Audit

```bash
cargo install cargo-audit
cargo audit
```

### Generate Documentation

```bash
# Generate and open docs
cargo doc --open

# Include private items
cargo doc --document-private-items
```

## Contribution Guidelines

### Code Style

- Follow Rust standard style (`cargo fmt`)
- Use meaningful variable names
- Add comments for complex logic
- Write documentation for public APIs

### Commit Messages

```
feat: Add support for custom expiration times
fix: Correct off-by-one error in view counting
docs: Update API reference for new endpoint
test: Add integration test for burn-after-reading
refactor: Simplify database transaction handling
```

### Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make changes and commit (`git commit -m 'feat: Add amazing feature'`)
4. Run tests (`cargo test`)
5. Run formatter (`cargo fmt`)
6. Run linter (`cargo clippy`)
7. Push to branch (`git push origin feature/amazing-feature`)
8. Open Pull Request

## Troubleshooting

### Compilation Errors

```bash
# Clean build artifacts
cargo clean

# Rebuild from scratch
SQLX_OFFLINE=true cargo build
```

**`error: set DATABASE_URL to use query macros`** — The `.sqlx/` offline cache is missing or stale. Run:

```bash
DATABASE_URL="sqlite:./ironshare.db" cargo sqlx prepare
```

Then rebuild with `SQLX_OFFLINE=true cargo build`.


### Database Locked Errors

```bash
# Check for other processes using the database
lsof ironshare.db

# Kill processes if needed
kill <PID>
```

### Port Already in Use

```bash
# Find process using port 3000
lsof -i :3000

# Kill process
kill <PID>

# Or use different port
IRONSHARE_PORT=8080 cargo run
```

## Resources

- [Rust Book](https://doc.rust-lang.org/book/)
- [Axum Documentation](https://docs.rs/axum/)
- [SQLx Documentation](https://docs.rs/sqlx/)
- [Tokio Documentation](https://docs.rs/tokio/)
- [Rust By Example](https://doc.rust-lang.org/rust-by-example/)
