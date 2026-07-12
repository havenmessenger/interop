//! mimi-hub daemon entrypoint. Env-driven, fail-closed on missing mTLS material: it never falls
//! back to plain HTTP. A hub is a public attack surface; no certificate means no serve.
//!
//! Env:
//!   MIMI_PROVIDER_DOMAIN   this hub's domain (required, no default - see README.md quickstart)
//!   MIMI_BIND_ADDR         listen address (default 0.0.0.0:8443)
//!   MIMI_DB_PATH           SQLite path (default /var/lib/mimi/provider.db)
//!   MIMI_SERVER_CERT       PEM path, this hub's TLS server certificate + chain
//!   MIMI_SERVER_KEY        PEM path, this hub's TLS server private key
//!   MIMI_CLIENT_CA         PEM path, the CA that signs client certificates for peers this hub trusts
//!                          (mTLS peer-trust allowlist; see README.md for how to generate one)

use std::sync::{Arc, Mutex};

use mimi_hub::{http::build_router, tls, Provider};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let domain = read_required_str("MIMI_PROVIDER_DOMAIN")?;
    let bind: std::net::SocketAddr = env_or("MIMI_BIND_ADDR", "0.0.0.0:8443").parse()?;
    let db_path = env_or("MIMI_DB_PATH", "/var/lib/mimi/provider.db");

    let provider = Provider::open(&domain, &db_path)?;
    let shared = Arc::new(Mutex::new(provider));
    let router = build_router(shared);

    // Fail closed: mTLS is mandatory. A missing cert path is a hard error, not a plain-HTTP fallback.
    let server_cert = read_required_bytes("MIMI_SERVER_CERT")?;
    let server_key = read_required_bytes("MIMI_SERVER_KEY")?;
    let client_ca = read_required_bytes("MIMI_CLIENT_CA")?;
    let tls_config = tls::build_mtls_server_config(&server_cert, &server_key, &client_ca)?;

    eprintln!(
        "[mimi-hub {}] domain={domain} db={db_path} listening (mTLS) on {bind}",
        env!("CARGO_PKG_VERSION")
    );
    tls::serve(bind, router, tls_config).await?;
    Ok(())
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// A required string env var. Hard error if unset, with a message that says what to set and points
/// at the README rather than assuming a default that would only be correct for one deployment.
fn read_required_str(key: &str) -> anyhow::Result<String> {
    std::env::var(key).map_err(|_| {
        anyhow::anyhow!("{key} is required (this hub's domain) - see README.md quickstart")
    })
}

/// Read a file whose path comes from a required env var. Hard error if the var is unset or the file
/// is missing: the fail-closed mTLS guard.
fn read_required_bytes(key: &str) -> anyhow::Result<Vec<u8>> {
    let path = std::env::var(key)
        .map_err(|_| anyhow::anyhow!("{key} is required (mTLS material) - refusing to start"))?;
    std::fs::read(&path).map_err(|e| anyhow::anyhow!("cannot read {key}={path}: {e}"))
}
