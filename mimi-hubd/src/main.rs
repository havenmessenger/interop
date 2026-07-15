//! mimi-hubd daemon entrypoint. Env-driven by default, fail-closed on missing mTLS material: it
//! never falls back to plain HTTP. A hub is a public attack surface; no certificate means no serve.
//!
//! Config: env vars only (no `--config` passed) is the original, byte-identical interface. Passing
//! `--config <path>` loads a TOML file as the base for the same six settings; any of the env vars
//! below, if set to a non-empty value, still overrides its file value - a deployment can be mostly
//! file-config with one setting pinned by the environment, without two separate code paths.
//!
//!   MIMI_PROVIDER_DOMAIN   this hub's domain (required, no default - see README.md quickstart)
//!   MIMI_BIND_ADDR         listen address (default 0.0.0.0:8443)
//!   MIMI_DB_PATH           SQLite path (default /var/lib/mimi/provider.db)
//!   MIMI_SERVER_CERT       PEM path, this hub's TLS server certificate + chain
//!   MIMI_SERVER_KEY        PEM path, this hub's TLS server private key
//!   MIMI_CLIENT_CA         PEM path, the CA that signs client certificates for peers this hub trusts
//!                          (mTLS peer-trust allowlist; see README.md for how to generate one)
//!
//! Startup order is deliberate: mTLS material is read and validated into a `ServerConfig` BEFORE
//! any durable state is opened. A hub with bad or missing certificates should fail before it
//! touches disk, not after creating a database file it then never serves from.

mod config;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser;
use mimi_hubd::{http::build_router, tls, Provider};

#[derive(Parser)]
#[command(name = "mimi-hubd", version, about = "Reference MIMI hub daemon")]
struct Cli {
    /// Path to a TOML config file providing the base values for MIMI_PROVIDER_DOMAIN,
    /// MIMI_BIND_ADDR, MIMI_DB_PATH, MIMI_SERVER_CERT, MIMI_SERVER_KEY, MIMI_CLIENT_CA. Any of
    /// these env vars, if set to a non-empty value, overrides the same key from the file. Omit
    /// this flag for the original env-only behavior.
    #[arg(long)]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let file = cli
        .config
        .as_deref()
        .map(config::ConfigFile::load)
        .transpose()?;
    let resolved = config::resolve_all(file.as_ref());

    let domain = resolved["MIMI_PROVIDER_DOMAIN"].clone().ok_or_else(|| {
        anyhow::anyhow!(
            "MIMI_PROVIDER_DOMAIN is required (this hub's domain) - see README.md quickstart"
        )
    })?;
    let bind: std::net::SocketAddr = resolved["MIMI_BIND_ADDR"]
        .clone()
        .expect("MIMI_BIND_ADDR always resolves - it has a default")
        .parse()?;
    let db_path = resolved["MIMI_DB_PATH"]
        .clone()
        .expect("MIMI_DB_PATH always resolves - it has a default");

    // mTLS material first, before any durable state is opened (see the module doc above). Each
    // required path is also reported by WHICH layer supplied it (env/file/default/unset) - for
    // client_ca in particular this is a statement about the actual peer-trust boundary an
    // operator is running with, worth a startup log line on its own.
    let server_cert = required_mtls_bytes("MIMI_SERVER_CERT", "server_cert", file.as_ref())?;
    let server_key = required_mtls_bytes("MIMI_SERVER_KEY", "server_key", file.as_ref())?;
    let client_ca = required_mtls_bytes("MIMI_CLIENT_CA", "client_ca", file.as_ref())?;
    let tls_config = tls::build_mtls_server_config(&server_cert, &server_key, &client_ca)?;

    let provider = Provider::open(&domain, &db_path)?;
    let shared = Arc::new(Mutex::new(provider));
    let router = build_router(shared);

    eprintln!(
        "[mimi-hubd {}] domain={domain} db={db_path} listening (mTLS) on {bind}",
        env!("CARGO_PKG_VERSION")
    );
    tls::serve_with_graceful_shutdown(bind, router, tls_config, Duration::from_secs(30)).await?;
    Ok(())
}

/// A required mTLS material path, resolved from env-or-file, logged with WHICH layer supplied it,
/// then read as bytes. Hard error if unresolved or the file is missing: the fail-closed mTLS
/// guard, same behavior in both env-only and file-config modes.
fn required_mtls_bytes(
    env_key: &'static str,
    file_key: &str,
    file: Option<&config::ConfigFile>,
) -> anyhow::Result<Vec<u8>> {
    let (value, source) = config::resolve_with_source(env_key, file_key, file, None);
    let path = value.ok_or_else(|| {
        anyhow::anyhow!("{env_key} is required (mTLS material) - refusing to start")
    })?;
    eprintln!("[mimi-hubd] {env_key} supplied by: {}", source.label());
    std::fs::read(&path).map_err(|e| anyhow::anyhow!("cannot read {env_key}={path}: {e}"))
}
