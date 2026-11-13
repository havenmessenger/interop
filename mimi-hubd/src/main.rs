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
//!   MIMI_PUBLIC_BASE_URL   https URL the directory's endpoint URLs start at (default https://{domain})
//!                          (mTLS peer-trust allowlist; see README.md for how to generate one)
//!   MIMI_ACTIVITY_LOG      optional; 1 prints one line per peer request (method, route template, status); off otherwise
//!   MIMI_DIRECTORY_BIND_ADDR  optional; a second listener, plain HTTP, that serves the directory document only
//!
//! Startup order is deliberate: mTLS material is read and validated into a `ServerConfig` BEFORE
//! any durable state is opened. A hub with bad or missing certificates should fail before it
//! touches disk, not after creating a database file it then never serves from.
//!
//! `mimi-hubd enroll <HANDLE>` does not serve. It enrolls a handle for `identifierQuery` in the store the settings
//! above name (`MIMI_DB_PATH`, or `db_path` in the config file), says which database it wrote, and exits. It reads no
//! certificate and needs no provider domain. See `mimi_hubd::enroll`.

mod config;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::{Parser, Subcommand};
use mimi_hubd::{
    activity::{enabled as activity_enabled, with_activity_log},
    enroll::enroll_handle,
    http::{build_directory_router, build_router},
    tls, Provider,
};

#[derive(Parser)]
#[command(name = "mimi-hubd", version, about = "Reference MIMI hub daemon")]
struct Cli {
    /// Path to a TOML config file providing the base values for MIMI_PROVIDER_DOMAIN,
    /// MIMI_BIND_ADDR, MIMI_DB_PATH, MIMI_SERVER_CERT, MIMI_SERVER_KEY, MIMI_CLIENT_CA,
    /// MIMI_PUBLIC_BASE_URL. Any of
    /// these env vars, if set to a non-empty value, overrides the same key from the file. Omit
    /// this flag for the original env-only behavior.
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    /// With no subcommand, run the hub.
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Enroll a handle for identifierQuery in the hub's store, then exit. Run it on the hub's host with the hub's
    /// own settings, as the user the hub runs as; a running hub answers for the handle from its next request.
    Enroll {
        /// The handle, matched exactly by identifierQuery.
        handle: String,
    },
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

    if let Some(Command::Enroll { handle }) = &cli.command {
        let db_path = resolved["MIMI_DB_PATH"]
            .as_deref()
            .expect("MIMI_DB_PATH always resolves - it has a default");
        enroll_handle(db_path, handle)?;
        println!("enrolled {handle:?} for identifierQuery in {db_path}");
        return Ok(());
    }

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
    // Which CAs this hub trusts to name its peers, by fingerprint: any CA in this bundle can issue a certificate for any
    // provider name (DIVERGENCES.md, DIV-16), so the list is part of what an operator reads at startup.
    for fingerprint in tls::certificate_fingerprints(&client_ca)? {
        eprintln!("[mimi-hubd] client CA in the bundle: sha256={fingerprint}");
    }
    let tls_config = tls::build_mtls_server_config(&server_cert, &server_key, &client_ca)?;

    let mut provider = Provider::open(&domain, &db_path)?;
    if let Some(url) = &resolved["MIMI_PUBLIC_BASE_URL"] {
        provider = provider.with_public_base_url(url)?;
    }
    let shared = Arc::new(Mutex::new(provider));
    // The activity line is for the peer-facing listener only, and off unless MIMI_ACTIVITY_LOG is 1.
    let router = with_activity_log(
        build_router(shared.clone()),
        activity_enabled(resolved["MIMI_ACTIVITY_LOG"].as_deref()),
        Arc::new(|line| eprintln!("{line}")),
    );

    // The directory-only listener, when asked for. Plain HTTP, no client certificate: it answers one GET with the
    // directory document and nothing else, and is meant to sit behind whatever terminates TLS for the public name.
    if let Some(addr) = resolved["MIMI_DIRECTORY_BIND_ADDR"].as_deref() {
        let addr: std::net::SocketAddr = addr.parse()?;
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let directory = build_directory_router(shared);
        eprintln!("[mimi-hubd] directory only (no client certificate) listening on {addr}");
        tokio::spawn(async move {
            if let Err(error) = axum::serve(listener, directory).await {
                eprintln!("[mimi-hubd] directory listener stopped: {error}");
            }
        });
    }

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
