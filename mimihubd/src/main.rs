//! mimihubd daemon entrypoint. Env-driven by default, fail-closed on missing mTLS material: it
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
//!   MIMI_LAST_RESORT_REUSE optional; `true` keeps a claimed last-resort KeyPackage to hand out again (DIVERGENCES
//!                          DIV-23); `false` or unset hands it out once, as protocol-07 §5.2 has key material. Any other
//!                          value stops the start
//!   MIMI_OTLP_ENDPOINT     optional; an OpenTelemetry collector's base URL (https, or http to loopback); traces and
//!                          metrics per peer go there over OTLP/HTTP. Needs a build with the `otlp` feature
//!   MIMI_DIRECTORY_BIND_ADDR  optional; a second listener, plain HTTP, that serves the directory document only
//!   MIMI_POLICY            optional; a TOML file of the deployment's choices (accepted ciphersuites, who
//!                          identifierQuery finds); without it the hub follows the drafts. A named
//!                          file that cannot be read or is not a valid policy stops the start
//!   MIMI_ADMIN_BIND_ADDR   optional; the operator's listener, plain HTTP on a loopback address only (127.0.0.0/8 or
//!                          ::1), serving roomPolicy, memberRole and addParticipant; any other address stops the start
//!   MIMI_LANE_BIND_ADDR    optional; the client lane's listener (see `client_lane`), TLS with its own certificate and
//!                          no client certificate; each request is signed by the provider's client-facing service for
//!                          one of its users. Needs all of:
//!   MIMI_LANE_CERT         PEM path, the lane's TLS certificate (the one the client-facing service pins)
//!   MIMI_LANE_KEY          PEM path, its private key
//!   MIMI_LANE_KEYS         JSON file of the service's keys ("<keyid>._mimi.client-lane": base64 Ed25519 public key)
//!   MIMI_LANE_ROOM_POLICY  optional; TOML file of what a room the lane creates starts with (see `client_lane_rooms`);
//!                          unset means the neutral profile. A file that is not a valid profile stops the start
//!   MIMI_LANE_DELIVERY     optional; `inbox` (default: per-user queues, read with inboxFetch/inboxAck) or `events`
//!                          (one provider event stream, pulled with events/wait, fetch and ack, or pushed); any other
//!                          value stops the start
//!   MIMI_EVENTS_PUSH_URL   optional, with MIMI_LANE_DELIVERY=events; an https URL on the provider's domain the hub
//!                          pushes the event stream to, signed with MIMI_SIGNING_KEY (required with it)
//!   MIMI_EVENTS_PUSH_ALLOW optional, with MIMI_EVENTS_PUSH_URL; comma-separated addr/len ranges the push
//!                          destination may be at although they are special (loopback, private, ...). It applies to
//!                          the push alone: MIMI_OUTBOUND_ALLOW, the peers' allowlist, does not apply to the push, and
//!                          this one never applies to a peer. The push connects directly, never through
//!                          MIMI_OUTBOUND_PROXY
//!   MIMI_PEER_KEYS         optional; JSON file of DNS-published peer keys ("<keyid>._mimi.<domain>": base64), kept
//!                          current by a job on the host; without it only a client certificate admits a peer
//!   MIMI_OUTBOUND_ALLOW    optional; comma-separated addr/len ranges an outbound request may reach although they are
//!                          special (loopback, private, ...); for test deployments. A value that does not parse stops
//!                          the start
//!   MIMI_OUTBOUND_PROXY    optional; an HTTP CONNECT proxy for outbound requests, http://host:port, or
//!                          http://user:secret@host:port for one that requires Proxy-Authorization (Basic)
//!   MIMI_PEER_TRUST        optional; `system` (default: the system roots plus MIMI_CLIENT_CA) or `bundle`
//!                          (MIMI_CLIENT_CA only), the roots a peer's server certificate may chain to
//!   MIMI_CLIENT_CERT       optional, with MIMI_CLIENT_KEY; PEM paths of the certificate and key outbound requests
//!   MIMI_CLIENT_KEY        present, when MIMI_SERVER_CERT cannot serve (it needs the clientAuth extended key usage)
//!   MIMI_HUB_MLS_KEY       optional; a file holding the hub's own MLS signing key (base64 32-byte Ed25519 seed),
//!                          which signs groupInfo answers; without it every groupInfo request is answered notAuthorized
//!   MIMI_PEERS             optional; a TOML file of "<peer domain>" = "https://<base>", for a peer whose directory
//!                          is not at https://<domain>; a base outside the peer's domain stops the start
//!
//! Startup order is deliberate: mTLS material is read and validated into a `ServerConfig` BEFORE
//! any durable state is opened. A hub with bad or missing certificates should fail before it
//! touches disk, not after creating a database file it then never serves from.
//!
//! `mimihubd enroll <HANDLE>` does not serve. It enrolls a handle for `identifierQuery` in the store the settings
//! above name (`MIMI_DB_PATH`, or `db_path` in the config file), says which database it wrote, and exits. It reads no
//! certificate and needs no provider domain. See `mimihubd::enroll`.

mod config;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::{Parser, Subcommand};
use mimihubd::{
    activity::{enabled as activity_enabled, with_activity_log},
    admin::{admin_bind_addr, build_admin_router},
    enroll::enroll_handle,
    http::{build_directory_router, build_router},
    policy::HubPolicy,
    tls, Provider,
};

#[derive(Parser)]
#[command(name = "mimihubd", version, about = "Reference MIMI hub daemon")]
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
        eprintln!("[mimihubd] client CA in the bundle: sha256={fingerprint}");
    }
    let tls_config = tls::build_mtls_server_config(&server_cert, &server_key, &client_ca)?;
    // The outbound client and the peer map, checked here like the listener's settings: a value that does not parse
    // stops the start.
    let outbound_settings =
        outbound_settings(&resolved, &domain, &server_cert, &server_key, &client_ca)?;
    let outbound = mimihubd::outbound::PeerClient::new(
        outbound_settings.clone(),
        Arc::new(mimihubd::outbound::SystemResolver),
    )?;
    eprintln!("[mimihubd] outbound: {}", outbound.describe());
    let peer_bases = match resolved["MIMI_PEERS"].as_deref() {
        Some(path) => mimihubd::peer_directory::PeerBases::load(std::path::Path::new(path))?,
        None => mimihubd::peer_directory::PeerBases::default(),
    };
    eprintln!(
        "[mimihubd] peers with their own base: {}; any other at https://<domain>",
        peer_bases.len()
    );
    // The client lane's settings, checked before any state is opened: a lane named without its certificate, key and key
    // file does not start.
    let lane = lane_settings(&resolved)?;
    let lane_rooms = match resolved["MIMI_LANE_ROOM_POLICY"].as_deref() {
        Some(path) => {
            mimihubd::client_lane_rooms::LaneRoomProfile::load(std::path::Path::new(path))?
        }
        None => mimihubd::client_lane_rooms::LaneRoomProfile::neutral(),
    };
    // The operator's address is checked before any state is opened, like the certificates: a hub asked to serve its
    // operator's routes beyond loopback does not start.
    let admin_addr = resolved["MIMI_ADMIN_BIND_ADDR"]
        .as_deref()
        .map(admin_bind_addr)
        .transpose()?;
    // The policy too: a named file the hub cannot read or that is not a valid policy stops the start here.
    let policy = match resolved["MIMI_POLICY"].as_deref() {
        Some(path) => HubPolicy::load(std::path::Path::new(path))?,
        None => HubPolicy::default(),
    };
    // The did_webvh credential's code points, read by every credential check from here on.
    mimihubd::configure_did_webvh(policy.did_webvh.code_points()?)?;
    eprintln!(
        "[mimihubd] policy ({}): {}",
        resolved["MIMI_POLICY"]
            .as_deref()
            .unwrap_or("the drafts' defaults"),
        policy.describe()
    );

    let require_nonce_on_key_material = policy.require_nonce_on_key_material;
    let last_resort_reuse =
        config::last_resort_reuse(resolved["MIMI_LAST_RESORT_REUSE"].as_deref())?;
    if last_resort_reuse {
        eprintln!("[mimihubd] a last-resort KeyPackage is handed out more than once (MIMI_LAST_RESORT_REUSE)");
    }
    let mut provider = Provider::open(&domain, &db_path)?
        .with_policy(policy)
        .with_last_resort_reuse(last_resort_reuse);
    if let Some(url) = &resolved["MIMI_PUBLIC_BASE_URL"] {
        provider = provider.with_public_base_url(url)?;
    }
    // The outbox worker delivers fan-out queued for other providers, in order per room and provider; the provider wakes
    // it after queueing.
    let wake = Arc::new(tokio::sync::Notify::new());
    // OTLP export: built with the `otlp` feature, and on only when MIMI_OTLP_ENDPOINT names a collector.
    let (telemetry, otlp_line) =
        mimihubd::telemetry::start(resolved["MIMI_OTLP_ENDPOINT"].as_deref())?;
    eprintln!("[mimihubd] {otlp_line}");
    let access = Arc::new(mimihubd::peer_directory::PeerAccess {
        client: Arc::new(outbound.with_telemetry(telemetry.clone())),
        directories: Arc::new(mimihubd::peer_directory::Directories::new(peer_bases)),
    });
    let mut provider = provider
        .with_outbox_waker(wake.clone())
        .with_peer_access(access.clone());
    // The hub's own MLS key, which signs a GroupInfoResponse as its hub_sender; without it groupInfo answers
    // notAuthorized.
    if let Some(path) = resolved["MIMI_HUB_MLS_KEY"].as_deref() {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("MIMI_HUB_MLS_KEY {path}: {e}"))?;
        let seed = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, text.trim())
            .map_err(|_| anyhow::anyhow!("MIMI_HUB_MLS_KEY {path} does not hold a base64 seed"))?;
        provider = provider.with_hub_signer(Arc::new(
            mimihubd::group_info_endpoint::hub_signer_from_seed(&seed, &domain)?,
        ));
        eprintln!("[mimihubd] groupInfo answers are signed with the hub's MLS key");
    } else {
        eprintln!("[mimihubd] no MIMI_HUB_MLS_KEY: groupInfo requests are answered notAuthorized");
    }
    let delivers_events = config::lane_delivers_events(resolved["MIMI_LANE_DELIVERY"].as_deref())?;
    let push_url = resolved["MIMI_EVENTS_PUSH_URL"].clone();
    if delivers_events {
        provider = provider.with_event_delivery();
        if push_url.is_none() && lane.is_none() {
            anyhow::bail!(
                "MIMI_LANE_DELIVERY=events needs a reader: the client lane (pull) or MIMI_EVENTS_PUSH_URL (push)"
            );
        }
    }
    if push_url.is_some() {
        if !delivers_events {
            anyhow::bail!("MIMI_EVENTS_PUSH_URL needs MIMI_LANE_DELIVERY=events");
        }
        if resolved["MIMI_SIGNING_KEY"].is_none() {
            anyhow::bail!(
                "MIMI_EVENTS_PUSH_URL needs MIMI_SIGNING_KEY: a pushed batch is signed by the hub"
            );
        }
        provider = provider.with_event_push()?;
    }
    let shared = Arc::new(Mutex::new(provider));
    if let Some(url) = push_url.as_deref() {
        // The push destination is the operator's own server: its own address allowlist, never the peers'.
        let allow = resolved["MIMI_EVENTS_PUSH_ALLOW"]
            .as_deref()
            .map(mimihubd::outbound::AddressPolicy::parse_allowlist)
            .transpose()
            .map_err(|why| anyhow::anyhow!("MIMI_EVENTS_PUSH_ALLOW: {why}"))?
            .unwrap_or_default();
        let push_client = mimihubd::outbound::PeerClient::new(
            outbound_settings.for_event_push(allow),
            Arc::new(mimihubd::outbound::SystemResolver),
        )?;
        eprintln!("[mimihubd] event push: {}", push_client.describe());
        let pusher =
            mimihubd::event_push::EventPusher::new(shared.clone(), Arc::new(push_client), url)?;
        pusher.spawn();
        eprintln!("[mimihubd] the provider event stream is pushed to {url}");
    } else if delivers_events {
        eprintln!("[mimihubd] the provider event stream is read by pull on the client lane");
    }
    let outbox = mimihubd::outbox::OutboxWorker::new(
        shared.clone(),
        access.client.clone(),
        access.directories.clone(),
        wake,
    );
    outbox.spawn();
    // The activity line is for the peer-facing listener only, and off unless MIMI_ACTIVITY_LOG is 1.
    // Every peer request is from an authenticated provider: a client certificate, or a DNS-key signature.
    let peer_keys = Arc::new(mimihubd::signature::PeerKeys::from_file(
        resolved["MIMI_PEER_KEYS"]
            .as_deref()
            .map(std::path::PathBuf::from),
    ));
    let router = mimihubd::telemetry::with_telemetry(
        with_activity_log(
            mimihubd::provider_auth::with_provider_auth_settings(
                build_router(shared.clone()),
                Arc::new(mimihubd::provider_auth::ProviderAuth {
                    keys: peer_keys,
                    nonces: mimihubd::signature::NonceLedger::default(),
                    require_nonce_on_key_material,
                }),
            ),
            activity_enabled(resolved["MIMI_ACTIVITY_LOG"].as_deref()),
            Arc::new(|line| eprintln!("{line}")),
        ),
        telemetry,
    );

    // The operator's listener, when asked for: loopback only, no client certificate, the three operator routes.
    if let Some(addr) = admin_addr {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let admin = build_admin_router(shared.clone());
        eprintln!(
            "[mimihubd] operator routes (loopback, no client certificate) listening on {addr}"
        );
        tokio::spawn(async move {
            if let Err(error) = axum::serve(listener, admin).await {
                eprintln!("[mimihubd] operator listener stopped: {error}");
            }
        });
    }

    // The directory-only listener, when asked for. Plain HTTP, no client certificate: it answers one GET with the
    // directory document and nothing else, and is meant to sit behind whatever terminates TLS for the public name.
    if let Some(addr) = resolved["MIMI_DIRECTORY_BIND_ADDR"].as_deref() {
        let addr: std::net::SocketAddr = addr.parse()?;
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let directory = build_directory_router(shared.clone());
        eprintln!("[mimihubd] directory only (no client certificate) listening on {addr}");
        tokio::spawn(async move {
            if let Err(error) = axum::serve(listener, directory).await {
                eprintln!("[mimihubd] directory listener stopped: {error}");
            }
        });
    }

    // The client lane, when configured: its own TLS listener, its own router, every request signed for one local user.
    if let Some((addr, lane_tls, lane_keys)) = lane {
        let started_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| {
                i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
            });
        let auth = std::sync::Arc::new(mimihubd::client_lane::ClientLaneAuth {
            keys: mimihubd::signature::PeerKeys::from_file(Some(lane_keys)),
            nonces: mimihubd::signature::NonceLedger::default(),
            started_unix,
            domain: domain.clone(),
        });
        eprintln!(
            "[mimihubd] client lane rooms ({}): {}",
            resolved["MIMI_LANE_ROOM_POLICY"]
                .as_deref()
                .unwrap_or("neutral profile"),
            lane_rooms.describe()
        );
        let lane_router =
            mimihubd::client_http::build_client_router(shared.clone(), auth, lane_rooms);
        let tls = axum_server::tls_rustls::RustlsConfig::from_config(lane_tls);
        eprintln!("[mimihubd] client lane (TLS, signed per request) listening on {addr}");
        tokio::spawn(async move {
            if let Err(error) = axum_server::bind_rustls(addr, tls)
                .serve(lane_router.into_make_service())
                .await
            {
                eprintln!("[mimihubd] client lane listener stopped: {error}");
            }
        });
    }

    eprintln!(
        "[mimihubd {} ({})] domain={domain} db={db_path} listening (mTLS) on {bind}",
        env!("CARGO_PKG_VERSION"),
        env!("MIMIHUBD_GIT_COMMIT")
    );
    tls::serve_with_graceful_shutdown(bind, router, tls_config, Duration::from_secs(30)).await?;
    Ok(())
}

/// The client lane's address, TLS config and key file, when `MIMI_LANE_BIND_ADDR` is set; all four settings or none.
fn lane_settings(
    resolved: &config::Resolved,
) -> anyhow::Result<
    Option<(
        std::net::SocketAddr,
        std::sync::Arc<rustls::ServerConfig>,
        std::path::PathBuf,
    )>,
> {
    let Some(addr) = resolved["MIMI_LANE_BIND_ADDR"].as_deref() else {
        return Ok(None);
    };
    let addr: std::net::SocketAddr = addr
        .parse()
        .map_err(|_| anyhow::anyhow!("MIMI_LANE_BIND_ADDR {addr} is not an address"))?;
    let path = |name: &str| {
        resolved[name]
            .clone()
            .ok_or_else(|| anyhow::anyhow!("MIMI_LANE_BIND_ADDR is set, so {name} is required"))
    };
    let (cert, key, keys) = (
        path("MIMI_LANE_CERT")?,
        path("MIMI_LANE_KEY")?,
        path("MIMI_LANE_KEYS")?,
    );
    let read = |file: &str| {
        std::fs::read(file).map_err(|error| anyhow::anyhow!("cannot read {file}: {error}"))
    };
    let tls = tls::build_server_config(&read(&cert)?, &read(&key)?)?;
    if !std::path::Path::new(&keys).is_file() {
        anyhow::bail!("MIMI_LANE_KEYS {keys} is not a file");
    }
    Ok(Some((addr, tls, std::path::PathBuf::from(keys))))
}

/// The outbound client from the resolved settings: `MIMI_CLIENT_CERT`/`KEY` as the client certificate, else the hub's
/// server certificate and key; the client CA bundle as extra trust anchors; and the address allowlist, proxy and trust
/// setting.
fn outbound_settings(
    resolved: &config::Resolved,
    domain: &str,
    server_cert: &[u8],
    server_key: &[u8],
    client_ca: &[u8],
) -> anyhow::Result<mimihubd::outbound::OutboundSettings> {
    use mimihubd::outbound::{AddressPolicy, OutboundSettings, PeerTrust, ProxyAddr};
    let allow = resolved["MIMI_OUTBOUND_ALLOW"]
        .as_deref()
        .map(AddressPolicy::parse_allowlist)
        .transpose()
        .map_err(|why| anyhow::anyhow!("MIMI_OUTBOUND_ALLOW: {why}"))?
        .unwrap_or_default();
    let proxy = resolved["MIMI_OUTBOUND_PROXY"]
        .as_deref()
        .map(ProxyAddr::parse)
        .transpose()
        .map_err(anyhow::Error::msg)?;
    let trust = resolved["MIMI_PEER_TRUST"]
        .as_deref()
        .map(PeerTrust::parse)
        .transpose()
        .map_err(anyhow::Error::msg)?
        .unwrap_or_default();
    // The provider's signing key, when set, signs every outbound request (draft-atwood-mimi-provider-auth §5).
    let signer = match (
        resolved["MIMI_SIGNING_KEY"].as_deref(),
        resolved["MIMI_SIGNING_SELECTOR"].as_deref(),
    ) {
        (Some(path), Some(selector)) => Some(Arc::new(
            mimihubd::request_signing::RequestSigner::from_file(
                std::path::Path::new(path),
                selector,
            )?,
        )),
        (None, None) => None,
        _ => anyhow::bail!(
            "MIMI_SIGNING_KEY and MIMI_SIGNING_SELECTOR are set together or not at all"
        ),
    };
    // A client certificate: MIMI_CLIENT_CERT/KEY when set; else the server's, but only for a hub that does not sign,
    // since a server certificate without the clientAuth extended key usage is refused by a strict peer.
    let client_certificate = match (
        resolved["MIMI_CLIENT_CERT"].as_deref(),
        resolved["MIMI_CLIENT_KEY"].as_deref(),
    ) {
        (Some(cert), Some(key)) => Some((
            std::fs::read(cert).map_err(|e| anyhow::anyhow!("MIMI_CLIENT_CERT {cert}: {e}"))?,
            std::fs::read(key).map_err(|e| anyhow::anyhow!("MIMI_CLIENT_KEY {key}: {e}"))?,
        )),
        (None, None) if signer.is_none() => Some((server_cert.to_vec(), server_key.to_vec())),
        (None, None) => None,
        _ => anyhow::bail!("MIMI_CLIENT_CERT and MIMI_CLIENT_KEY are set together or not at all"),
    };
    Ok(OutboundSettings {
        own_domain: domain.to_string(),
        client_certificate,
        signer,
        peer_bundle_pem: Some(client_ca.to_vec()),
        trust,
        addresses: AddressPolicy::with_allowlist(allow),
        proxy,
    })
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
    eprintln!("[mimihubd] {env_key} supplied by: {}", source.label());
    std::fs::read(&path).map_err(|e| anyhow::anyhow!("cannot read {env_key}={path}: {e}"))
}
