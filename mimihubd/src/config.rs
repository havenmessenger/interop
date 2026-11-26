//! File-based configuration, layered under the env-var interface `main.rs` has always used.
//!
//! Precedence: an env var (`MIMI_*`) always wins over the same setting in a `--config` file, so a
//! deployment can be "mostly file, override one thing via env" without two separate code paths. If
//! no `--config` is passed, resolution never looks at a file and behaves exactly as before. An env
//! var set to the empty string is treated as unset (falls through to the file/default), not as an
//! explicit override to an empty value - matching how these settings (a domain name, an address,
//! three file paths, a URL) have no meaningful empty-string value in the first place, so
//! treating "set but empty" as "not set" avoids a confusing silent-empty-value failure mode.

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;

const KNOWN_KEYS: &[&str] = &[
    "provider_domain",
    "bind_addr",
    "db_path",
    "server_cert",
    "server_key",
    "client_ca",
    "directory_bind_addr",
    "admin_bind_addr",
    "lane_bind_addr",
    "lane_cert",
    "lane_key",
    "lane_keys",
    "lane_room_policy",
    "lane_delivery",
    "events_push_url",
    "policy",
    "public_base_url",
    "activity_log",
    "last_resort_reuse",
    "otlp_endpoint",
    "peer_keys",
    "outbound_allow",
    "outbound_proxy",
    "peer_trust",
    "client_cert",
    "client_key",
    "peers",
    "signing_key",
    "signing_selector",
    "hub_mls_key",
];

/// The settings this daemon takes from env vars, also loadable from a TOML file. Field names match the env var suffix in lowercase (`MIMI_PROVIDER_DOMAIN` ->
/// `provider_domain`).
#[derive(Debug, Default, Deserialize)]
pub struct ConfigFile {
    pub provider_domain: Option<String>,
    pub bind_addr: Option<String>,
    pub db_path: Option<String>,
    pub server_cert: Option<String>,
    pub server_key: Option<String>,
    pub client_ca: Option<String>,
    /// Where the directory-only listener binds. Unset means there is none.
    pub directory_bind_addr: Option<String>,
    /// Where the operator's listener binds, a loopback address only. Unset means there is none.
    pub admin_bind_addr: Option<String>,
    /// Where the client lane's listener binds (see `client_lane.rs`). Unset means there is none.
    pub lane_bind_addr: Option<String>,
    /// PEM paths of the client lane's own TLS certificate and key.
    pub lane_cert: Option<String>,
    pub lane_key: Option<String>,
    /// The client lane's key file: `"<keyid>._mimi.client-lane": "<base64 Ed25519 public key>"`.
    pub lane_keys: Option<String>,
    /// The lane room profile (see `client_lane_rooms.rs`). Unset means the neutral profile.
    pub lane_room_policy: Option<String>,
    /// How the hub delivers to this provider's users: `inbox` (per-user queues, the default) or `events` (the provider
    /// event stream; see `client_lane_events.rs`).
    pub lane_delivery: Option<String>,
    /// Where the hub pushes the provider event stream (an https URL on the provider's domain); unset means no push.
    pub events_push_url: Option<String>,
    /// The policy file (see `policy.rs`). Unset means the drafts' defaults.
    pub policy: Option<String>,
    pub public_base_url: Option<String>,
    /// `1` turns on the activity line (see `activity.rs`). Anything else, or no value, leaves it off.
    pub activity_log: Option<String>,
    /// `true` keeps a claimed last-resort KeyPackage to hand out again (DIVERGENCES DIV-23); `false` or no value hands it
    /// out once, as protocol-07 §5.2 has key material ("MUST NOT be provided in any other response"). Any other value
    /// stops the start.
    pub last_resort_reuse: Option<String>,
    /// The OpenTelemetry collector's base URL (see `telemetry.rs`). Unset means no export.
    pub otlp_endpoint: Option<String>,
    pub peer_keys: Option<String>,
    /// Address ranges taken out of the outbound refusal list, comma-separated `addr/len`. For test deployments.
    pub outbound_allow: Option<String>,
    /// An HTTP `CONNECT` proxy for outbound requests, `http://host:port`. Unset means direct.
    pub outbound_proxy: Option<String>,
    /// Which roots a peer's server certificate may chain to: `system` (the system roots plus the client CA bundle, the
    /// default) or `bundle` (the bundle only).
    pub peer_trust: Option<String>,
    /// The certificate and key presented on outbound requests, when they are not `server_cert` / `server_key`.
    pub client_cert: Option<String>,
    pub client_key: Option<String>,
    /// A TOML file mapping a peer's domain to the base its directory is under, when that is not `https://<domain>`.
    pub peers: Option<String>,
    /// The file holding the provider's request-signing key (a base64 32-byte Ed25519 seed), with its DNS selector.
    pub signing_key: Option<String>,
    pub signing_selector: Option<String>,
    /// The file holding the hub's own MLS signing key (a base64 32-byte Ed25519 seed), which signs GroupInfoResponses.
    pub hub_mls_key: Option<String>,
}

/// `MIMI_LANE_DELIVERY`: `events` delivers through the provider event stream, `inbox` or no value through per-user
/// queues. Any other value is an error, so a mistyped setting stops the start.
pub fn lane_delivers_events(value: Option<&str>) -> anyhow::Result<bool> {
    match value {
        None | Some("inbox") => Ok(false),
        Some("events") => Ok(true),
        Some(other) => anyhow::bail!("MIMI_LANE_DELIVERY must be inbox or events, not {other:?}"),
    }
}

/// `MIMI_LAST_RESORT_REUSE`: `true` keeps a claimed last-resort KeyPackage to hand out again, `false` or no value hands
/// it out once. Any other value is an error, so a mistyped setting stops the start instead of choosing for the operator.
pub fn last_resort_reuse(value: Option<&str>) -> anyhow::Result<bool> {
    match value {
        None | Some("false") => Ok(false),
        Some("true") => Ok(true),
        Some(other) => {
            anyhow::bail!("MIMI_LAST_RESORT_REUSE must be true or false, not {other:?}")
        }
    }
}

impl ConfigFile {
    /// Read and parse a TOML config file. Unknown top-level keys are ignored for parsing
    /// (forward-compatible - this file only ever carries a subset of settings anyone might have
    /// already scripted past) but logged as a warning: silently ignoring an unrecognized key is
    /// the right behavior for a genuinely-unknown future key, but the same silent-ignore also
    /// hides a typo (e.g. `bnid_addr`) behind a confusing "my setting isn't taking effect"
    /// symptom instead of an actionable diagnostic - so the warning exists without changing the
    /// permissive parsing behavior.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("cannot read config file {}: {e}", path.display()))?;
        if let Ok(table) = raw.parse::<toml::Table>() {
            for key in table.keys() {
                if !KNOWN_KEYS.contains(&key.as_str()) {
                    eprintln!(
                        "[mimihubd] warning: config file {} has unrecognized key '{key}' (ignored - check for a typo)",
                        path.display()
                    );
                }
            }
        }
        toml::from_str(&raw)
            .map_err(|e| anyhow::anyhow!("cannot parse config file {}: {e}", path.display()))
    }

    fn get(&self, key: &str) -> Option<&String> {
        match key {
            "provider_domain" => self.provider_domain.as_ref(),
            "bind_addr" => self.bind_addr.as_ref(),
            "db_path" => self.db_path.as_ref(),
            "server_cert" => self.server_cert.as_ref(),
            "server_key" => self.server_key.as_ref(),
            "client_ca" => self.client_ca.as_ref(),
            "directory_bind_addr" => self.directory_bind_addr.as_ref(),
            "admin_bind_addr" => self.admin_bind_addr.as_ref(),
            "lane_bind_addr" => self.lane_bind_addr.as_ref(),
            "lane_cert" => self.lane_cert.as_ref(),
            "lane_key" => self.lane_key.as_ref(),
            "lane_keys" => self.lane_keys.as_ref(),
            "lane_room_policy" => self.lane_room_policy.as_ref(),
            "lane_delivery" => self.lane_delivery.as_ref(),
            "events_push_url" => self.events_push_url.as_ref(),
            "policy" => self.policy.as_ref(),
            "public_base_url" => self.public_base_url.as_ref(),
            "activity_log" => self.activity_log.as_ref(),
            "last_resort_reuse" => self.last_resort_reuse.as_ref(),
            "otlp_endpoint" => self.otlp_endpoint.as_ref(),
            "peer_keys" => self.peer_keys.as_ref(),
            "outbound_allow" => self.outbound_allow.as_ref(),
            "outbound_proxy" => self.outbound_proxy.as_ref(),
            "peer_trust" => self.peer_trust.as_ref(),
            "client_cert" => self.client_cert.as_ref(),
            "client_key" => self.client_key.as_ref(),
            "peers" => self.peers.as_ref(),
            "signing_key" => self.signing_key.as_ref(),
            "signing_selector" => self.signing_selector.as_ref(),
            "hub_mls_key" => self.hub_mls_key.as_ref(),
            _ => None,
        }
    }
}

/// Which layer supplied a resolved setting's value - reported for the mTLS material specifically
/// (`main.rs` logs it at startup), since which layer supplied `client_ca` in particular is a
/// statement about the actual peer-trust boundary, not just an ergonomic detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Env,
    File,
    Default,
    Unset,
}

impl Source {
    pub fn label(self) -> &'static str {
        match self {
            Source::Env => "env",
            Source::File => "file",
            Source::Default => "default",
            Source::Unset => "unset",
        }
    }
}

/// Resolves one setting and reports which layer supplied it: `MIMI_{ENV_KEY}` env var (if set to
/// a non-empty value) wins, else the config file's value (if a file was loaded and sets it), else
/// `default` (if given), else unresolved. `file` is `None` when no `--config` was passed - in that
/// case this degenerates to exactly the pre-existing env-or-default lookup, so the no-`--config`
/// path is byte-identical to the daemon's original behavior.
pub fn resolve_with_source(
    env_key: &str,
    file_key: &str,
    file: Option<&ConfigFile>,
    default: Option<&str>,
) -> (Option<String>, Source) {
    // var_os + explicit UTF-8 conversion, not std::env::var: the latter's Err collapses "not
    // present" and "present but not valid Unicode" into the SAME Err(NotUnicode) case an `if let
    // Ok` silently treats as absent, falling through to file/default - a genuinely-set but
    // mis-encoded env var would silently lose to a lower-precedence layer instead of surfacing as
    // the operator error it is. Distinguish the two explicitly and hard-error on NotUnicode.
    match std::env::var_os(env_key) {
        Some(os_v) => match os_v.into_string() {
            Ok(v) if !v.is_empty() => return (Some(v), Source::Env),
            Ok(_) => {
                // Empty string: treated as unset, falls through to file/default below.
            }
            // A genuinely dynamic panic message (the bad env var's name + the raw bytes) can't be
            // a `.expect()` string literal like every other panic site in this crate - this is
            // the one deliberate exception to the crate's panic lint, not a relaxed convention.
            #[allow(clippy::panic)]
            Err(bad) => panic!(
                "{env_key} is set but is not valid UTF-8 ({bad:?}) - fix the environment, this is \
                 not silently treated as unset"
            ),
        },
        None => {
            // Not present at all: falls through to file/default below.
        }
    }
    // A TOML-sourced empty string gets the SAME "treated as unset" treatment as an empty env var
    // above - an unchecked empty file value would otherwise reach a caller like
    // `Connection::open("")`, which SQLite treats as a private, silently-deleted-on-close temp DB
    // rather than the persistent path the operator meant to configure.
    if let Some(v) = file.and_then(|f| f.get(file_key)) {
        if !v.trim().is_empty() {
            return (Some(v.clone()), Source::File);
        }
    }
    match default {
        Some(d) => (Some(d.to_string()), Source::Default),
        None => (None, Source::Unset),
    }
}

/// Value-only convenience wrapper around [`resolve_with_source`] for callers that don't need the
/// source label.
pub fn resolve(
    env_key: &str,
    file_key: &str,
    file: Option<&ConfigFile>,
    default: Option<&str>,
) -> Option<String> {
    resolve_with_source(env_key, file_key, file, default).0
}

/// Every resolved setting this daemon needs, keyed the same way `resolve` is called - kept as a
/// map rather than named fields so `main.rs`'s existing `read_required_*` call sites can ask for
/// exactly the key they already know, unchanged in shape.
pub type Resolved = HashMap<&'static str, Option<String>>;

pub fn resolve_all(file: Option<&ConfigFile>) -> Resolved {
    let mut m: Resolved = HashMap::new();
    m.insert(
        "MIMI_PROVIDER_DOMAIN",
        resolve("MIMI_PROVIDER_DOMAIN", "provider_domain", file, None),
    );
    m.insert(
        "MIMI_BIND_ADDR",
        resolve("MIMI_BIND_ADDR", "bind_addr", file, Some("0.0.0.0:8443")),
    );
    m.insert(
        "MIMI_DB_PATH",
        // Unchanged from the daemon's original env-only default - a packaged deployment's own
        // config template may recommend a different path (see debian/mimihubd.toml.example), but
        // that is the template's choice, not a change to this binary's own default.
        resolve(
            "MIMI_DB_PATH",
            "db_path",
            file,
            Some("/var/lib/mimi/provider.db"),
        ),
    );
    m.insert(
        "MIMI_SERVER_CERT",
        resolve("MIMI_SERVER_CERT", "server_cert", file, None),
    );
    m.insert(
        "MIMI_SERVER_KEY",
        resolve("MIMI_SERVER_KEY", "server_key", file, None),
    );
    m.insert(
        "MIMI_CLIENT_CA",
        resolve("MIMI_CLIENT_CA", "client_ca", file, None),
    );
    // No default: the directory-only listener exists only where an operator asks for it.
    m.insert(
        "MIMI_DIRECTORY_BIND_ADDR",
        resolve(
            "MIMI_DIRECTORY_BIND_ADDR",
            "directory_bind_addr",
            file,
            None,
        ),
    );
    // No default: the operator's listener exists only where an operator asks for it, and only on loopback.
    m.insert(
        "MIMI_ADMIN_BIND_ADDR",
        resolve("MIMI_ADMIN_BIND_ADDR", "admin_bind_addr", file, None),
    );
    // No defaults: the client lane exists only where a provider configures all four.
    for (env, key) in [
        ("MIMI_LANE_BIND_ADDR", "lane_bind_addr"),
        ("MIMI_LANE_CERT", "lane_cert"),
        ("MIMI_LANE_KEY", "lane_key"),
        ("MIMI_LANE_KEYS", "lane_keys"),
    ] {
        m.insert(env, resolve(env, key, file, None));
    }
    // No default: without a profile file a lane room starts with the neutral profile.
    m.insert(
        "MIMI_LANE_ROOM_POLICY",
        resolve("MIMI_LANE_ROOM_POLICY", "lane_room_policy", file, None),
    );
    // No default: per-user inboxes unless an operator chooses the event stream.
    m.insert(
        "MIMI_LANE_DELIVERY",
        resolve("MIMI_LANE_DELIVERY", "lane_delivery", file, None),
    );
    // No default: the event stream is pushed only where an operator names the provider server's URL.
    m.insert(
        "MIMI_EVENTS_PUSH_URL",
        resolve("MIMI_EVENTS_PUSH_URL", "events_push_url", file, None),
    );
    // No default: without a policy file the hub follows the drafts' defaults.
    m.insert("MIMI_POLICY", resolve("MIMI_POLICY", "policy", file, None));
    m.insert(
        "MIMI_PUBLIC_BASE_URL",
        resolve("MIMI_PUBLIC_BASE_URL", "public_base_url", file, None),
    );
    // No default: the activity line is off unless an operator sets this to `1`.
    m.insert(
        "MIMI_ACTIVITY_LOG",
        resolve("MIMI_ACTIVITY_LOG", "activity_log", file, None),
    );
    // No default: a last-resort KeyPackage is handed out once unless an operator sets this to `true`.
    m.insert(
        "MIMI_LAST_RESORT_REUSE",
        resolve("MIMI_LAST_RESORT_REUSE", "last_resort_reuse", file, None),
    );
    // No default: nothing is exported unless an operator names a collector.
    m.insert(
        "MIMI_OTLP_ENDPOINT",
        resolve("MIMI_OTLP_ENDPOINT", "otlp_endpoint", file, None),
    );
    // No default: without a key file no signature verifies, and only a client certificate admits a peer.
    m.insert(
        "MIMI_PEER_KEYS",
        resolve("MIMI_PEER_KEYS", "peer_keys", file, None),
    );
    // No defaults: outbound requests refuse every special range, go direct, and trust the system roots plus the bundle.
    m.insert(
        "MIMI_OUTBOUND_ALLOW",
        resolve("MIMI_OUTBOUND_ALLOW", "outbound_allow", file, None),
    );
    m.insert(
        "MIMI_OUTBOUND_PROXY",
        resolve("MIMI_OUTBOUND_PROXY", "outbound_proxy", file, None),
    );
    m.insert(
        "MIMI_PEER_TRUST",
        resolve("MIMI_PEER_TRUST", "peer_trust", file, None),
    );
    // No defaults: outbound requests present the server certificate, and every peer's base is https://<domain>.
    m.insert(
        "MIMI_CLIENT_CERT",
        resolve("MIMI_CLIENT_CERT", "client_cert", file, None),
    );
    m.insert(
        "MIMI_CLIENT_KEY",
        resolve("MIMI_CLIENT_KEY", "client_key", file, None),
    );
    m.insert("MIMI_PEERS", resolve("MIMI_PEERS", "peers", file, None));
    // No defaults: without a signing key the hub signs nothing it sends.
    m.insert(
        "MIMI_SIGNING_KEY",
        resolve("MIMI_SIGNING_KEY", "signing_key", file, None),
    );
    m.insert(
        "MIMI_SIGNING_SELECTOR",
        resolve("MIMI_SIGNING_SELECTOR", "signing_selector", file, None),
    );
    // No default: without it the hub answers every groupInfo request notAuthorized.
    m.insert(
        "MIMI_HUB_MLS_KEY",
        resolve("MIMI_HUB_MLS_KEY", "hub_mls_key", file, None),
    );
    m
}

#[cfg(test)]
#[path = "config_last_resort_tests.rs"]
mod last_resort_tests;

#[cfg(test)]
mod tests {
    use super::*;

    fn clear_env() {
        for k in [
            "MIMI_PROVIDER_DOMAIN",
            "MIMI_BIND_ADDR",
            "MIMI_DB_PATH",
            "MIMI_SERVER_CERT",
            "MIMI_SERVER_KEY",
            "MIMI_CLIENT_CA",
            "MIMI_DIRECTORY_BIND_ADDR",
            "MIMI_ADMIN_BIND_ADDR",
            "MIMI_POLICY",
            "MIMI_PUBLIC_BASE_URL",
            "MIMI_ACTIVITY_LOG",
        ] {
            std::env::remove_var(k);
        }
    }

    // These tests mutate process-wide env vars, so they must not run concurrently with each
    // other (std::env::set_var races across threads within one test binary). A single
    // std::sync::Mutex serializes them; each test clears state on entry so ordering doesn't
    // matter, only exclusivity does.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn env_only_matches_pre_config_behavior() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_env();
        std::env::set_var("MIMI_PROVIDER_DOMAIN", "hub.example.org");
        std::env::set_var("MIMI_SERVER_CERT", "/env/cert.pem");
        std::env::set_var("MIMI_SERVER_KEY", "/env/key.pem");
        std::env::set_var("MIMI_CLIENT_CA", "/env/ca.pem");
        let resolved = resolve_all(None);
        assert_eq!(
            resolved["MIMI_PROVIDER_DOMAIN"].as_deref(),
            Some("hub.example.org")
        );
        assert_eq!(resolved["MIMI_BIND_ADDR"].as_deref(), Some("0.0.0.0:8443"));
        assert_eq!(
            resolved["MIMI_DB_PATH"].as_deref(),
            Some("/var/lib/mimi/provider.db")
        );
        assert_eq!(
            resolved["MIMI_SERVER_CERT"].as_deref(),
            Some("/env/cert.pem")
        );
        clear_env();
    }

    #[test]
    fn the_activity_line_is_off_unless_it_is_set() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_env();
        assert_eq!(resolve_all(None)["MIMI_ACTIVITY_LOG"], None);
        std::env::set_var("MIMI_ACTIVITY_LOG", "1");
        assert_eq!(resolve_all(None)["MIMI_ACTIVITY_LOG"].as_deref(), Some("1"));
        clear_env();
    }

    #[test]
    fn the_directory_listener_exists_only_where_it_is_asked_for() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_env();
        assert_eq!(resolve_all(None)["MIMI_DIRECTORY_BIND_ADDR"], None);
        std::env::set_var("MIMI_DIRECTORY_BIND_ADDR", "127.0.0.1:8448");
        assert_eq!(
            resolve_all(None)["MIMI_DIRECTORY_BIND_ADDR"].as_deref(),
            Some("127.0.0.1:8448")
        );
        clear_env();
        let file = ConfigFile {
            directory_bind_addr: Some("192.0.2.2:8448".to_string()),
            ..Default::default()
        };
        assert_eq!(
            resolve_all(Some(&file))["MIMI_DIRECTORY_BIND_ADDR"].as_deref(),
            Some("192.0.2.2:8448")
        );
    }

    #[test]
    fn the_operator_listener_exists_only_where_it_is_asked_for() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_env();
        assert_eq!(resolve_all(None)["MIMI_ADMIN_BIND_ADDR"], None);
        std::env::set_var("MIMI_ADMIN_BIND_ADDR", "127.0.0.1:8445");
        assert_eq!(
            resolve_all(None)["MIMI_ADMIN_BIND_ADDR"].as_deref(),
            Some("127.0.0.1:8445")
        );
        clear_env();
        let file = ConfigFile {
            admin_bind_addr: Some("[::1]:8445".to_string()),
            ..Default::default()
        };
        assert_eq!(
            resolve_all(Some(&file))["MIMI_ADMIN_BIND_ADDR"].as_deref(),
            Some("[::1]:8445")
        );
    }

    #[test]
    fn file_only_supplies_every_value_when_env_is_unset() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_env();
        let file = ConfigFile {
            provider_domain: Some("filehub.example.org".to_string()),
            bind_addr: Some("127.0.0.1:9443".to_string()),
            db_path: Some("/file/hub.db".to_string()),
            server_cert: Some("/file/cert.pem".to_string()),
            server_key: Some("/file/key.pem".to_string()),
            client_ca: Some("/file/ca.pem".to_string()),
            ..Default::default()
        };
        let resolved = resolve_all(Some(&file));
        assert_eq!(
            resolved["MIMI_PROVIDER_DOMAIN"].as_deref(),
            Some("filehub.example.org")
        );
        assert_eq!(
            resolved["MIMI_BIND_ADDR"].as_deref(),
            Some("127.0.0.1:9443")
        );
        assert_eq!(resolved["MIMI_DB_PATH"].as_deref(), Some("/file/hub.db"));
        assert_eq!(
            resolved["MIMI_SERVER_CERT"].as_deref(),
            Some("/file/cert.pem")
        );
        assert_eq!(
            resolved["MIMI_SERVER_KEY"].as_deref(),
            Some("/file/key.pem")
        );
        assert_eq!(resolved["MIMI_CLIENT_CA"].as_deref(), Some("/file/ca.pem"));
    }

    #[test]
    fn env_overrides_one_key_on_top_of_the_file() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_env();
        std::env::set_var("MIMI_BIND_ADDR", "192.0.2.1:8443");
        let file = ConfigFile {
            provider_domain: Some("filehub.example.org".to_string()),
            bind_addr: Some("127.0.0.1:9443".to_string()),
            db_path: Some("/file/hub.db".to_string()),
            server_cert: Some("/file/cert.pem".to_string()),
            server_key: Some("/file/key.pem".to_string()),
            client_ca: Some("/file/ca.pem".to_string()),
            ..Default::default()
        };
        let resolved = resolve_all(Some(&file));
        // The overridden key wins from env...
        assert_eq!(
            resolved["MIMI_BIND_ADDR"].as_deref(),
            Some("192.0.2.1:8443")
        );
        // ...every other key still comes from the file.
        assert_eq!(
            resolved["MIMI_PROVIDER_DOMAIN"].as_deref(),
            Some("filehub.example.org")
        );
        assert_eq!(resolved["MIMI_DB_PATH"].as_deref(), Some("/file/hub.db"));
        clear_env();
    }

    #[test]
    fn missing_required_field_resolves_to_none_in_both_modes() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_env();
        // Env-only, nothing set: required field resolves to None (fails closed upstream).
        let resolved = resolve_all(None);
        assert_eq!(resolved["MIMI_PROVIDER_DOMAIN"], None);
        assert_eq!(resolved["MIMI_SERVER_CERT"], None);

        // File-only, file omits the required field too.
        let file = ConfigFile {
            bind_addr: Some("127.0.0.1:9443".to_string()),
            ..Default::default()
        };
        let resolved = resolve_all(Some(&file));
        assert_eq!(resolved["MIMI_PROVIDER_DOMAIN"], None);
        assert_eq!(resolved["MIMI_SERVER_CERT"], None);
    }

    #[test]
    fn empty_env_var_is_treated_as_unset_not_as_an_empty_override() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_env();
        std::env::set_var("MIMI_BIND_ADDR", "");
        let file = ConfigFile {
            bind_addr: Some("127.0.0.1:9443".to_string()),
            ..Default::default()
        };
        // Empty env var falls through to the file's value, not to an empty string.
        let (value, source) = resolve_with_source(
            "MIMI_BIND_ADDR",
            "bind_addr",
            Some(&file),
            Some("0.0.0.0:8443"),
        );
        assert_eq!(value.as_deref(), Some("127.0.0.1:9443"));
        assert_eq!(source, Source::File);

        // Same, but no file either: falls through all the way to the default.
        let (value, source) =
            resolve_with_source("MIMI_BIND_ADDR", "bind_addr", None, Some("0.0.0.0:8443"));
        assert_eq!(value.as_deref(), Some("0.0.0.0:8443"));
        assert_eq!(source, Source::Default);
        clear_env();
    }

    #[test]
    fn empty_file_value_is_treated_as_unset_not_as_an_empty_override() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_env();
        // A TOML `db_path = ""` (or whitespace-only) must fall through to the default, not reach a
        // caller as a real empty path (SQLite treats "" as a private, silently-deleted temp DB).
        let file = ConfigFile {
            db_path: Some("   ".to_string()),
            ..Default::default()
        };
        let (value, source) = resolve_with_source(
            "MIMI_DB_PATH",
            "db_path",
            Some(&file),
            Some("/var/lib/mimi/provider.db"),
        );
        assert_eq!(value.as_deref(), Some("/var/lib/mimi/provider.db"));
        assert_eq!(source, Source::Default);
        clear_env();
    }

    #[test]
    fn env_var_set_to_invalid_utf8_hard_errors_instead_of_silently_falling_through() {
        use std::os::unix::ffi::OsStringExt;
        // #[should_panic] would poison the shared ENV_LOCK mutex (the panic unwinds through the
        // held guard), failing every OTHER test in this file that also locks it - catch_unwind
        // lets this test clean up its own env var + release the lock before returning, same as
        // every other test here.
        let _guard = ENV_LOCK.lock().unwrap();
        clear_env();
        // A lone 0x80 byte is not valid UTF-8 in any position - std::env::var would report this as
        // Err(NotUnicode), indistinguishable via `if let Ok` from "not set at all."
        std::env::set_var("MIMI_BIND_ADDR", std::ffi::OsString::from_vec(vec![0x80]));
        let result = std::panic::catch_unwind(|| {
            resolve_with_source("MIMI_BIND_ADDR", "bind_addr", None, Some("0.0.0.0:8443"))
        });
        clear_env();
        let err = result.expect_err("expected a panic on invalid UTF-8, got a normal return");
        let msg = err
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| err.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default();
        assert!(
            msg.contains("is set but is not valid UTF-8"),
            "unexpected panic message: {msg}"
        );
    }

    #[test]
    fn resolve_with_source_reports_the_correct_layer() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_env();
        std::env::set_var("MIMI_CLIENT_CA", "/env/ca.pem");
        let file = ConfigFile {
            client_ca: Some("/file/ca.pem".to_string()),
            ..Default::default()
        };
        let (value, source) = resolve_with_source("MIMI_CLIENT_CA", "client_ca", Some(&file), None);
        assert_eq!(value.as_deref(), Some("/env/ca.pem"));
        assert_eq!(source, Source::Env);
        assert_eq!(source.label(), "env");

        std::env::remove_var("MIMI_CLIENT_CA");
        let (value, source) = resolve_with_source("MIMI_CLIENT_CA", "client_ca", Some(&file), None);
        assert_eq!(value.as_deref(), Some("/file/ca.pem"));
        assert_eq!(source, Source::File);

        let (value, source) = resolve_with_source("MIMI_CLIENT_CA", "client_ca", None, None);
        assert_eq!(value, None);
        assert_eq!(source, Source::Unset);
        clear_env();
    }

    #[test]
    fn parses_a_real_toml_file() {
        let dir = std::env::temp_dir().join(format!("mimihubd-config-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mimihubd.toml");
        std::fs::write(
            &path,
            r#"
provider_domain = "hub.example.org"
bind_addr = "0.0.0.0:8443"
db_path = "/var/lib/mimihubd/hub.db"
server_cert = "/etc/mimihubd/server-cert.pem"
server_key = "/etc/mimihubd/server-key.pem"
client_ca = "/etc/mimihubd/ca-cert.pem"
"#,
        )
        .unwrap();
        let file = ConfigFile::load(&path).unwrap();
        assert_eq!(file.provider_domain.as_deref(), Some("hub.example.org"));
        assert_eq!(
            file.server_key.as_deref(),
            Some("/etc/mimihubd/server-key.pem")
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn public_base_url_is_optional_and_layered_like_the_rest() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_env();
        assert_eq!(resolve_all(None)["MIMI_PUBLIC_BASE_URL"], None);
        let file = ConfigFile {
            public_base_url: Some("https://mimi.example.org".to_string()),
            ..ConfigFile::default()
        };
        assert_eq!(
            resolve_all(Some(&file))["MIMI_PUBLIC_BASE_URL"].as_deref(),
            Some("https://mimi.example.org")
        );
        std::env::set_var("MIMI_PUBLIC_BASE_URL", "https://proxy.example.org:8443");
        assert_eq!(
            resolve_all(Some(&file))["MIMI_PUBLIC_BASE_URL"].as_deref(),
            Some("https://proxy.example.org:8443")
        );
        clear_env();
    }

    #[test]
    fn unrecognized_key_does_not_fail_parsing() {
        // A typo'd or forward-compat key must not break the file - the daemon still starts on
        // every OTHER correctly-spelled setting. (The warning this prints to stderr is not
        // asserted here - see this module's own doc comment for why it's a warning, not an error.)
        let dir =
            std::env::temp_dir().join(format!("mimihubd-config-typo-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mimihubd.toml");
        std::fs::write(
            &path,
            r#"
provider_domain = "hub.example.org"
bnid_addr = "0.0.0.0:8443"
"#,
        )
        .unwrap();
        let file = ConfigFile::load(&path).unwrap();
        assert_eq!(file.provider_domain.as_deref(), Some("hub.example.org"));
        assert_eq!(file.bind_addr, None);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_config_file_is_a_clear_error_not_a_panic() {
        let result = ConfigFile::load(Path::new("/nonexistent/mimihubd-config-test.toml"));
        assert!(result.is_err());
    }
}
