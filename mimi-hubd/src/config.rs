//! File-based configuration, layered under the env-var interface `main.rs` has always used.
//!
//! Precedence: an env var (`MIMI_*`) always wins over the same setting in a `--config` file, so a
//! deployment can be "mostly file, override one thing via env" without two separate code paths. If
//! no `--config` is passed, resolution never looks at a file and behaves exactly as before. An env
//! var set to the empty string is treated as unset (falls through to the file/default), not as an
//! explicit override to an empty value - matching how these six settings (a domain name, an
//! address, three file paths) have no meaningful empty-string value in the first place, so
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
];

/// The six settings this daemon has always taken from env vars, now also loadable from a TOML
/// file. Field names match the env var suffix in lowercase (`MIMI_PROVIDER_DOMAIN` ->
/// `provider_domain`).
#[derive(Debug, Default, Deserialize)]
pub struct ConfigFile {
    pub provider_domain: Option<String>,
    pub bind_addr: Option<String>,
    pub db_path: Option<String>,
    pub server_cert: Option<String>,
    pub server_key: Option<String>,
    pub client_ca: Option<String>,
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
                        "[mimi-hubd] warning: config file {} has unrecognized key '{key}' (ignored - check for a typo)",
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
    if let Ok(v) = std::env::var(env_key) {
        if !v.is_empty() {
            return (Some(v), Source::Env);
        }
        // Empty string: treated as unset, falls through to file/default below.
    }
    if let Some(v) = file.and_then(|f| f.get(file_key)) {
        return (Some(v.clone()), Source::File);
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
        // config template may recommend a different path (see debian/mimi-hubd.toml.example), but
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
    m
}

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
        let dir =
            std::env::temp_dir().join(format!("mimi-hubd-config-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mimi-hubd.toml");
        std::fs::write(
            &path,
            r#"
provider_domain = "hub.example.org"
bind_addr = "0.0.0.0:8443"
db_path = "/var/lib/mimi-hubd/hub.db"
server_cert = "/etc/mimi-hubd/server-cert.pem"
server_key = "/etc/mimi-hubd/server-key.pem"
client_ca = "/etc/mimi-hubd/ca-cert.pem"
"#,
        )
        .unwrap();
        let file = ConfigFile::load(&path).unwrap();
        assert_eq!(file.provider_domain.as_deref(), Some("hub.example.org"));
        assert_eq!(
            file.server_key.as_deref(),
            Some("/etc/mimi-hubd/server-key.pem")
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn unrecognized_key_does_not_fail_parsing() {
        // A typo'd or forward-compat key must not break the file - the daemon still starts on
        // every OTHER correctly-spelled setting. (The warning this prints to stderr is not
        // asserted here - see this module's own doc comment for why it's a warning, not an error.)
        let dir =
            std::env::temp_dir().join(format!("mimi-hubd-config-typo-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mimi-hubd.toml");
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
        let result = ConfigFile::load(Path::new("/nonexistent/mimi-hubd-config-test.toml"));
        assert!(result.is_err());
    }
}
