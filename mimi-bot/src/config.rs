//! File-based configuration, layered under an env-var interface - same precedence contract as
//! `mimi-hubd`'s `config.rs` (DISPATCH-174), which this module deliberately mirrors byte-for-byte
//! in its resolution logic so the two daemons read as siblings, not independently-invented config
//! systems (per DISPATCH-184's own routing note). The `ConfigFile` field set and env-var prefix
//! differ because this is a different daemon with different settings; the mechanism (env wins over
//! file, empty env var = unset, unknown file keys warn-not-fail, `--config`-absent is byte-
//! identical to env-only) is copied intentionally, not reinvented.
//!
//! Precedence: an env var (`MIMI_BOT_*`, prefixed to avoid colliding with `mimi-hubd`'s own
//! `MIMI_*` vars if the two daemons are co-located) always wins over the same setting in a
//! `--config` file. If no `--config` is passed, resolution never looks at a file. An env var set to
//! the empty string is treated as unset, not as an explicit empty override.
//!
//! No mTLS/TLS fields here (the DISPATCH-184 revision): mimi-bot talks to its paired provider over
//! a private Unix-socket channel, not the public mTLS HTTP surface - `socket_path` replaces
//! `provider_url`/`client_cert`/`client_key`/`server_ca` from the first design.

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;

const KNOWN_KEYS: &[&str] = &[
    "bot_domain",
    "bot_username",
    "socket_path",
    "poll_interval_secs",
    "rate_limit_max_per_window",
    "rate_limit_window_secs",
    "max_concurrent_rooms",
];

/// The seven settings this daemon takes from env vars or an equivalent TOML file. Field names
/// match the env var suffix in lowercase (`MIMI_BOT_SOCKET_PATH` -> `socket_path`). All
/// `Option<String>` (including the numeric ones) so the same generic `resolve`/`resolve_with_source`
/// machinery handles every field; numeric fields are parsed by the caller after resolution.
#[derive(Debug, Default, Deserialize)]
pub struct ConfigFile {
    pub bot_domain: Option<String>,
    pub bot_username: Option<String>,
    pub socket_path: Option<String>,
    pub poll_interval_secs: Option<String>,
    pub rate_limit_max_per_window: Option<String>,
    pub rate_limit_window_secs: Option<String>,
    pub max_concurrent_rooms: Option<String>,
}

impl ConfigFile {
    /// Read and parse a TOML config file. Unknown top-level keys are ignored for parsing
    /// (forward-compatible) but logged as a warning - the same typo-vs-future-key tradeoff
    /// `mimi-hubd`'s `ConfigFile::load` documents.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("cannot read config file {}: {e}", path.display()))?;
        if let Ok(table) = raw.parse::<toml::Table>() {
            for key in table.keys() {
                if !KNOWN_KEYS.contains(&key.as_str()) {
                    eprintln!(
                        "[mimi-bot] warning: config file {} has unrecognized key '{key}' (ignored - check for a typo)",
                        path.display()
                    );
                }
            }
        }
        // TOML numeric fields (poll_interval_secs etc.) may be written as bare integers by an
        // operator, but ConfigFile's fields are all String (see struct doc) so resolve_all's
        // generic machinery is shared with the string fields. Round-trip any integer/float TOML
        // value through its Display form before deserializing into ConfigFile's String fields.
        let normalized = normalize_numeric_toml_values(&raw)?;
        toml::from_str(&normalized)
            .map_err(|e| anyhow::anyhow!("cannot parse config file {}: {e}", path.display()))
    }

    fn get(&self, key: &str) -> Option<&String> {
        match key {
            "bot_domain" => self.bot_domain.as_ref(),
            "bot_username" => self.bot_username.as_ref(),
            "socket_path" => self.socket_path.as_ref(),
            "poll_interval_secs" => self.poll_interval_secs.as_ref(),
            "rate_limit_max_per_window" => self.rate_limit_max_per_window.as_ref(),
            "rate_limit_window_secs" => self.rate_limit_window_secs.as_ref(),
            "max_concurrent_rooms" => self.max_concurrent_rooms.as_ref(),
            _ => None,
        }
    }
}

/// TOML lets an operator write `poll_interval_secs = 5` (an integer) instead of `"5"` (a string).
/// `ConfigFile`'s fields are all `String` so the shared `resolve`/`resolve_with_source` machinery
/// (designed for string-valued settings like paths and domains) also covers the numeric ones
/// without a second code path. Re-parse as a generic `toml::Table`, stringify any integer/float
/// leaf value in place, and re-serialize before the real `toml::from_str::<ConfigFile>` call.
fn normalize_numeric_toml_values(raw: &str) -> anyhow::Result<String> {
    let Ok(mut table) = raw.parse::<toml::Table>() else {
        // Let the real parse call below produce the actual error message.
        return Ok(raw.to_string());
    };
    for key in KNOWN_KEYS {
        if let Some(v) = table.get(*key) {
            let stringified = match v {
                toml::Value::Integer(n) => Some(n.to_string()),
                toml::Value::Float(f) => Some(f.to_string()),
                _ => None,
            };
            if let Some(s) = stringified {
                table.insert((*key).to_string(), toml::Value::String(s));
            }
        }
    }
    Ok(toml::to_string(&table)?)
}

/// Which layer supplied a resolved setting's value. Reported for `socket_path` specifically
/// (`main.rs` logs it at startup) since which layer supplied the private-channel path is a
/// statement about the trust boundary (the socket, not TLS, IS the trust boundary here) - same
/// rationale as `mimi-hubd`'s identical `Source` type.
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

/// Resolves one setting and reports which layer supplied it: `MIMI_BOT_{ENV_KEY}` env var (if set
/// to a non-empty value) wins, else the config file's value (if a file was loaded and sets it),
/// else `default` (if given), else unresolved. `file` is `None` when no `--config` was passed - in
/// that case this degenerates to exactly the pre-existing env-or-default lookup, so the
/// no-`--config` path is byte-identical to env-only behavior. Identical logic to `mimi-hubd`'s
/// `resolve_with_source` (DISPATCH-174) - copied deliberately, not reinvented (see module doc).
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

/// Value-only convenience wrapper around [`resolve_with_source`].
pub fn resolve(
    env_key: &str,
    file_key: &str,
    file: Option<&ConfigFile>,
    default: Option<&str>,
) -> Option<String> {
    resolve_with_source(env_key, file_key, file, default).0
}

/// Every resolved setting this daemon needs, keyed by its env-var name.
pub type Resolved = HashMap<&'static str, Option<String>>;

pub fn resolve_all(file: Option<&ConfigFile>) -> Resolved {
    let mut m: Resolved = HashMap::new();
    m.insert(
        "MIMI_BOT_DOMAIN",
        resolve("MIMI_BOT_DOMAIN", "bot_domain", file, None),
    );
    m.insert(
        "MIMI_BOT_USERNAME",
        resolve("MIMI_BOT_USERNAME", "bot_username", file, Some("mimi-bot")),
    );
    m.insert(
        "MIMI_BOT_SOCKET_PATH",
        resolve("MIMI_BOT_SOCKET_PATH", "socket_path", file, None),
    );
    m.insert(
        "MIMI_BOT_POLL_INTERVAL_SECS",
        resolve(
            "MIMI_BOT_POLL_INTERVAL_SECS",
            "poll_interval_secs",
            file,
            Some("5"),
        ),
    );
    m.insert(
        "MIMI_BOT_RATE_LIMIT_MAX_PER_WINDOW",
        resolve(
            "MIMI_BOT_RATE_LIMIT_MAX_PER_WINDOW",
            "rate_limit_max_per_window",
            file,
            Some("5"),
        ),
    );
    m.insert(
        "MIMI_BOT_RATE_LIMIT_WINDOW_SECS",
        resolve(
            "MIMI_BOT_RATE_LIMIT_WINDOW_SECS",
            "rate_limit_window_secs",
            file,
            Some("10"),
        ),
    );
    m.insert(
        "MIMI_BOT_MAX_CONCURRENT_ROOMS",
        resolve(
            "MIMI_BOT_MAX_CONCURRENT_ROOMS",
            "max_concurrent_rooms",
            file,
            Some("50"),
        ),
    );
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clear_env() {
        for k in [
            "MIMI_BOT_DOMAIN",
            "MIMI_BOT_USERNAME",
            "MIMI_BOT_SOCKET_PATH",
            "MIMI_BOT_POLL_INTERVAL_SECS",
            "MIMI_BOT_RATE_LIMIT_MAX_PER_WINDOW",
            "MIMI_BOT_RATE_LIMIT_WINDOW_SECS",
            "MIMI_BOT_MAX_CONCURRENT_ROOMS",
        ] {
            std::env::remove_var(k);
        }
    }

    // Same cross-test env-mutation hazard as mimi-hubd's config tests: serialize on one lock.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn env_only_matches_pre_config_behavior() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_env();
        std::env::set_var("MIMI_BOT_DOMAIN", "bot.example.org");
        std::env::set_var(
            "MIMI_BOT_SOCKET_PATH",
            "/var/run/mimi-provider/mimi-bot.sock",
        );
        let resolved = resolve_all(None);
        assert_eq!(
            resolved["MIMI_BOT_DOMAIN"].as_deref(),
            Some("bot.example.org")
        );
        assert_eq!(resolved["MIMI_BOT_USERNAME"].as_deref(), Some("mimi-bot"));
        assert_eq!(
            resolved["MIMI_BOT_SOCKET_PATH"].as_deref(),
            Some("/var/run/mimi-provider/mimi-bot.sock")
        );
        assert_eq!(
            resolved["MIMI_BOT_POLL_INTERVAL_SECS"].as_deref(),
            Some("5")
        );
        clear_env();
    }

    #[test]
    fn file_only_supplies_every_value_when_env_is_unset() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_env();
        let file = ConfigFile {
            bot_domain: Some("filebot.example.org".to_string()),
            bot_username: Some("filebot".to_string()),
            socket_path: Some("/var/run/mimi-provider/mimi-bot.sock".to_string()),
            poll_interval_secs: Some("10".to_string()),
            rate_limit_max_per_window: Some("3".to_string()),
            rate_limit_window_secs: Some("20".to_string()),
            max_concurrent_rooms: Some("10".to_string()),
        };
        let resolved = resolve_all(Some(&file));
        assert_eq!(
            resolved["MIMI_BOT_DOMAIN"].as_deref(),
            Some("filebot.example.org")
        );
        assert_eq!(resolved["MIMI_BOT_USERNAME"].as_deref(), Some("filebot"));
        assert_eq!(
            resolved["MIMI_BOT_POLL_INTERVAL_SECS"].as_deref(),
            Some("10")
        );
        assert_eq!(
            resolved["MIMI_BOT_MAX_CONCURRENT_ROOMS"].as_deref(),
            Some("10")
        );
    }

    #[test]
    fn env_overrides_one_key_on_top_of_the_file() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_env();
        std::env::set_var("MIMI_BOT_POLL_INTERVAL_SECS", "1");
        let file = ConfigFile {
            bot_domain: Some("filebot.example.org".to_string()),
            socket_path: Some("/var/run/mimi-provider/mimi-bot.sock".to_string()),
            poll_interval_secs: Some("10".to_string()),
            ..Default::default()
        };
        let resolved = resolve_all(Some(&file));
        assert_eq!(
            resolved["MIMI_BOT_POLL_INTERVAL_SECS"].as_deref(),
            Some("1")
        );
        assert_eq!(
            resolved["MIMI_BOT_DOMAIN"].as_deref(),
            Some("filebot.example.org")
        );
        clear_env();
    }

    #[test]
    fn missing_required_field_resolves_to_none_in_both_modes() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_env();
        let resolved = resolve_all(None);
        assert_eq!(resolved["MIMI_BOT_DOMAIN"], None);
        assert_eq!(resolved["MIMI_BOT_SOCKET_PATH"], None);

        let file = ConfigFile {
            bot_username: Some("x".to_string()),
            ..Default::default()
        };
        let resolved = resolve_all(Some(&file));
        assert_eq!(resolved["MIMI_BOT_DOMAIN"], None);
        assert_eq!(resolved["MIMI_BOT_SOCKET_PATH"], None);
    }

    #[test]
    fn empty_env_var_is_treated_as_unset_not_as_an_empty_override() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_env();
        std::env::set_var("MIMI_BOT_DOMAIN", "");
        let file = ConfigFile {
            bot_domain: Some("filebot.example.org".to_string()),
            ..Default::default()
        };
        let (value, source) =
            resolve_with_source("MIMI_BOT_DOMAIN", "bot_domain", Some(&file), None);
        assert_eq!(value.as_deref(), Some("filebot.example.org"));
        assert_eq!(source, Source::File);
        clear_env();
    }

    #[test]
    fn parses_a_real_toml_file_with_bare_integer_settings() {
        let dir = std::env::temp_dir().join(format!("mimi-bot-config-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mimi-bot.toml");
        std::fs::write(
            &path,
            r#"
bot_domain = "bot.example.org"
bot_username = "mimi-bot"
socket_path = "/var/run/mimi-provider/mimi-bot.sock"
poll_interval_secs = 5
rate_limit_max_per_window = 5
rate_limit_window_secs = 10
max_concurrent_rooms = 50
"#,
        )
        .unwrap();
        let file = ConfigFile::load(&path).unwrap();
        assert_eq!(file.bot_domain.as_deref(), Some("bot.example.org"));
        assert_eq!(file.poll_interval_secs.as_deref(), Some("5"));
        assert_eq!(file.max_concurrent_rooms.as_deref(), Some("50"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn unrecognized_key_does_not_fail_parsing() {
        let dir =
            std::env::temp_dir().join(format!("mimi-bot-config-typo-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mimi-bot.toml");
        std::fs::write(
            &path,
            r#"
bot_domain = "bot.example.org"
bnot_username = "typo"
"#,
        )
        .unwrap();
        let file = ConfigFile::load(&path).unwrap();
        assert_eq!(file.bot_domain.as_deref(), Some("bot.example.org"));
        assert_eq!(file.bot_username, None);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_config_file_is_a_clear_error_not_a_panic() {
        let result = ConfigFile::load(Path::new("/nonexistent/mimi-bot-config-test.toml"));
        assert!(result.is_err());
    }
}
