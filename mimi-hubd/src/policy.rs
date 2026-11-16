//! What this hub accepts and answers, where the drafts leave it to the deployment: one TOML file, named by
//! `MIMI_POLICY` (or `policy` in the config file). With no file the hub follows the drafts; every field has that default.
//!
//! ```toml
//! # The MLS ciphersuites accepted from other providers, as wire values. Default: every suite the crypto provider
//! # implements. The directory advertises exactly this list.
//! mls_ciphersuites = [0x0001]
//! # Who identifierQuery may find: "all" (default), every user this hub can answer for, which here means a user it has
//! # enrolled or holds KeyPackages for; or "enrolled", only users enrolled with `mimi-hubd enroll`.
//! identifier_discovery = "enrolled"
//! ```
//!
//! A named file the hub cannot read, a key it does not know, an empty suite list or a suite the crypto provider does not
//! implement stops the start: a policy that is not the one written must not run as if it were.

use std::path::Path;

use serde::Deserialize;

/// Who `identifierQuery` may find. Protocol-07 §5.8's privacy considerations apply to either setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Discovery {
    /// Every user this hub can answer for: one it has enrolled or holds KeyPackages for.
    #[default]
    All,
    /// Only users enrolled with `mimi-hubd enroll`.
    Enrolled,
}

/// The deployment's choices; [`Default`] is the drafts' behaviour.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HubPolicy {
    /// The MLS ciphersuites accepted from other providers, as wire values.
    pub mls_ciphersuites: Vec<u16>,
    pub identifier_discovery: Discovery,
}

impl Default for HubPolicy {
    fn default() -> Self {
        Self {
            mls_ciphersuites: mimi_core::gate::default_mls_ciphersuites(),
            identifier_discovery: Discovery::default(),
        }
    }
}

impl HubPolicy {
    /// Read and check the policy file at `path`.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("cannot read the policy file {}: {e}", path.display()))?;
        Self::parse(&raw).map_err(|e| anyhow::anyhow!("the policy file {}: {e}", path.display()))
    }

    /// Parse and check a policy written as TOML.
    pub fn parse(raw: &str) -> anyhow::Result<Self> {
        let policy: Self = toml::from_str(raw)?;
        policy.check()?;
        Ok(policy)
    }

    fn check(&self) -> anyhow::Result<()> {
        if self.mls_ciphersuites.is_empty() {
            anyhow::bail!(
                "mls_ciphersuites is empty, so nothing from another provider would be accepted"
            );
        }
        let implemented = mimi_core::gate::default_mls_ciphersuites();
        if let Some(suite) = self
            .mls_ciphersuites
            .iter()
            .find(|suite| !implemented.contains(suite))
        {
            anyhow::bail!(
                "mls_ciphersuites names 0x{suite:04x}, which this hub's crypto provider does not implement; it implements {}",
                hex_list(&implemented)
            );
        }
        Ok(())
    }

    /// The policy in one line, for the startup log.
    pub fn describe(&self) -> String {
        let discovery = match self.identifier_discovery {
            Discovery::All => "all",
            Discovery::Enrolled => "enrolled",
        };
        format!(
            "mls_ciphersuites={} identifier_discovery={discovery}",
            hex_list(&self.mls_ciphersuites)
        )
    }
}

fn hex_list(suites: &[u16]) -> String {
    suites
        .iter()
        .map(|suite| format!("0x{suite:04x}"))
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod tests;
