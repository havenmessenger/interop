//! What this hub accepts and answers, where the drafts leave it to the deployment: one TOML file, named by
//! `MIMI_POLICY` (or `policy` in the config file). With no file the hub follows the drafts; every field has that default.
//!
//! ```toml
//! # The MLS ciphersuites accepted from other providers, as wire values. Default: every suite the crypto provider
//! # implements. The directory advertises exactly this list.
//! mls_ciphersuites = [0x0001]
//! # Who identifierQuery may find: "all" (default), every user this hub can answer for, which here means a user it has
//! # enrolled or holds KeyPackages for; or "enrolled", only users enrolled with `mimihubd enroll`.
//! identifier_discovery = "enrolled"
//! # Refuse a signed keyMaterial request that carries no nonce. Default false: draft-atwood-mimi-provider-auth-00 has no
//! # nonce. A repeated nonce is refused whatever this says.
//! require_nonce_on_key_material = true
//! # An external Commit to a room whose operational policy says nothing (no mls_operational_policy component):
//! # "allow" (default, as MLS: subject to who may join) or "deny".
//! external_commit_when_unset = "allow"
//! # A room hosted here whose ratchet tree the hub does not keep: "refuse" (default) takes its first Commit, and any
//! # participant-list or room-policy change to it, only with a bundle that gives the hub the tree; "accept" applies
//! # changes the hub cannot authorize, trusting the members to have checked them.
//! untracked_rooms = "refuse"
//! # Consent on the client lane (protocol-07 §8). A user may also decide for every user of a provider (default false:
//! # the draft's scope is one requesting user). It is read against the requester URI's domain, which any peer naming a
//! # room on its own domain can choose (DIVERGENCES DIV-6), so on it admits any authenticated peer: leave it off unless
//! # every peer is trusted.
//! consent_provider_grants = false
//! # Send a revoke to the requester's provider (default false: §8, "typically not communicated").
//! consent_revoke_notifies = false
//! # Keep a user's consent decisions when they opt out (default false: they start over when they opt in again).
//! consent_kept_at_opt_out = false
//! # Days a consent request made of a user stays pending (default 30).
//! consent_request_days = 30
//!
//! # The did_webvh credential (draft-atwood-mls-didwebvh-credential, DIVERGENCES DIV-24): whether this hub reads it, and
//! # the code points it reads it under until IANA assigns them. Defaults: on, credential type 0x0008, record component
//! # 0xF013 (the reference implementation's). Every member of a room must use the same values.
//! [did_webvh]
//! enabled = true
//! credential_type = 0x0008
//! heads_component = 0xF013
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
    /// Only users enrolled with `mimihubd enroll`.
    Enrolled,
}

/// What an external Commit to a room with no `mls_operational_policy` component meets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExternalCommitWhenUnset {
    /// As MLS: an external join is possible, subject to who may join.
    #[default]
    Allow,
    /// Refused, as if the room's policy said `external_commit_allowed = false`.
    Deny,
}

/// What a room hosted here whose ratchet tree the hub does not keep meets (`hosted_untracked.rs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UntrackedRooms {
    /// The hub refuses what it cannot authorize: the room's first Commit, and a participant-list or room-policy change,
    /// need a bundle that gives the hub the tree (protocol-07 §9: the hub enforces the room's policy).
    #[default]
    Refuse,
    /// The hub applies changes it cannot authorize, trusting the members to have checked them (RFC 9420's delivery
    /// service is not required to), until a bundle gives it the tree.
    Accept,
}

/// The did_webvh credential: whether the hub reads it, and the code points it reads it under (DIV-24).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DidWebvhPolicy {
    /// Off: a did_webvh credential is a type the hub does not read, and its record a component it has no rule for.
    pub enabled: bool,
    /// The credential type it is read under.
    pub credential_type: u16,
    /// The `app_data_dictionary` component of its `did_webvh_heads` record.
    pub heads_component: u16,
}

impl Default for DidWebvhPolicy {
    fn default() -> Self {
        let points = mls_didwebvh::CodePoints::DEFAULT;
        Self {
            enabled: true,
            credential_type: points.credential_type(),
            heads_component: points.heads_component(),
        }
    }
}

impl DidWebvhPolicy {
    /// The code points the hub reads the credential under, `None` when it is off; values the credential cannot take
    /// (reserved, already assigned, GREASE) are refused.
    pub fn code_points(&self) -> anyhow::Result<Option<mls_didwebvh::CodePoints>> {
        if !self.enabled {
            return Ok(None);
        }
        mls_didwebvh::CodePoints::new(self.credential_type, self.heads_component)
            .map(Some)
            .map_err(|e| anyhow::anyhow!("[did_webvh]: {e}"))
    }
}

/// The deployment's choices; [`Default`] is the drafts' behaviour.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HubPolicy {
    /// The MLS ciphersuites accepted from other providers, as wire values.
    pub mls_ciphersuites: Vec<u16>,
    pub identifier_discovery: Discovery,
    /// Refuse a signed keyMaterial request with no `nonce`: a replayed one would take another KeyPackage.
    pub require_nonce_on_key_material: bool,
    pub external_commit_when_unset: ExternalCommitWhenUnset,
    pub untracked_rooms: UntrackedRooms,
    /// A lane user may decide for every user of a provider, not only for one user (`client_lane_consent.rs`).
    pub consent_provider_grants: bool,
    /// A revoke is sent to the requester's provider as `updateConsent`; otherwise only a grant is.
    pub consent_revoke_notifies: bool,
    /// A user's consent decisions stay when they opt out; otherwise opting out clears them.
    pub consent_kept_at_opt_out: bool,
    /// Days a consent request made of a user stays pending before it is dropped.
    pub consent_request_days: u32,
    /// The did_webvh credential (DIV-24).
    pub did_webvh: DidWebvhPolicy,
}

impl Default for HubPolicy {
    fn default() -> Self {
        Self {
            mls_ciphersuites: mimi_core::gate::default_mls_ciphersuites(),
            identifier_discovery: Discovery::default(),
            require_nonce_on_key_material: false,
            external_commit_when_unset: ExternalCommitWhenUnset::default(),
            untracked_rooms: UntrackedRooms::default(),
            consent_provider_grants: false,
            consent_revoke_notifies: false,
            consent_kept_at_opt_out: false,
            consent_request_days: 30,
            did_webvh: DidWebvhPolicy::default(),
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
        if self.consent_request_days == 0 {
            anyhow::bail!(
                "consent_request_days is 0, so every consent request would expire as it arrives"
            );
        }
        self.did_webvh.code_points()?;
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
            "mls_ciphersuites={} identifier_discovery={discovery} require_nonce_on_key_material={} external_commit_when_unset={} untracked_rooms={} consent_provider_grants={} consent_revoke_notifies={} consent_kept_at_opt_out={} consent_request_days={} did_webvh={}",
            hex_list(&self.mls_ciphersuites),
            self.require_nonce_on_key_material,
            match self.external_commit_when_unset {
                ExternalCommitWhenUnset::Allow => "allow",
                ExternalCommitWhenUnset::Deny => "deny",
            },
            match self.untracked_rooms {
                UntrackedRooms::Refuse => "refuse",
                UntrackedRooms::Accept => "accept",
            },
            self.consent_provider_grants,
            self.consent_revoke_notifies,
            self.consent_kept_at_opt_out,
            self.consent_request_days,
            if self.did_webvh.enabled {
                format!(
                    "0x{:04x}/0x{:04x}",
                    self.did_webvh.credential_type, self.did_webvh.heads_component
                )
            } else {
                "off".to_owned()
            },
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
