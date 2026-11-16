//! keyMaterial for a user of another provider (protocol-07 §5.2): the hub of the room forwards the request to the
//! target's provider, and keeps which provider each KeyPackage it returns came from.
//!
//! §5.2 has a KeyPackage for a room claimed through that room's hub, so the hub can send the Welcome that uses it to the
//! right provider. The hub forwards a request only for a room it hosts, and only from a participant of it whose role may
//! add participants (`canAddParticipant`; a room with no roles: any participant). Any other request is answered
//! `noConsent`, the code §5.2 has for a refusal, and nothing is forwarded. The request goes as received to the
//! `keyMaterial` endpoint in the target provider's directory, through the outbound client. A `200` answer must decode as a
//! `KeyMaterialResponse` (its KeyPackages suite-gated as they decode); the `KeyPackageRef` of each KeyPackage in it is
//! recorded against that provider, and the answer is returned as received. Anything else from the peer is a `502`.

use std::sync::Arc;

use mimi_core::protocol_wire::KeyMaterialResponse;
use mimi_core::room_policy::Capability;
use mimi_core::uri::MimiUri;

use crate::peer_directory::PeerAccess;
use crate::Provider;

/// How long a forwarded KeyPackage's provider is remembered for routing its Welcome.
pub const PROXIED_KEY_PACKAGE_SECS: u64 = 30 * 24 * 3600;

/// Where a keyMaterial request goes.
pub enum KeyMaterialRoute {
    /// The target is a user of this provider.
    Local,
    /// The target is another provider's user, and the request may be forwarded to it.
    Forward {
        domain: String,
        access: Arc<PeerAccess>,
    },
    /// The target is another provider's user, and the request is not one this hub forwards.
    Refused(&'static str),
    /// The target is another provider's user, and this hub has no outbound client.
    Unavailable,
}

impl Provider {
    /// Hold the outbound client and directory cache, for requests the hub makes while answering one.
    pub fn with_peer_access(mut self, access: Arc<PeerAccess>) -> Self {
        self.peer_access = Some(access);
        self
    }

    /// Where a keyMaterial request for `target_uri` from `requester_uri`, for `room_uri`, goes.
    pub fn key_material_route(
        &self,
        requester_uri: &str,
        target_uri: &str,
        room_uri: Option<&str>,
    ) -> KeyMaterialRoute {
        let Ok(target) = MimiUri::parse(target_uri) else {
            return KeyMaterialRoute::Local;
        };
        if target.is_local_to(&self.domain) {
            return KeyMaterialRoute::Local;
        }
        let Some(room_uri) = room_uri else {
            return KeyMaterialRoute::Refused("no room is named");
        };
        if self.assert_hub_of_record(room_uri).is_err() {
            return KeyMaterialRoute::Refused("the room is not one this hub hosts");
        }
        let requester = mimi_core::uri::canonical(requester_uri);
        let role = match self.store.list_participant_rows(room_uri) {
            Ok(rows) => rows
                .into_iter()
                .find(|row| row.member_uri == requester)
                .map(|row| row.role_index),
            Err(_) => {
                return KeyMaterialRoute::Refused("the room's participants could not be read")
            }
        };
        let Some(role) = role else {
            return KeyMaterialRoute::Refused("the requester is not a participant of the room");
        };
        let may_add = match self.room_policy(room_uri) {
            Ok(Some(policy)) if !policy.roles.is_empty() => role
                .and_then(|role| policy.role(role))
                .is_some_and(|role| role.has(Capability::AddParticipant)),
            Ok(_) => true,
            Err(_) => false,
        };
        if !may_add {
            return KeyMaterialRoute::Refused("the requester's role may not add participants");
        }
        match &self.peer_access {
            Some(access) => KeyMaterialRoute::Forward {
                domain: target.authority.to_ascii_lowercase(),
                access: access.clone(),
            },
            None => KeyMaterialRoute::Unavailable,
        }
    }

    /// Record the provider each KeyPackage in a forwarded answer came from. Returns how many.
    pub fn record_forwarded_key_material(
        &self,
        domain: &str,
        answer: &KeyMaterialResponse,
        now_unix: u64,
    ) -> anyhow::Result<usize> {
        let key_packages: Vec<&[u8]> = match answer {
            KeyMaterialResponse::Success { key_package, .. } => vec![key_package.as_slice()],
            KeyMaterialResponse::Clients { clients, .. } => clients
                .iter()
                .filter_map(|client| client.key_package.as_deref())
                .collect(),
            _ => Vec::new(),
        };
        for key_package in &key_packages {
            self.associate_claimed_keypackage(
                key_package,
                domain,
                now_unix.saturating_add(PROXIED_KEY_PACKAGE_SECS),
            )?;
        }
        Ok(key_packages.len())
    }
}

/// Forward a keyMaterial request body, as received, to `domain`'s `keyMaterial` endpoint for `target_uri`. Returns the
/// `200` answer's body, or why there is none.
pub async fn forward_key_material(
    access: &PeerAccess,
    domain: &str,
    target_uri: &str,
    body: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let directory = access
        .directories
        .get(&access.client, domain)
        .await
        .map_err(|error| error.to_string())?;
    let url = directory
        .endpoint("keyMaterial", "targetUser", target_uri, domain)
        .map_err(|error| error.to_string())?;
    let response = access
        .client
        .post(&url, "application/mimi-protocol", body)
        .await
        .map_err(|error| {
            access.directories.forget(domain);
            error.to_string()
        })?;
    if response.status != 200 {
        return Err(format!("answered {}", response.status));
    }
    Ok(response.body)
}

#[cfg(test)]
#[path = "key_material_proxy_tests.rs"]
mod tests;
