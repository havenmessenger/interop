//! What the client lane sends on to another provider, and the limits on its keyMaterial.
//!
//! **A room on another hub.** protocol-07 has a member provider forward its user's message and updates to the room's
//! hub (§3.4: "sends it to ServerC, who forwards it to the hub ServerA on Cathy's behalf"; §3.3 and §3.5 for adds and
//! leaves). For a room whose URI is on another domain, the lane's `submitMessage` and `update` post the request, as this
//! provider, to that hub's `submitMessage` and `update` endpoints, and answer what it answers. The hosting hub judges
//! the request as it judges any peer's, against the room it holds; this hub vouches only that the request comes from
//! the user the lane signature names (a relayed message names that user as its sender). DIVERGENCES DIV-19.
//!
//! **keyMaterial.** §5.2: "KeyPackages requested using this primitive MUST be sent via the hub provider of whatever
//! room they will be used in." The lane takes the client's signed `KeyMaterialRequest`; its `requestingUser` and the
//! credential it is signed under must be the lane user, and its signature must verify. A room hosted here answers it as
//! the peer route does; a room on another hub has it sent there. Each user is held to [`KEY_MATERIAL_PER_MINUTE`]
//! requests a minute, and to [`KEY_MATERIAL_PER_TARGET_PER_HOUR`] for any one target user, so no user can drain
//! another user's KeyPackages through this hub.
//!
//! A hub with no outbound client answers what would go to another provider with 502 `upstream-failed`.

use std::collections::HashMap;
use std::sync::Mutex;

use mimi_core::protocol_wire::KeyMaterialRequest;
use mimi_core::uri::MimiUri;

use crate::peer_directory::PeerAccess;

/// keyMaterial requests one lane user may make in a minute.
// LIMIT-REASON: quota: adding a room's members takes one request per member; this bounds a user fetching for many
pub const KEY_MATERIAL_PER_MINUTE: u32 = 30;

/// keyMaterial requests one lane user may make for one target user in an hour, and one requesting provider on the
/// provider path.
// LIMIT-REASON: quota: a target's KeyPackages are single-use; this bounds one user spending another's
pub const KEY_MATERIAL_PER_TARGET_PER_HOUR: u32 = 5;

/// The client lane's keyMaterial requests per user (this minute) and per user and target (this hour), in memory.
#[derive(Default)]
pub struct KeyMaterialCap {
    per_user: Mutex<HashMap<String, (i64, u32)>>,
    per_target: Mutex<HashMap<(String, String), (i64, u32)>>,
}

/// The provider path's keyMaterial requests per requesting provider and target (this hour), in memory. The provider is
/// the domain the peer proved; the requester a request names is the peer's choice (DIV-6), so it is not counted: a
/// count on it would let one peer spend the budget of whatever requester it names.
#[derive(Default)]
pub struct PeerKeyMaterialCap {
    per_provider_target: Mutex<HashMap<(String, String), (i64, u32)>>,
}

fn count<K: std::hash::Hash + Eq>(
    counts: &Mutex<HashMap<K, (i64, u32)>>,
    key: K,
    window: i64,
    limit: u32,
) -> bool {
    let mut counts = counts
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    counts.retain(|_, (at, _)| *at == window);
    let entry = counts.entry(key).or_insert((window, 0));
    entry.1 = entry.1.saturating_add(1);
    entry.1 <= limit
}

impl KeyMaterialCap {
    /// Count one request by `user` for `target` at `now` (seconds); false when either limit is passed.
    pub fn admit(&self, user: &str, target: &str, now: i64) -> bool {
        let user_ok = count(
            &self.per_user,
            user.to_string(),
            now / 60,
            KEY_MATERIAL_PER_MINUTE,
        );
        let target_ok = count(
            &self.per_target,
            (user.to_string(), mimi_core::uri::canonical(target)),
            now / 3600,
            KEY_MATERIAL_PER_TARGET_PER_HOUR,
        );
        user_ok && target_ok
    }
}

impl PeerKeyMaterialCap {
    /// Count one provider-path request at `now` (seconds) from the peer whose proof authenticated `provider`, for
    /// `target`; false when the hourly limit is passed. A refused request is not counted.
    pub fn admit(&self, provider: &str, target: &str, now: i64) -> bool {
        let window = now / 3600;
        let key = (
            provider.to_ascii_lowercase(),
            mimi_core::uri::canonical(target),
        );
        let mut counts = self
            .per_provider_target
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        counts.retain(|_, (at, _)| *at == window);
        let spent = counts.entry(key).or_insert((window, 0));
        if spent.1 >= KEY_MATERIAL_PER_TARGET_PER_HOUR {
            return false;
        }
        spent.1 += 1;
        true
    }
}

/// Why a lane keyMaterial request is not taken.
#[derive(Debug, PartialEq, Eq)]
pub enum KeyMaterialRefusal {
    /// Its `requestingUser`, or the credential it is signed under, is not the lane user, or its signature does not
    /// verify.
    NotTheUser,
    /// It names no room: §5.2 has a request made to add a user name the room.
    NoRoom,
}

/// Check a lane keyMaterial request is the lane user's own: `requestingUser` and the credential are `user`, and the
/// signature verifies under the key it names.
pub fn check_key_material_request(
    request: &KeyMaterialRequest,
    user: &str,
) -> Result<(), KeyMaterialRefusal> {
    let user = mimi_core::uri::canonical(user);
    if mimi_core::uri::canonical(&request.requesting_user.0) != user {
        return Err(KeyMaterialRefusal::NotTheUser);
    }
    let credential = crate::credential::user_uri(
        &request.requester_credential,
        request.requester_signature_key.as_slice(),
    )
    .ok_or(KeyMaterialRefusal::NotTheUser)?;
    if credential != user || !request.signature_verifies() {
        return Err(KeyMaterialRefusal::NotTheUser);
    }
    if request.room_id.0.is_empty() {
        return Err(KeyMaterialRefusal::NoRoom);
    }
    Ok(())
}

/// The domain of the hub of `room_uri` when it is not `own_domain`: where a request about the room is sent.
pub fn other_hub(room_uri: &str, own_domain: &str) -> Option<String> {
    let room = MimiUri::parse(room_uri).ok()?;
    (!room.is_local_to(own_domain)).then(|| room.authority.to_ascii_lowercase())
}

/// POST `body` to `domain`'s `endpoint` (a key of its directory) with `variable` filled by `value`. Returns the
/// answer's status and body, or why there is none.
pub async fn post_to_peer(
    access: &PeerAccess,
    domain: &str,
    endpoint: &'static str,
    variable: &str,
    value: &str,
    body: Vec<u8>,
) -> Result<(u16, Vec<u8>), String> {
    let directory = access
        .directories
        .get(&access.client, domain)
        .await
        .map_err(|error| error.to_string())?;
    let url = directory
        .endpoint(endpoint, variable, value, domain)
        .map_err(|error| error.to_string())?;
    let started = crate::telemetry::now();
    let result = access
        .client
        .post(&url, "application/mimi-protocol", body)
        .await;
    access.client.telemetry().record_peer_request(
        domain,
        endpoint,
        None,
        started,
        &result,
        |response| response.status,
    );
    let response = result.map_err(|error| {
        access.directories.forget(domain);
        error.to_string()
    })?;
    Ok((response.status, response.body))
}

#[cfg(test)]
#[path = "client_lane_relay_tests.rs"]
mod tests;
