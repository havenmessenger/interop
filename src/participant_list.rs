//! MIMI participant list / AppSync (protocol §5.3 + **§7.5**, conformance R1/R2/M1).
//!
//! Participant-list changes travel as an **AppSync proposal** (`applicationId = mimiParticipantList`),
//! committed before/with the corresponding MLS operation. AppSync is an MLS *custom proposal*
//! (`ProposalType::Custom(u16)`) - an ORDINARY in-group proposal by a member, NOT an external
//! proposal/commit (so INV-MLS-001 is untouched).
//!
//! WIRE FORMAT - **NORMATIVE** (draft-ietf-mimi-protocol §7.5): the participant list IS specified
//! (it is not implementation-defined) - the structs are TLS presentation language and MIMI
//! "uses varints extensively" (`<V>` = QUIC variable-length, RFC 9000), not CBOR and not a
//! fixed-u16 layout. This module encodes the §7.5 structs verbatim.
//!
//!   struct { opaque user<V>; uint32 role_index; } UserRolePair;
//!   struct { UserRolePair participants<V>; } ParticipantListData;          // canonical state (GroupContext)
//!
//!   struct { uint32 user_index; uint32 role_index; } UserindexRolePair;
//!   struct {
//!     UserindexRolePair changedRoleParticipants<V>;
//!     uint32            removedIndices<V>;
//!     UserRolePair      addedParticipants<V>;
//!   } ParticipantListUpdate;                                               // the AppDataUpdate (op=update) patch
//!
//! There is **no per-op type discriminant**: a single update batches role-changes, removes and adds.
//! `removedIndices` / `changedRoleParticipants` reference the `user_index` (position) in the CURRENT
//! `ParticipantListData`; only `addedParticipants` carry the URI (the user is not yet in the list). Apply
//! order is changes → removes → adds-appended (§7.5). A single update MUST NOT touch the same user twice.
//!
//! `<V>` maps to tls_codec `VLBytes` (opaque) and `Vec<T>` (vectors); `uint32` = `u32` BE. Encode composes
//! the tls_codec varint primitives (the canonical varint impl); decode uses the byte-slice `DeserializeBytes`
//! API (fail-closed on trailing bytes). A reference client implementation reproduces these exact
//! bytes; the two encoders are kept in lockstep by the `tls_kat` golden vectors below + a
//! cross-implementation functional livetest.
//!
//! Why it's load-bearing: GROUP interop with a NON-Haven MIMI client needs the roster via AppSync - a
//! foreign client does not parse Haven's URI-in-credential convention. This is the portable primitive.
//! The hub encodes and decodes it in add and remove commits.
//!
//! STILL HAVEN-CHOSEN (not resolved by §7.5): the custom `ProposalType` value `0xF7A0` (IANA/WG
//! registration open) and the credential↔URI binding (BasicCredential-carrying-URI vs X.509
//! IM-URI). SCOPE BOUNDARY: this module is the spec-faithful primitive (structs + codec + apply); storing
//! `ParticipantListData` as a real MLS GroupContext `app_data_dictionary` extension is a flagged follow-on
//! (the live hub mirrors the ordering to compute indices).

use tls_codec::{
    DeserializeBytes, Error as TlsError, Serialize as TlsSerialize, Size as TlsSize, VLBytes,
};

use crate::protocol_wire::{bounded_run_input, MAX_RUN_AGGREGATE_BYTES};
use crate::uri::{MimiKind, MimiUri};

/// The custom MLS `ProposalType` value for `mimiParticipantList` AppSync proposals. HAVEN-CHOSEN pending
/// IANA/WG guidance - §7.5 does not resolve registration for this ProposalType. Picked
/// in the private/experimental high range (0xF000+) to avoid colliding with registered MLS proposal types
/// (Add=0x0001..GroupContextExtensions=0x0007, SelfRemove, Grease 0x0A0A-pattern). A gated wire-format event.
pub const MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE: u16 = 0xF7A0;

/// Reserved role indices (room-policy-04 §3). 0 = non-participant, 1 = banned. Ordinary roles are >= 2.
pub const ROLE_NON_PARTICIPANT: u32 = 0;
pub const ROLE_BANNED: u32 = 1;

// ============================ public model ============================

/// A single Figure-9 roster-change *intent*, addressed by URI (caller-ergonomic). Converted to the
/// index-based normative [`ParticipantListUpdate`] via [`build_update`] against the current state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RosterOp {
    /// Add a user with a role.
    Add { user_uri: String, role_index: u32 },
    /// Remove a user completely.
    Remove { user_uri: String },
    /// Change a user's role.
    SetRole { user_uri: String, role_index: u32 },
}

impl RosterOp {
    fn user_uri(&self) -> &str {
        match self {
            Self::Add { user_uri, .. }
            | Self::Remove { user_uri }
            | Self::SetRole { user_uri, .. } => user_uri,
        }
    }
}

/// §7.5 `UserRolePair { opaque user<V>; uint32 role_index; }` - a member and their role. `user_uri` is the
/// opaque UTF-8 MIMI user URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRolePair {
    pub user_uri: String,
    pub role_index: u32,
}

/// §7.5 `UserindexRolePair { uint32 user_index; uint32 role_index; }` - a position in the current
/// `ParticipantListData.participants` and the new role for that user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserindexRolePair {
    pub user_index: u32,
    pub role_index: u32,
}

/// §7.5 `ParticipantListData { UserRolePair participants<V>; }` - the canonical participant-list state,
/// the `data` field of the participant-list ComponentData in the GroupContext `app_data_dictionary`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParticipantListData {
    pub participants: Vec<UserRolePair>,
}

impl ParticipantListData {
    /// Index of a user URI in the current list, or `None` if absent.
    pub fn index_of(&self, user_uri: &str) -> Option<u32> {
        self.participants
            .iter()
            .position(|p| p.user_uri == user_uri)
            .map(|i| i as u32)
    }
}

/// §7.5 `ParticipantListUpdate` - the AppDataUpdate (op=update) patch. No per-op discriminant: role-changes
/// and removes reference `user_index` in the current [`ParticipantListData`]; adds carry the URI and are
/// appended. Apply order: changes → removes → adds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParticipantListUpdate {
    pub changed_role_participants: Vec<UserindexRolePair>,
    pub removed_indices: Vec<u32>,
    pub added_participants: Vec<UserRolePair>,
}

// ============================ intent → update / apply ============================

/// Typed errors for participant-list construction/validation/codec (`thiserror`
/// per-module enum - the library convention). URI-parse failures surface transparently.
#[derive(Debug, thiserror::Error)]
pub enum ParticipantListError {
    /// A roster-op / added-participant URI did not parse as a MIMI URI.
    #[error(transparent)]
    Uri(#[from] crate::uri::UriError),
    /// A URI parsed but is not a `/u/` (user) URI.
    #[error("{0}")]
    NotUserUri(String),
    /// A §7.5 roster-construction rule was violated (same user twice; add a reserved role; add an
    /// existing member; remove/set-role on a non-member; set the reserved role).
    #[error("{0}")]
    RosterRule(String),
    /// A structural-validation rule was violated (reserved-role assign; duplicate or overlapping index sets).
    #[error("{0}")]
    Structure(String),
    /// An index referenced by an update is out of bounds for the current list.
    #[error("{0}")]
    IndexOutOfBounds(String),
    /// A participant's user URI was not valid UTF-8.
    #[error("participant user is not valid UTF-8")]
    NonUtf8User,
    /// TLS-presentation encoding failed.
    #[error("encode {what}: {detail}")]
    Encode { what: &'static str, detail: String },
    /// TLS-presentation decoding failed.
    #[error("decode {what}: {detail}")]
    Decode { what: &'static str, detail: String },
    /// Trailing bytes after a complete TLS-presentation decode (fail-closed).
    #[error("{0}")]
    TrailingBytes(String),
}

/// Build the normative index-based [`ParticipantListUpdate`] from URI-addressed [`RosterOp`] intents
/// against the current [`ParticipantListData`]. Resolves URI→index for Remove/SetRole (errors if the user
/// is not currently a member), validates user URIs + reserved roles, and enforces §7.5 "no same user twice".
pub fn build_update(
    current: &ParticipantListData,
    ops: &[RosterOp],
) -> Result<ParticipantListUpdate, ParticipantListError> {
    let mut changed = Vec::new();
    let mut removed = Vec::new();
    let mut added: Vec<UserRolePair> = Vec::new();
    // Track every user the update touches (by URI) to reject same-user-twice (§7.5).
    let mut touched: Vec<String> = Vec::new();
    let touch = |uri: &str, touched: &mut Vec<String>| -> Result<(), ParticipantListError> {
        if touched.iter().any(|t| t == uri) {
            return Err(ParticipantListError::RosterRule(format!(
                "participant-list update touches the same user twice: {uri}"
            )));
        }
        touched.push(uri.to_string());
        Ok(())
    };

    for op in ops {
        let uri = op.user_uri();
        let parsed = MimiUri::parse(uri)?;
        if parsed.kind != Some(MimiKind::User) {
            return Err(ParticipantListError::NotUserUri(format!(
                "roster op user_uri must be a user URI: {uri}"
            )));
        }
        match op {
            RosterOp::Add {
                user_uri,
                role_index,
            } => {
                if *role_index == ROLE_NON_PARTICIPANT {
                    return Err(ParticipantListError::RosterRule(
                        "cannot add a user with the reserved non-participant role (0)".to_string(),
                    ));
                }
                if current.index_of(user_uri).is_some() {
                    return Err(ParticipantListError::RosterRule(format!(
                        "cannot add a user already in the participant list: {user_uri}"
                    )));
                }
                touch(user_uri, &mut touched)?;
                added.push(UserRolePair {
                    user_uri: user_uri.clone(),
                    role_index: *role_index,
                });
            }
            RosterOp::Remove { user_uri } => {
                let idx = current.index_of(user_uri).ok_or_else(|| {
                    ParticipantListError::RosterRule(format!(
                        "cannot remove a non-member: {user_uri}"
                    ))
                })?;
                touch(user_uri, &mut touched)?;
                removed.push(idx);
            }
            RosterOp::SetRole {
                user_uri,
                role_index,
            } => {
                if *role_index == ROLE_NON_PARTICIPANT {
                    return Err(ParticipantListError::RosterRule(
                        "cannot set the reserved non-participant role (0); use Remove".to_string(),
                    ));
                }
                let idx = current.index_of(user_uri).ok_or_else(|| {
                    ParticipantListError::RosterRule(format!(
                        "cannot change the role of a non-member: {user_uri}"
                    ))
                })?;
                touch(user_uri, &mut touched)?;
                changed.push(UserindexRolePair {
                    user_index: idx,
                    role_index: *role_index,
                });
            }
        }
    }
    Ok(ParticipantListUpdate {
        changed_role_participants: changed,
        removed_indices: removed,
        added_participants: added,
    })
}

/// Apply a [`ParticipantListUpdate`] to the current [`ParticipantListData`], producing the next state.
/// Order per §7.5: role-changes, then removes (by descending original index so earlier removals don't
/// shift later ones), then adds appended. Fail-closed: every referenced index MUST be in bounds.
pub fn apply_update(
    current: &ParticipantListData,
    u: &ParticipantListUpdate,
) -> Result<ParticipantListData, ParticipantListError> {
    validate_participant_list_update(u)?;
    let n = current.participants.len() as u32;
    for c in &u.changed_role_participants {
        if c.user_index >= n {
            return Err(ParticipantListError::IndexOutOfBounds(format!(
                "changed-role user_index {} out of bounds (len {n})",
                c.user_index
            )));
        }
    }
    for &r in &u.removed_indices {
        if r >= n {
            return Err(ParticipantListError::IndexOutOfBounds(format!(
                "removed index {r} out of bounds (len {n})"
            )));
        }
    }
    let mut participants = current.participants.clone();
    // 1. role changes (indices still valid - no removal/add has happened yet).
    for c in &u.changed_role_participants {
        participants[c.user_index as usize].role_index = c.role_index;
    }
    // 2. removes - descending original index keeps the remaining indices stable.
    let mut rem = u.removed_indices.clone();
    rem.sort_unstable();
    for &idx in rem.iter().rev() {
        participants.remove(idx as usize);
    }
    // 3. adds appended to the end.
    for a in &u.added_participants {
        participants.push(a.clone());
    }
    Ok(ParticipantListData { participants })
}

/// Structural validation of a decoded update (wire-checkable, state-free): added users MUST be MIMI user
/// URIs with a non-reserved role; role-changes MUST not assign role 0; the changed/removed index sets MUST
/// each be unique and disjoint (the wire-level proxy for §7.5 "no same user twice"). Bounds + member
/// existence are checked in [`apply_update`] / [`build_update`] (they need the current state).
pub fn validate_participant_list_update(
    u: &ParticipantListUpdate,
) -> Result<(), ParticipantListError> {
    for a in &u.added_participants {
        let parsed = MimiUri::parse(&a.user_uri)?;
        if parsed.kind != Some(MimiKind::User) {
            return Err(ParticipantListError::NotUserUri(format!(
                "added participant user_uri must be a user URI: {}",
                a.user_uri
            )));
        }
        if a.role_index == ROLE_NON_PARTICIPANT {
            return Err(ParticipantListError::Structure(
                "cannot add a user with the reserved non-participant role (0)".to_string(),
            ));
        }
    }
    for c in &u.changed_role_participants {
        if c.role_index == ROLE_NON_PARTICIPANT {
            return Err(ParticipantListError::Structure(
                "cannot set the reserved non-participant role (0); use a removal".to_string(),
            ));
        }
    }
    // changed indices unique; removed indices unique; the two disjoint (no user touched twice by index).
    let changed_idx: Vec<u32> = u
        .changed_role_participants
        .iter()
        .map(|c| c.user_index)
        .collect();
    if has_dup(&changed_idx) {
        return Err(ParticipantListError::Structure(
            "changedRoleParticipants references the same index twice".to_string(),
        ));
    }
    if has_dup(&u.removed_indices) {
        return Err(ParticipantListError::Structure(
            "removedIndices references the same index twice".to_string(),
        ));
    }
    if changed_idx.iter().any(|i| u.removed_indices.contains(i)) {
        return Err(ParticipantListError::Structure(
            "an index appears in both changedRoleParticipants and removedIndices".to_string(),
        ));
    }
    // Note: addedParticipants had no uniqueness check at all -- two identical
    // added-user entries decoded and validated cleanly, unlike changed/removed which are
    // index-checked above.
    for (i, a) in u.added_participants.iter().enumerate() {
        if u.added_participants[i + 1..]
            .iter()
            .any(|b| b.user_uri == a.user_uri)
        {
            return Err(ParticipantListError::Structure(
                "addedParticipants references the same user twice".to_string(),
            ));
        }
    }
    Ok(())
}

fn has_dup(v: &[u32]) -> bool {
    for (i, a) in v.iter().enumerate() {
        if v[i + 1..].contains(a) {
            return true;
        }
    }
    false
}

// ============================ TLS presentation-language wire codec (private) ============================
//
// `<V>` = QUIC varint (tls_codec VLBytes / Vec<T>); uint32 = u32 BE. Encode via the std-Write `Serialize`
// trait into a buffer; decode via the byte-slice `DeserializeBytes` API. Wire newtypes carry `VLBytes`
// (opaque user<V>) so the field types match §7.5 exactly.

/// Wire form of `UserRolePair { opaque user<V>; uint32 role_index; }`.
#[derive(Debug, Clone)]
struct WireUserRolePair {
    user: VLBytes,
    role_index: u32,
}

impl TlsSize for WireUserRolePair {
    fn tls_serialized_len(&self) -> usize {
        self.user.tls_serialized_len() + self.role_index.tls_serialized_len()
    }
}
impl TlsSerialize for WireUserRolePair {
    fn tls_serialize<W: std::io::Write>(&self, w: &mut W) -> Result<usize, TlsError> {
        Ok(self.user.tls_serialize(w)? + self.role_index.tls_serialize(w)?)
    }
}
impl DeserializeBytes for WireUserRolePair {
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), TlsError> {
        // Bound `user` to its own declared length before decoding it. The blanket
        // `Vec<T>: DeserializeBytes` impl that calls this per element does not bound an element
        // to what remains of the outer run's declared length, so an oversized `user` declaration
        // would otherwise reach tls_codec's short-read debug_assert and panic under `cargo test`
        // (compiled out, so silent, under `--release`). Reuses `bounded_run_input`
        // (`protocol_wire.rs`) rather than a budget check of its own - the outer run's own
        // `bounded_run_input` call already caps the aggregate size any single element can claim.
        let (user_bounded, rest) =
            bounded_run_input(bytes, "WireUserRolePair.user", MAX_RUN_AGGREGATE_BYTES)
                .map_err(|_| TlsError::EndOfStream)?;
        let (user, _tail) = VLBytes::tls_deserialize_bytes(user_bounded)?;
        let (role_index, rest) = u32::tls_deserialize_bytes(rest)?;
        Ok((Self { user, role_index }, rest))
    }
}

/// Wire form of `UserindexRolePair { uint32 user_index; uint32 role_index; }`.
#[derive(Debug, Clone, Copy)]
struct WireUserindexRolePair {
    user_index: u32,
    role_index: u32,
}

impl TlsSize for WireUserindexRolePair {
    fn tls_serialized_len(&self) -> usize {
        self.user_index.tls_serialized_len() + self.role_index.tls_serialized_len()
    }
}
impl TlsSerialize for WireUserindexRolePair {
    fn tls_serialize<W: std::io::Write>(&self, w: &mut W) -> Result<usize, TlsError> {
        Ok(self.user_index.tls_serialize(w)? + self.role_index.tls_serialize(w)?)
    }
}
impl DeserializeBytes for WireUserindexRolePair {
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), TlsError> {
        let (user_index, rest) = u32::tls_deserialize_bytes(bytes)?;
        let (role_index, rest) = u32::tls_deserialize_bytes(rest)?;
        Ok((
            Self {
                user_index,
                role_index,
            },
            rest,
        ))
    }
}

impl From<&UserRolePair> for WireUserRolePair {
    fn from(p: &UserRolePair) -> Self {
        Self {
            user: VLBytes::new(p.user_uri.clone().into_bytes()),
            role_index: p.role_index,
        }
    }
}
impl TryFrom<WireUserRolePair> for UserRolePair {
    type Error = ParticipantListError;
    fn try_from(w: WireUserRolePair) -> Result<Self, ParticipantListError> {
        let user_uri = String::from_utf8(w.user.as_slice().to_vec())
            .map_err(|_| ParticipantListError::NonUtf8User)?;
        Ok(Self {
            user_uri,
            role_index: w.role_index,
        })
    }
}
impl From<&UserindexRolePair> for WireUserindexRolePair {
    fn from(p: &UserindexRolePair) -> Self {
        Self {
            user_index: p.user_index,
            role_index: p.role_index,
        }
    }
}
impl From<WireUserindexRolePair> for UserindexRolePair {
    fn from(w: WireUserindexRolePair) -> Self {
        Self {
            user_index: w.user_index,
            role_index: w.role_index,
        }
    }
}

/// Encode the §7.5 `ParticipantListUpdate` (the AppDataUpdate payload carried in the CustomProposal):
/// three `<V>` vectors concatenated - changedRoleParticipants, removedIndices, addedParticipants.
pub fn encode_participant_list_update(
    u: &ParticipantListUpdate,
) -> Result<Vec<u8>, ParticipantListError> {
    let changed: Vec<WireUserindexRolePair> =
        u.changed_role_participants.iter().map(Into::into).collect();
    let removed: Vec<u32> = u.removed_indices.clone();
    let added: Vec<WireUserRolePair> = u
        .added_participants
        .iter()
        .map(WireUserRolePair::from)
        .collect();
    let mut out = Vec::new();
    changed
        .tls_serialize(&mut out)
        .map_err(|e| ParticipantListError::Encode {
            what: "changed",
            detail: e.to_string(),
        })?;
    removed
        .tls_serialize(&mut out)
        .map_err(|e| ParticipantListError::Encode {
            what: "removed",
            detail: e.to_string(),
        })?;
    added
        .tls_serialize(&mut out)
        .map_err(|e| ParticipantListError::Encode {
            what: "added",
            detail: e.to_string(),
        })?;
    Ok(out)
}

/// Note: the pinned tls_codec 0.4.2's `Vec<T>: DeserializeBytes` does not require the
/// consumed byte count to EXACTLY equal the vector's own declared length -- it stops once the
/// cumulative count reaches or exceeds it, so a final element can overrun the declared boundary
/// and still be accepted (confirmed empirically: a declared 1-byte `changedRoleParticipants<V>`
/// still decoded a real 8-byte `UserindexRolePair` element). Re-encoding the parsed vector and
/// comparing it byte-for-byte against exactly the bytes the declared length claims closes this:
/// a vector that round-trips to different bytes than it was declared as was never valid TLS-PL
/// to begin with, regardless of what the crate's own decoder tolerated.
fn verify_vec_roundtrip<T: TlsSize + TlsSerialize + std::fmt::Debug>(
    parsed: &[T],
    consumed_bytes: &[u8],
    what: &'static str,
) -> Result<(), ParticipantListError> {
    let mut re_encoded = Vec::new();
    parsed
        .tls_serialize(&mut re_encoded)
        .map_err(|e| ParticipantListError::Decode {
            what,
            detail: format!("round-trip re-encode failed: {e}"),
        })?;
    if re_encoded != consumed_bytes {
        return Err(ParticipantListError::Decode {
            what,
            detail: "declared vector length does not match the actual element bytes".into(),
        });
    }
    Ok(())
}

/// Decode + structurally validate a §7.5 `ParticipantListUpdate`. Fail-closed: trailing bytes, a short
/// buffer, a non-UTF-8 user, or a structural-validation failure all error.
pub fn decode_participant_list_update(
    bytes: &[u8],
) -> Result<ParticipantListUpdate, ParticipantListError> {
    // `Vec<T>::tls_deserialize_bytes` is tls_codec's own blanket impl over all
    // three runs below - a single opaque call per run, not a loop this module writes, so a
    // per-element budget can't be interjected. `bounded_run_input` (shared with
    // `protocol_wire.rs`) truncates the input to this run's declared window before the real
    // decode call runs. This closes the nested-overshoot class for `added` (its element
    // type carries a nested `VLBytes` field the blanket impl would otherwise decode against the
    // untruncated remainder); `changed`/`removed` route through the same helper for uniformity
    // even though their fixed-size element types are not independently exposed to it. Not live
    // from mimi-hubd's own HTTP handlers today (confirmed by grep), but public API any consumer
    // decodes a `ParticipantListUpdate` with.
    let (bounded, rest) =
        bounded_run_input(bytes, "changed", MAX_RUN_AGGREGATE_BYTES).map_err(|e| {
            ParticipantListError::Decode {
                what: "changed",
                detail: e.to_string(),
            }
        })?;
    let (changed, _tail) =
        Vec::<WireUserindexRolePair>::tls_deserialize_bytes(bounded).map_err(|e| {
            ParticipantListError::Decode {
                what: "changed",
                detail: e.to_string(),
            }
        })?;
    verify_vec_roundtrip(&changed, &bytes[..bytes.len() - rest.len()], "changed")?;

    let removed_input = rest;
    let (bounded, rest) =
        bounded_run_input(rest, "removed", MAX_RUN_AGGREGATE_BYTES).map_err(|e| {
            ParticipantListError::Decode {
                what: "removed",
                detail: e.to_string(),
            }
        })?;
    let (removed, _tail) =
        Vec::<u32>::tls_deserialize_bytes(bounded).map_err(|e| ParticipantListError::Decode {
            what: "removed",
            detail: e.to_string(),
        })?;
    verify_vec_roundtrip(
        &removed,
        &removed_input[..removed_input.len() - rest.len()],
        "removed",
    )?;

    let added_input = rest;
    let (bounded, rest) =
        bounded_run_input(rest, "added", MAX_RUN_AGGREGATE_BYTES).map_err(|e| {
            ParticipantListError::Decode {
                what: "added",
                detail: e.to_string(),
            }
        })?;
    let (added, _tail) = Vec::<WireUserRolePair>::tls_deserialize_bytes(bounded).map_err(|e| {
        ParticipantListError::Decode {
            what: "added",
            detail: e.to_string(),
        }
    })?;
    verify_vec_roundtrip(
        &added,
        &added_input[..added_input.len() - rest.len()],
        "added",
    )?;
    if !rest.is_empty() {
        return Err(ParticipantListError::TrailingBytes(format!(
            "participant-list update: {} trailing byte(s)",
            rest.len()
        )));
    }
    let update = ParticipantListUpdate {
        changed_role_participants: changed.into_iter().map(Into::into).collect(),
        removed_indices: removed,
        added_participants: added
            .into_iter()
            .map(UserRolePair::try_from)
            .collect::<Result<Vec<_>, ParticipantListError>>()?,
    };
    validate_participant_list_update(&update)?;
    Ok(update)
}

/// Encode the §7.5 `ParticipantListData` (the canonical state - `UserRolePair participants<V>`).
pub fn encode_participant_list_data(
    d: &ParticipantListData,
) -> Result<Vec<u8>, ParticipantListError> {
    let participants: Vec<WireUserRolePair> =
        d.participants.iter().map(WireUserRolePair::from).collect();
    let mut out = Vec::new();
    participants
        .tls_serialize(&mut out)
        .map_err(|e| ParticipantListError::Encode {
            what: "participant list data",
            detail: e.to_string(),
        })?;
    Ok(out)
}

/// Decode the §7.5 `ParticipantListData`. Fail-closed on trailing bytes / non-UTF-8 users.
pub fn decode_participant_list_data(
    bytes: &[u8],
) -> Result<ParticipantListData, ParticipantListError> {
    // Same nested-overshoot exposure as `added` above (`WireUserRolePair` carries
    // a nested `VLBytes` field) - bound the input to the declared window before decoding it.
    let (bounded, rest) =
        bounded_run_input(bytes, "participant list data", MAX_RUN_AGGREGATE_BYTES).map_err(
            |e| ParticipantListError::Decode {
                what: "participant list data",
                detail: e.to_string(),
            },
        )?;
    let (participants, _tail) =
        Vec::<WireUserRolePair>::tls_deserialize_bytes(bounded).map_err(|e| {
            ParticipantListError::Decode {
                what: "participant list data",
                detail: e.to_string(),
            }
        })?;
    if !rest.is_empty() {
        return Err(ParticipantListError::TrailingBytes(format!(
            "participant-list data: {} trailing byte(s)",
            rest.len()
        )));
    }
    Ok(ParticipantListData {
        participants: participants
            .into_iter()
            .map(UserRolePair::try_from)
            .collect::<Result<Vec<_>, ParticipantListError>>()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_data() -> ParticipantListData {
        ParticipantListData {
            participants: vec![
                UserRolePair {
                    user_uri: "mimi://mimi.havenmessenger.com/u/alice".into(),
                    role_index: 2,
                },
                UserRolePair {
                    user_uri: "mimi://mimi-b.havenmessenger.com/u/bob".into(),
                    role_index: 2,
                },
                UserRolePair {
                    user_uri: "mimi://mimi.havenmessenger.com/u/carol".into(),
                    role_index: 2,
                },
            ],
        }
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    fn tohex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn build_update_resolves_uris_to_indices() {
        let data = sample_data();
        let u = build_update(
            &data,
            &[
                RosterOp::SetRole {
                    user_uri: "mimi://mimi-b.havenmessenger.com/u/bob".into(),
                    role_index: 3,
                },
                RosterOp::Remove {
                    user_uri: "mimi://mimi.havenmessenger.com/u/carol".into(),
                },
                RosterOp::Add {
                    user_uri: "mimi://mimi.havenmessenger.com/u/dave".into(),
                    role_index: 2,
                },
            ],
        )
        .unwrap();
        assert_eq!(
            u.changed_role_participants,
            vec![UserindexRolePair {
                user_index: 1,
                role_index: 3
            }]
        );
        assert_eq!(u.removed_indices, vec![2]);
        assert_eq!(
            u.added_participants,
            vec![UserRolePair {
                user_uri: "mimi://mimi.havenmessenger.com/u/dave".into(),
                role_index: 2
            }]
        );
    }

    #[test]
    fn build_update_rejects_non_member_and_same_user_twice() {
        let data = sample_data();
        assert!(build_update(
            &data,
            &[RosterOp::Remove {
                user_uri: "mimi://h/u/ghost".into()
            }]
        )
        .is_err());
        assert!(build_update(
            &data,
            &[
                RosterOp::Remove {
                    user_uri: "mimi://mimi.havenmessenger.com/u/carol".into()
                },
                RosterOp::SetRole {
                    user_uri: "mimi://mimi.havenmessenger.com/u/carol".into(),
                    role_index: 3
                },
            ],
        )
        .is_err());
    }

    #[test]
    fn apply_update_changes_then_removes_then_adds() {
        let data = sample_data();
        // change alice→3, remove bob+carol (indices 1,2), add dave.
        let u = ParticipantListUpdate {
            changed_role_participants: vec![UserindexRolePair {
                user_index: 0,
                role_index: 3,
            }],
            removed_indices: vec![1, 2],
            added_participants: vec![UserRolePair {
                user_uri: "mimi://h/u/dave".into(),
                role_index: 2,
            }],
        };
        let next = apply_update(&data, &u).unwrap();
        assert_eq!(next.participants.len(), 2);
        assert_eq!(
            next.participants[0].user_uri,
            "mimi://mimi.havenmessenger.com/u/alice"
        );
        assert_eq!(next.participants[0].role_index, 3, "alice's role changed");
        assert_eq!(
            next.participants[1].user_uri, "mimi://h/u/dave",
            "dave appended"
        );
    }

    #[test]
    fn apply_update_rejects_out_of_bounds() {
        let data = sample_data();
        let u = ParticipantListUpdate {
            removed_indices: vec![9],
            ..Default::default()
        };
        assert!(
            apply_update(&data, &u).is_err(),
            "out-of-bounds removal rejected"
        );
    }

    #[test]
    fn update_roundtrip_and_deterministic() {
        let u = build_update(
            &sample_data(),
            &[
                RosterOp::SetRole {
                    user_uri: "mimi://mimi-b.havenmessenger.com/u/bob".into(),
                    role_index: 3,
                },
                RosterOp::Remove {
                    user_uri: "mimi://mimi.havenmessenger.com/u/carol".into(),
                },
                RosterOp::Add {
                    user_uri: "mimi://mimi.havenmessenger.com/u/dave".into(),
                    role_index: 2,
                },
            ],
        )
        .unwrap();
        let a = encode_participant_list_update(&u).unwrap();
        let b = encode_participant_list_update(&u).unwrap();
        assert_eq!(a, b, "deterministic");
        assert_eq!(decode_participant_list_update(&a).unwrap(), u, "round-trip");
    }

    #[test]
    fn data_roundtrip() {
        let d = sample_data();
        let bytes = encode_participant_list_data(&d).unwrap();
        assert_eq!(decode_participant_list_data(&bytes).unwrap(), d);
    }

    /// Proves the pre-check is actually wired into `decode_participant_list_data`,
    /// not just tested in isolation on `bounded_run_input`/`protocol_wire.rs`. A declared
    /// length past the shared budget, with no body bytes following at all - the reject must
    /// happen before this decoder would need that body.
    #[test]
    fn decode_participant_list_data_rejects_over_budget_declared_length() {
        let mut bytes = Vec::new();
        tls_codec::vlen::write_length(&mut bytes, MAX_RUN_AGGREGATE_BYTES + 1).unwrap();
        let err = decode_participant_list_data(&bytes)
            .expect_err("an over-budget declared length must be rejected");
        assert!(matches!(err, ParticipantListError::Decode { .. }));
    }

    /// A nested-overshoot shape at the `added` site: an outer run declaring length 1 (far too
    /// small for any real element), immediately followed by one real, well-formed
    /// `WireUserRolePair` element whose `user` field is a large `VLBytes`.
    /// `WireUserRolePair` is the vulnerable shape: `Vec<WireUserRolePair>` is decoded via
    /// `tls_codec`'s blanket impl, and that impl decodes each element against whatever slice it
    /// is given, not against this run's declared length. `verify_vec_roundtrip` alone does not
    /// catch this (it re-encodes whatever was actually consumed and compares against those same
    /// consumed bytes, which trivially match); `bounded_run_input` truncating the input to the
    /// declared 1 byte first is what actually closes it - the inner element's own length prefix
    /// cannot be fully read inside that window, so the whole decode fails closed.
    #[test]
    fn decode_participant_list_update_rejects_nested_oversized_added_element_before_the_big_clone()
    {
        let mut real_element = Vec::new();
        VLBytes::new(vec![0xAAu8; 4096])
            .tls_serialize(&mut real_element)
            .unwrap();
        real_element.extend_from_slice(&0u32.to_be_bytes()); // role_index

        let mut bytes = Vec::new();
        tls_codec::vlen::write_length(&mut bytes, 0).unwrap(); // changed: empty
        tls_codec::vlen::write_length(&mut bytes, 0).unwrap(); // removed: empty
        tls_codec::vlen::write_length(&mut bytes, 1).unwrap(); // added declares "1 byte" - a lie
        bytes.extend_from_slice(&real_element);

        let err = decode_participant_list_update(&bytes).expect_err(
            "an outer declared length of 1 must not let a 4096-byte inner element through",
        );
        assert!(matches!(err, ParticipantListError::Decode { .. }));
    }

    /// Same class as `added` above, for `decode_participant_list_data`'s `participants` run.
    #[test]
    fn decode_participant_list_data_rejects_nested_oversized_participant_element_before_the_big_clone(
    ) {
        let mut real_element = Vec::new();
        VLBytes::new(vec![0xAAu8; 4096])
            .tls_serialize(&mut real_element)
            .unwrap();
        real_element.extend_from_slice(&0u32.to_be_bytes());

        let mut bytes = Vec::new();
        tls_codec::vlen::write_length(&mut bytes, 1).unwrap(); // declares "1 byte" - a lie
        bytes.extend_from_slice(&real_element);

        let err = decode_participant_list_data(&bytes).expect_err(
            "an outer declared length of 1 must not let a 4096-byte inner element through",
        );
        assert!(matches!(err, ParticipantListError::Decode { .. }));
    }

    /// A distinct shape from the test above: an outer declared length
    /// of 1 truncates `user`'s own length prefix before it can even be read in full. This test
    /// uses an outer declared length that exactly fits a real, complete `user` length prefix (2
    /// bytes for a QUIC varint declaring 4096) but leaves zero payload bytes for it - the prefix
    /// reads successfully, then tls_codec tries to clone 4096 payload bytes it does not have.
    /// Before `WireUserRolePair::tls_deserialize_bytes` bounded `user` internally, this reached
    /// tls_codec's short-read `debug_assert_eq!` and panicked under `cargo test` (compiled out,
    /// so silent, under `--release`).
    #[test]
    fn decode_participant_list_update_rejects_added_element_whose_user_prefix_reads_but_overshoots_its_own_payload(
    ) {
        let mut user_prefix = Vec::new();
        tls_codec::vlen::write_length(&mut user_prefix, 4096).unwrap();
        assert_eq!(user_prefix.len(), 2, "this proof needs a full 2-byte prefix, not a 1-byte one the outer window would truncate before it can be read");

        let mut bytes = Vec::new();
        tls_codec::vlen::write_length(&mut bytes, 0).unwrap(); // changed: empty
        tls_codec::vlen::write_length(&mut bytes, 0).unwrap(); // removed: empty
        tls_codec::vlen::write_length(&mut bytes, user_prefix.len()).unwrap(); // added: exactly 2 bytes
        bytes.extend_from_slice(&user_prefix); // the full user prefix, zero payload bytes for it

        let err = decode_participant_list_update(&bytes).expect_err(
            "a user prefix declaring more payload than the outer window has left must be rejected, not panic",
        );
        assert!(matches!(err, ParticipantListError::Decode { .. }));
    }

    /// The same 8-byte varint form `protocol_wire.rs`'s
    /// `bounded_run_input_rejects_the_8_byte_varint_form_before_calling_tls_codec` proves at the
    /// unit level, exercised through this crate's other bounded chokepoint -
    /// `WireUserRolePair::tls_deserialize_bytes`'s own bounding of its `user` field.
    #[test]
    fn decode_participant_list_update_rejects_the_8_byte_varint_form_in_added_user() {
        let mut bytes = Vec::new();
        tls_codec::vlen::write_length(&mut bytes, 0).unwrap(); // changed: empty
        tls_codec::vlen::write_length(&mut bytes, 0).unwrap(); // removed: empty
        tls_codec::vlen::write_length(&mut bytes, 8).unwrap(); // added: 8 bytes, enough to hold the form below
        bytes.push(0xC0); // user: 8-byte varint form selector
        bytes.extend_from_slice(&[0u8; 7]);

        let err = decode_participant_list_update(&bytes)
            .expect_err("the 8-byte varint form in added[].user must be rejected, not panic");
        assert!(matches!(err, ParticipantListError::Decode { .. }));
    }

    /// Same class as above, for `decode_participant_list_data`'s `participants` run.
    #[test]
    fn decode_participant_list_data_rejects_participant_element_whose_user_prefix_reads_but_overshoots_its_own_payload(
    ) {
        let mut user_prefix = Vec::new();
        tls_codec::vlen::write_length(&mut user_prefix, 4096).unwrap();

        let mut bytes = Vec::new();
        tls_codec::vlen::write_length(&mut bytes, user_prefix.len()).unwrap();
        bytes.extend_from_slice(&user_prefix);

        let err = decode_participant_list_data(&bytes).expect_err(
            "a user prefix declaring more payload than the outer window has left must be rejected, not panic",
        );
        assert!(matches!(err, ParticipantListError::Decode { .. }));
    }

    /// Golden vectors (TLS presentation language, §7.5) - the cross-implementation pin. Any
    /// reference client implementation MUST reproduce these exact bytes. `<V>` = QUIC varint; uint32 = BE.
    /// URI "mimi://h/u/a" = 12 bytes = 6d696d693a2f2f682f752f61 (varint len 0x0c).
    #[test]
    fn tls_kat() {
        let uri = "mimi://h/u/a";
        // Add(role=2): changed<V>=empty(00) removed<V>=empty(00) added<V>= [varint(17)=11][user: 0c+12B][role u32=00000002]
        let add = ParticipantListUpdate {
            added_participants: vec![UserRolePair {
                user_uri: uri.into(),
                role_index: 2,
            }],
            ..Default::default()
        };
        let want_add = "0000110c6d696d693a2f2f682f752f6100000002";
        assert_eq!(
            tohex(&encode_participant_list_update(&add).unwrap()),
            want_add,
            "Add KAT"
        );

        // Remove(index 0): changed=empty(00) removed<V>=[varint(4)=04][u32 idx=00000000] added=empty(00)
        let rem = ParticipantListUpdate {
            removed_indices: vec![0],
            ..Default::default()
        };
        let want_rem = "00040000000000";
        assert_eq!(
            tohex(&encode_participant_list_update(&rem).unwrap()),
            want_rem,
            "Remove KAT"
        );

        // SetRole(index 0, role 3): changed<V>=[varint(8)=08][idx u32=00000000][role u32=00000003] removed=00 added=00
        let sr = ParticipantListUpdate {
            changed_role_participants: vec![UserindexRolePair {
                user_index: 0,
                role_index: 3,
            }],
            ..Default::default()
        };
        let want_sr = "0800000000000000030000";
        assert_eq!(
            tohex(&encode_participant_list_update(&sr).unwrap()),
            want_sr,
            "SetRole KAT"
        );

        for u in [&add, &rem, &sr] {
            assert_eq!(
                decode_participant_list_update(&encode_participant_list_update(u).unwrap())
                    .unwrap(),
                *u
            );
        }
    }

    #[test]
    fn decode_rejects_malformed() {
        // trailing data after a complete (empty) update → fail-closed.
        let mut trailing = unhex("000000");
        trailing.push(0xff);
        assert!(
            decode_participant_list_update(&trailing).is_err(),
            "trailing data rejected"
        );
        // a short buffer (claims a removed vec of 4 bytes but provides 2) → EndOfStream.
        assert!(
            decode_participant_list_update(&unhex("00040000")).is_err(),
            "short buffer rejected"
        );
        assert!(
            decode_participant_list_update(b"").is_err(),
            "empty buffer rejected (needs 3 vectors)"
        );
    }

    #[test]
    fn decode_rejects_short_declared_length_with_full_element_bytes() {
        // changedRoleParticipants<V> declares length=1 but the bytes that follow are a full
        // 8-byte UserindexRolePair (user_index=0, role_index=2).
        // A naive decoder would accept this (tls_codec's Vec<T> stops once cumulative consumed
        // >= declared, not ==); this must be rejected.
        let bytes: &[u8] = &[
            0x01, // changed_role_participants<V> declared length = 1 (wrong; a pair needs 8)
            0x00, 0x00, 0x00, 0x00, // user_index = 0
            0x00, 0x00, 0x00, 0x02, // role_index = 2
            0x00, // removed_indices<V> = empty
            0x00, // added_participants<V> = empty
        ];
        assert!(decode_participant_list_update(bytes).is_err());
    }

    #[test]
    fn validate_rejects_duplicate_added_user() {
        // Note: two identical added-user entries must not survive validation.
        let dup = ParticipantListUpdate {
            changed_role_participants: Vec::new(),
            removed_indices: Vec::new(),
            added_participants: vec![
                UserRolePair {
                    user_uri: "mimi://mimi.havenmessenger.com/u/alice".into(),
                    role_index: 2,
                },
                UserRolePair {
                    user_uri: "mimi://mimi.havenmessenger.com/u/alice".into(),
                    role_index: 2,
                },
            ],
        };
        assert!(validate_participant_list_update(&dup).is_err());
    }

    #[test]
    fn validate_rejects_non_user_uri_reserved_role_and_double_touch() {
        // room URI as an added member
        let bad_uri = ParticipantListUpdate {
            added_participants: vec![UserRolePair {
                user_uri: "mimi://h/r/room".into(),
                role_index: 2,
            }],
            ..Default::default()
        };
        assert!(
            validate_participant_list_update(&bad_uri).is_err(),
            "room URI as member rejected"
        );
        // reserved role on add
        let reserved = ParticipantListUpdate {
            added_participants: vec![UserRolePair {
                user_uri: "mimi://h/u/a".into(),
                role_index: ROLE_NON_PARTICIPANT,
            }],
            ..Default::default()
        };
        assert!(
            validate_participant_list_update(&reserved).is_err(),
            "role 0 rejected"
        );
        // same index changed and removed
        let double = ParticipantListUpdate {
            changed_role_participants: vec![UserindexRolePair {
                user_index: 1,
                role_index: 3,
            }],
            removed_indices: vec![1],
            ..Default::default()
        };
        assert!(
            validate_participant_list_update(&double).is_err(),
            "index in both changed+removed rejected"
        );
    }

    // ---- R1/R2: the AppSync custom-proposal round-trip against REAL openmls ----
    //
    // The C4 empirical proof: a mimiParticipantList payload travels as an MLS custom proposal carried IN a
    // commit (R1), the RECEIVING member's process_message surfaces it via the staged commit's
    // queued_proposals, and a roster Remove can ride in the SAME commit as the MLS Remove (R2 atomicity).
    // Re-modeled to the §7.5 wire format (Add via addedParticipants; Remove via removedIndices).

    use openmls::ciphersuite::signature::SignaturePublicKey;
    use openmls::credentials::{BasicCredential, CredentialWithKey};
    use openmls::prelude::*;
    use openmls_rust_crypto::OpenMlsRustCrypto;
    use openmls_traits::signatures::{Signer, SignerError};
    use openmls_traits::OpenMlsProvider;
    // std Read-based Deserialize for the openmls MlsMessageIn round-trip helpers (the codec above uses the
    // byte-slice DeserializeBytes API, so this trait isn't imported at module top).
    use tls_codec::Deserialize as _;

    fn welcome_in(out: MlsMessageOut) -> Welcome {
        let bytes = out.tls_serialize_detached().unwrap();
        match MlsMessageIn::tls_deserialize(&mut bytes.as_slice())
            .unwrap()
            .extract()
        {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => panic!("not a welcome"),
        }
    }

    fn protocol_in(out: MlsMessageOut) -> ProtocolMessage {
        let bytes = out.tls_serialize_detached().unwrap();
        let msg_in = MlsMessageIn::tls_deserialize(&mut bytes.as_slice()).unwrap();
        ProtocolMessage::try_from(msg_in).unwrap()
    }

    const AES: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    struct TestSigner {
        key: Vec<u8>,
        scheme: SignatureScheme,
    }
    impl Signer for TestSigner {
        fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
            OpenMlsRustCrypto::default()
                .crypto()
                .sign(self.scheme, payload, &self.key)
                .map_err(|_| SignerError::SigningError)
        }
        fn signature_scheme(&self) -> SignatureScheme {
            self.scheme
        }
    }

    fn caps() -> Capabilities {
        Capabilities::new(
            None,
            Some(&[AES]),
            None,
            Some(&[ProposalType::Custom(MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE)]),
            None,
        )
    }

    fn ident(user: &str) -> (TestSigner, CredentialWithKey, OpenMlsRustCrypto) {
        let provider = OpenMlsRustCrypto::default();
        let scheme = SignatureScheme::ED25519;
        let (priv_b, pub_b) = provider.crypto().signature_key_gen(scheme).unwrap();
        let pk = SignaturePublicKey::try_from(pub_b).unwrap();
        let cwk = CredentialWithKey {
            credential: BasicCredential::new(user.as_bytes().to_vec()).into(),
            signature_key: pk,
        };
        (
            TestSigner {
                key: priv_b,
                scheme,
            },
            cwk,
            provider,
        )
    }

    fn keypackage(
        signer: &TestSigner,
        cwk: &CredentialWithKey,
        provider: &OpenMlsRustCrypto,
    ) -> KeyPackage {
        KeyPackage::builder()
            .leaf_node_capabilities(caps())
            .build(AES, provider, signer, cwk.clone())
            .unwrap()
            .key_package()
            .clone()
    }

    /// Find a mimiParticipantList custom proposal in a staged commit and decode its payload.
    fn extract_roster(staged: &StagedCommit) -> Option<ParticipantListUpdate> {
        for qp in staged.queued_proposals() {
            if let Proposal::Custom(c) = qp.proposal() {
                if c.proposal_type() == MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE {
                    return Some(decode_participant_list_update(c.payload()).unwrap());
                }
            }
        }
        None
    }

    #[test]
    fn appsync_custom_proposal_round_trips_through_a_commit_r1() {
        let (asig, acwk, aprov) = ident("alice");
        let (bsig, bcwk, bprov) = ident("bob");
        let cfg = MlsGroupCreateConfig::builder()
            .capabilities(caps())
            .ciphersuite(AES)
            .use_ratchet_tree_extension(true)
            .build();
        let mut alice = MlsGroup::new(&aprov, &asig, &cfg, acwk).unwrap();
        let bob_kp = keypackage(&bsig, &bcwk, &bprov);
        let (_c, welcome, _gi) = alice.add_members(&aprov, &asig, &[bob_kp]).unwrap();
        alice.merge_pending_commit(&aprov).unwrap();
        let welcome = welcome_in(welcome);
        let mut bob = StagedWelcome::new_from_welcome(&bprov, cfg.join_config(), welcome, None)
            .unwrap()
            .into_group(&bprov)
            .unwrap();

        // alice proposes a mimiParticipantList AppSync Add (carol) - §7.5 addedParticipants - then commits.
        let update = ParticipantListUpdate {
            added_participants: vec![UserRolePair {
                user_uri: "mimi://mimi.havenmessenger.com/u/carol".into(),
                role_index: 2,
            }],
            ..Default::default()
        };
        let payload = encode_participant_list_update(&update).unwrap();
        let custom = CustomProposal::new(MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE, payload);
        alice
            .propose_custom_proposal_by_value(&aprov, &asig, custom)
            .unwrap();
        let (commit, _w, _gi) = alice.commit_to_pending_proposals(&aprov, &asig).unwrap();
        alice.merge_pending_commit(&aprov).unwrap();

        let commit_in = protocol_in(commit);
        let processed = bob.process_message(&bprov, commit_in).unwrap();
        match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                let roster = extract_roster(&staged)
                    .expect("mimiParticipantList custom proposal must surface on the receiver");
                assert_eq!(
                    roster, update,
                    "receiver decodes the exact roster update (R1 proven)"
                );
                bob.merge_staged_commit(&bprov, *staged).unwrap();
            }
            other => panic!("expected a staged commit, got {other:?}"),
        }
    }

    #[test]
    fn roster_remove_rides_with_the_mls_remove_in_one_commit_r2() {
        let (asig, acwk, aprov) = ident("alice");
        let (bsig, bcwk, bprov) = ident("bob");
        let (csig, ccwk, cprov) = ident("carol");
        let cfg = MlsGroupCreateConfig::builder()
            .capabilities(caps())
            .ciphersuite(AES)
            .use_ratchet_tree_extension(true)
            .build();
        let mut alice = MlsGroup::new(&aprov, &asig, &cfg, acwk).unwrap();
        let bob_kp = keypackage(&bsig, &bcwk, &bprov);
        let carol_kp = keypackage(&csig, &ccwk, &cprov);
        let (_c, welcome, _gi) = alice
            .add_members(&aprov, &asig, &[bob_kp, carol_kp])
            .unwrap();
        alice.merge_pending_commit(&aprov).unwrap();
        let welcome = welcome_in(welcome);
        let mut bob = StagedWelcome::new_from_welcome(&bprov, cfg.join_config(), welcome, None)
            .unwrap()
            .into_group(&bprov)
            .unwrap();

        let carol_idx = alice
            .members()
            .find(|m| m.credential.serialized_content() == b"carol")
            .map(|m| m.index)
            .expect("carol is a member");

        // §7.5 Remove via removedIndices. The roster's canonical ParticipantListData here is [alice,bob,carol]
        // → carol is index 2 (build_update resolves the URI against that state).
        let roster_state = ParticipantListData {
            participants: vec![
                UserRolePair {
                    user_uri: "mimi://mimi.havenmessenger.com/u/alice".into(),
                    role_index: 2,
                },
                UserRolePair {
                    user_uri: "mimi://mimi.havenmessenger.com/u/bob".into(),
                    role_index: 2,
                },
                UserRolePair {
                    user_uri: "mimi://mimi.havenmessenger.com/u/carol".into(),
                    role_index: 2,
                },
            ],
        };
        let update = build_update(
            &roster_state,
            &[RosterOp::Remove {
                user_uri: "mimi://mimi.havenmessenger.com/u/carol".into(),
            }],
        )
        .unwrap();
        assert_eq!(update.removed_indices, vec![2], "carol resolves to index 2");
        let custom = CustomProposal::new(
            MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE,
            encode_participant_list_update(&update).unwrap(),
        );
        alice
            .propose_custom_proposal_by_value(&aprov, &asig, custom)
            .unwrap();
        let (remove_msg, _ref) = alice
            .propose_remove_member(&aprov, &asig, carol_idx)
            .unwrap();
        let remove_in = protocol_in(remove_msg);
        let pr = bob.process_message(&bprov, remove_in).unwrap();
        match pr.into_content() {
            ProcessedMessageContent::ProposalMessage(p) => {
                bob.store_pending_proposal(bprov.storage(), *p).unwrap()
            }
            other => panic!("expected a proposal message, got {other:?}"),
        }
        let (commit, _w, _gi) = alice.commit_to_pending_proposals(&aprov, &asig).unwrap();
        alice.merge_pending_commit(&aprov).unwrap();

        let commit_in = protocol_in(commit);
        let processed = bob.process_message(&bprov, commit_in).unwrap();
        match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                let roster = extract_roster(&staged).expect("roster Remove present");
                assert_eq!(roster, update);
                let has_mls_remove = staged.remove_proposals().count() == 1;
                assert!(
                    has_mls_remove,
                    "the MLS Remove rides in the same commit as the roster Remove (R2)"
                );
                bob.merge_staged_commit(&bprov, *staged).unwrap();
            }
            other => panic!("expected a staged commit, got {other:?}"),
        }
        assert!(
            !bob.members()
                .any(|m| m.credential.serialized_content() == b"carol"),
            "carol removed after the combined commit"
        );
    }
}
