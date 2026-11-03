//! The room-policy-04 components a hub reads off an AppDataUpdate, in the draft's TLS presentation language:
//! `roles_list` (§3, `RoleData`) and `base_room_policy` (§5, `BaseRoomPolicy`).
//!
//! protocol-07 §5.3 sends a change to the room policy as an AppDataUpdate for the room policy components, and the
//! `update` of a component is the value that replaces it. This module decodes those two values and encodes them for
//! tests and vectors. Everything decoded from a peer is bounded before it is allocated, and a value that does not parse
//! to its last byte, or breaks a rule of the draft that a decoder can check, is refused.
//!
//! The hub enforces six capabilities and a handful of base fields (see [`crate::room_policy`]); the rest of a role and of
//! the base policy is read for its shape and not kept. The mapping is [`capability_from_wire`] and the fields that are
//! kept are listed on [`decode_role_data`] and [`decode_base_room_policy`].

use tls_codec::VLBytes;

use crate::protocol_wire::{bounded_run_input, MAX_RUN_AGGREGATE_BYTES};
use crate::room_policy::{
    BaseRoomPolicy, Capability, Role, RoomPolicyError, SingleSourceRoleChangeTargets,
};

/// The component id room-policy-04 §10.1.2 suggests for `roles_list` (not yet registered).
pub const ROLES_LIST_COMPONENT_ID: u16 = 0x0025;
/// The component id room-policy-04 §10.1.4 suggests for `base_room_policy` (not yet registered).
pub const BASE_ROOM_POLICY_COMPONENT_ID: u16 = 0x0027;

/// Most roles one list may hold.
pub const MAX_ROLES: usize = 256;
/// Most capabilities one role may list.
const MAX_CAPABILITIES: usize = 512;
/// Most `authorized_role_changes` entries one role may hold, and most targets one entry may hold.
const MAX_TRANSITIONS: usize = 256;
const MAX_TARGETS: usize = 256;
/// Longest role name, role description and parent room URI, in octets.
const MAX_TEXT: usize = 1024;
/// Most component ids a base policy may list.
const MAX_COMPONENT_IDS: usize = 256;

/// room-policy-04 §10.2 capability values for the capabilities the hub enforces.
const CAN_ADD_PARTICIPANT: u16 = 0x0000;
const CAN_REMOVE_PARTICIPANT: u16 = 0x0001;
const CAN_BAN: u16 = 0x000a;
const CAN_KICK: u16 = 0x000c;
const CAN_CHANGE_USER_ROLE: u16 = 0x000f;
const CAN_SEND_MESSAGE: u16 = 0x0100;

/// The hub's capability for a registry value, or `None` for a capability it does not enforce. The registry has about
/// eighty values (uploads, calls, room attributes and more) and is open to additions; those are for clients, and a role
/// that lists them keeps its place in the list with only the six below carried.
pub const fn capability_from_wire(value: u16) -> Option<Capability> {
    match value {
        CAN_ADD_PARTICIPANT => Some(Capability::AddParticipant),
        CAN_REMOVE_PARTICIPANT => Some(Capability::RemoveParticipant),
        CAN_BAN => Some(Capability::Ban),
        CAN_KICK => Some(Capability::Kick),
        CAN_CHANGE_USER_ROLE => Some(Capability::ChangeRole),
        CAN_SEND_MESSAGE => Some(Capability::SendMessage),
        _ => None,
    }
}

/// The registry value of one of the hub's capabilities.
pub const fn capability_to_wire(capability: Capability) -> u16 {
    match capability {
        Capability::AddParticipant => CAN_ADD_PARTICIPANT,
        Capability::RemoveParticipant => CAN_REMOVE_PARTICIPANT,
        Capability::Ban => CAN_BAN,
        Capability::Kick => CAN_KICK,
        Capability::ChangeRole => CAN_CHANGE_USER_ROLE,
        Capability::SendMessage => CAN_SEND_MESSAGE,
    }
}

fn refuse(what: &'static str, detail: impl std::fmt::Display) -> RoomPolicyError {
    RoomPolicyError::Wire(format!("{what}: {detail}"))
}

/// A cursor over bytes that are all peer-controlled: nothing is read past what was declared.
struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    const fn new(rest: &'a [u8]) -> Self {
        Self { rest }
    }

    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], RoomPolicyError> {
        if self.rest.len() < n {
            return Err(refuse(
                what,
                format!("needs {n} bytes, {} left", self.rest.len()),
            ));
        }
        let (head, tail) = self.rest.split_at(n);
        self.rest = tail;
        Ok(head)
    }

    fn u16(&mut self, what: &'static str) -> Result<u16, RoomPolicyError> {
        let b = self.take(2, what)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self, what: &'static str) -> Result<u32, RoomPolicyError> {
        let b = self.take(4, what)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// `bool`: one octet, 0 or 1.
    fn flag(&mut self, what: &'static str) -> Result<bool, RoomPolicyError> {
        match self.take(1, what)?[0] {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(refuse(what, format!("expected 0 or 1, got {other}"))),
        }
    }

    /// `optional uint32`: a presence octet, then the value when present.
    fn optional_u32(&mut self, what: &'static str) -> Result<Option<u32>, RoomPolicyError> {
        if self.flag(what)? {
            Ok(Some(self.u32(what)?))
        } else {
            Ok(None)
        }
    }

    /// A `<V>` run: its content, as a reader of its own, bounded by the declared length before anything is read.
    fn run(&mut self, what: &'static str, limit: usize) -> Result<Self, RoomPolicyError> {
        let (bounded, rest) =
            bounded_run_input(self.rest, what, limit.min(MAX_RUN_AGGREGATE_BYTES))
                .map_err(|e| refuse(what, e))?;
        let mut cursor = bounded;
        let (length, _prefix) =
            tls_codec::vlen::read_length(&mut cursor).map_err(|e| refuse(what, e))?;
        if cursor.len() != length {
            return Err(refuse(what, "the declared length is not the run's length"));
        }
        self.rest = rest;
        Ok(Reader { rest: cursor })
    }

    /// `opaque x<V>`: the bytes.
    fn opaque(&mut self, what: &'static str, limit: usize) -> Result<&'a [u8], RoomPolicyError> {
        let bytes = self.run(what, limit)?.rest;
        if bytes.len() > limit {
            return Err(refuse(
                what,
                format!("{} octets, at most {limit}", bytes.len()),
            ));
        }
        Ok(bytes)
    }

    fn text(&mut self, what: &'static str) -> Result<String, RoomPolicyError> {
        let bytes = self.opaque(what, MAX_TEXT)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| refuse(what, "not valid UTF-8"))
    }

    fn done(&self, what: &'static str) -> Result<(), RoomPolicyError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(refuse(what, format!("{} trailing octets", self.rest.len())))
        }
    }

    const fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }
}

/// Decode a `RoleData` (the `roles_list` component and its update, which has the same shape) into the roles the hub
/// enforces.
///
/// Kept: `role_index`, `role_name`, the capabilities the hub enforces ([`capability_from_wire`]; the rest are read and
/// dropped, and a capability listed twice counts once) and `authorized_role_changes`. Read and not kept: the
/// description and the four participant-count constraints. A role is refused when its minimum participant count
/// exceeds its maximum (or the active ones do), and the list when a `role_index` repeats; the reserved and dangling
/// index rules of [`crate::room_policy::RoomPolicy::validate`] apply when the roles are put into a policy.
pub fn decode_role_data(bytes: &[u8]) -> Result<Vec<Role>, RoomPolicyError> {
    const WHAT: &str = "RoleData";
    let mut top = Reader::new(bytes);
    let mut run = top.run("RoleData.roles", MAX_RUN_AGGREGATE_BYTES)?;
    top.done(WHAT)?;
    let mut roles: Vec<Role> = Vec::new();
    while !run.is_empty() {
        if roles.len() >= MAX_ROLES {
            return Err(refuse(WHAT, format!("more than {MAX_ROLES} roles")));
        }
        let role = decode_role(&mut run)?;
        if roles.iter().any(|r| r.role_index == role.role_index) {
            return Err(refuse(
                WHAT,
                format!("role_index {} appears twice", role.role_index),
            ));
        }
        roles.push(role);
    }
    Ok(roles)
}

fn decode_role(reader: &mut Reader<'_>) -> Result<Role, RoomPolicyError> {
    let role_index = reader.u32("Role.role_index")?;
    let role_name = reader.text("Role.role_name")?;
    let _description = reader.text("Role.role_description")?;
    let mut capabilities_run = reader.run("Role.role_capabilities", MAX_CAPABILITIES * 2)?;
    let mut capabilities: Vec<Capability> = Vec::new();
    let mut listed = 0usize;
    while !capabilities_run.is_empty() {
        listed += 1;
        if listed > MAX_CAPABILITIES {
            return Err(refuse(
                "Role.role_capabilities",
                format!("more than {MAX_CAPABILITIES} entries"),
            ));
        }
        if let Some(capability) =
            capability_from_wire(capabilities_run.u16("Role.role_capabilities")?)
        {
            if !capabilities.contains(&capability) {
                capabilities.push(capability);
            }
        }
    }
    let min_participants = reader.u32("Role.minimum_participants_constraint")?;
    let max_participants = reader.optional_u32("Role.maximum_participants_constraint")?;
    let min_active = reader.u32("Role.minimum_active_participants_constraint")?;
    let max_active = reader.optional_u32("Role.maximum_active_participants_constraint")?;
    for (min, max, what) in [
        (min_participants, max_participants, "participants"),
        (min_active, max_active, "active participants"),
    ] {
        if let Some(max) = max {
            if min > max {
                return Err(refuse(
                    "Role",
                    format!("the minimum of {what} ({min}) exceeds the maximum ({max})"),
                ));
            }
        }
    }
    let mut changes_run = reader.run("Role.authorized_role_changes", MAX_RUN_AGGREGATE_BYTES)?;
    let mut authorized_role_changes = Vec::new();
    while !changes_run.is_empty() {
        if authorized_role_changes.len() >= MAX_TRANSITIONS {
            return Err(refuse(
                "Role.authorized_role_changes",
                format!("more than {MAX_TRANSITIONS} entries"),
            ));
        }
        let from_role_index = changes_run.u32("SingleSourceRoleChangeTargets.from_role_index")?;
        let mut targets_run = changes_run.run(
            "SingleSourceRoleChangeTargets.target_role_indexes",
            MAX_TARGETS * 4,
        )?;
        let mut target_role_indexes = Vec::new();
        while !targets_run.is_empty() {
            if target_role_indexes.len() >= MAX_TARGETS {
                return Err(refuse(
                    "SingleSourceRoleChangeTargets",
                    format!("more than {MAX_TARGETS} targets"),
                ));
            }
            target_role_indexes
                .push(targets_run.u32("SingleSourceRoleChangeTargets.target_role_indexes")?);
        }
        authorized_role_changes.push(SingleSourceRoleChangeTargets {
            from_role_index,
            target_role_indexes,
        });
    }
    Ok(Role {
        role_index,
        role_name,
        capabilities,
        authorized_role_changes,
    })
}

/// Decode a `BaseRoomPolicy` (the `base_room_policy` component and its update).
///
/// Kept: `fixed_membership`, `parent_dependant`, `max_clients`, `max_users` and `discoverable`. Read and not kept:
/// `multi_device`, `pseudonyms_allowed`, `persistent_room`, the parent room's URI and the list of policy components. A
/// parent-dependent room must name its parent, and any other must not (§5).
pub fn decode_base_room_policy(bytes: &[u8]) -> Result<BaseRoomPolicy, RoomPolicyError> {
    const WHAT: &str = "BaseRoomPolicy";
    let mut reader = Reader::new(bytes);
    let fixed_membership = reader.flag("BaseRoomPolicy.fixed_membership")?;
    let parent_dependant = reader.flag("BaseRoomPolicy.parent_dependant")?;
    // `Uri parent_room<V>`: a vector of `Uri` structs, each an `opaque uri<V>`; none, or the one parent.
    let mut parents = reader.run("BaseRoomPolicy.parent_room", MAX_TEXT + 8)?;
    let mut parent_rooms = 0usize;
    while !parents.is_empty() {
        parent_rooms += 1;
        if parent_rooms > 1 {
            return Err(refuse(WHAT, "more than one parent room"));
        }
        let uri = parents.opaque("Uri.uri", MAX_TEXT)?;
        if uri.is_empty() {
            return Err(refuse(WHAT, "an empty parent room URI"));
        }
    }
    if parent_dependant != (parent_rooms == 1) {
        return Err(refuse(
            WHAT,
            "a parent-dependent room names its parent, and any other does not",
        ));
    }
    let _multi_device = reader.flag("BaseRoomPolicy.multi_device")?;
    let max_clients = reader.optional_u32("BaseRoomPolicy.max_clients")?;
    let max_users = reader.optional_u32("BaseRoomPolicy.max_users")?;
    let _pseudonyms_allowed = reader.flag("BaseRoomPolicy.pseudonyms_allowed")?;
    let _persistent_room = reader.flag("BaseRoomPolicy.persistent_room")?;
    let discoverable = reader.flag("BaseRoomPolicy.discoverable")?;
    let mut components =
        reader.run("BaseRoomPolicy.policy_component_ids", MAX_COMPONENT_IDS * 2)?;
    let mut listed = 0usize;
    while !components.is_empty() {
        listed += 1;
        if listed > MAX_COMPONENT_IDS {
            return Err(refuse(
                WHAT,
                format!("more than {MAX_COMPONENT_IDS} policy components"),
            ));
        }
        components.u16("BaseRoomPolicy.policy_component_ids")?;
    }
    reader.done(WHAT)?;
    Ok(BaseRoomPolicy {
        fixed_membership,
        parent_dependant,
        max_clients,
        max_users,
        discoverable,
    })
}

fn put_run(out: &mut Vec<u8>, content: &[u8]) {
    // The content is built here, never from a peer, and is far below the 30-bit limit.
    let wrapped = VLBytes::new(content.to_vec());
    let encoded =
        tls_codec::Serialize::tls_serialize_detached(&wrapped).expect("a run this small encodes");
    out.extend_from_slice(&encoded);
}

fn put_opaque(out: &mut Vec<u8>, bytes: &[u8]) {
    put_run(out, bytes);
}

fn put_optional(out: &mut Vec<u8>, value: Option<u32>) {
    match value {
        Some(v) => {
            out.push(1);
            out.extend_from_slice(&v.to_be_bytes());
        }
        None => out.push(0),
    }
}

/// Encode roles as a `RoleData`. The fields the hub does not keep are written empty or unconstrained.
pub fn encode_role_data(roles: &[Role]) -> Vec<u8> {
    let mut list = Vec::new();
    for role in roles {
        list.extend_from_slice(&role.role_index.to_be_bytes());
        put_opaque(&mut list, role.role_name.as_bytes());
        put_opaque(&mut list, b"");
        let mut capabilities = Vec::new();
        for capability in &role.capabilities {
            capabilities.extend_from_slice(&capability_to_wire(*capability).to_be_bytes());
        }
        put_run(&mut list, &capabilities);
        list.extend_from_slice(&0u32.to_be_bytes());
        put_optional(&mut list, None);
        list.extend_from_slice(&0u32.to_be_bytes());
        put_optional(&mut list, None);
        let mut changes = Vec::new();
        for change in &role.authorized_role_changes {
            changes.extend_from_slice(&change.from_role_index.to_be_bytes());
            let mut targets = Vec::new();
            for target in &change.target_role_indexes {
                targets.extend_from_slice(&target.to_be_bytes());
            }
            put_run(&mut changes, &targets);
        }
        put_run(&mut list, &changes);
    }
    let mut out = Vec::new();
    put_run(&mut out, &list);
    out
}

/// Encode a base policy as a `BaseRoomPolicy`. The fields the hub does not keep are written at their draft defaults.
pub fn encode_base_room_policy(base: &BaseRoomPolicy, parent_room: Option<&str>) -> Vec<u8> {
    let mut out = vec![
        u8::from(base.fixed_membership),
        u8::from(base.parent_dependant),
    ];
    let mut parent = Vec::new();
    if let Some(uri) = parent_room {
        put_opaque(&mut parent, uri.as_bytes());
    }
    put_run(&mut out, &parent);
    out.push(1); // multi_device
    put_optional(&mut out, base.max_clients);
    put_optional(&mut out, base.max_users);
    out.push(0); // pseudonyms_allowed
    out.push(1); // persistent_room
    out.push(u8::from(base.discoverable));
    put_run(&mut out, &[]); // policy_component_ids
    out
}

#[cfg(test)]
#[path = "room_policy_wire_tests.rs"]
mod tests;
