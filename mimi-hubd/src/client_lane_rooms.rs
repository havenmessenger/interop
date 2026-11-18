//! Rooms the client lane creates: hosted here, with the creating user as their first participant and admin.
//!
//! What the hub holds for such a room is its state before the creator's group is tracked. The creator's first Commit
//! that carries a full GroupInfo and ratchet tree seeds the room's tree, and from then on the group's own components
//! (participant list, roles, operational policy) are the room's state, as for any room hosted here.

use mimi_core::operational_parameters::{encode_operational_parameters, OperationalParameters};
use mimi_core::room_policy::{
    BaseRoomPolicy, Capability, Role, RoomPolicy, SingleSourceRoleChangeTargets,
};
use ring::rand::SecureRandom;

use crate::Provider;

/// The role the creator holds.
pub const ROLE_ADMIN: u32 = 2;
/// The role an added participant holds.
pub const ROLE_MEMBER: u32 = 3;

/// The one room policy the lane creates rooms with: admins add, remove, ban and change roles; members send and may
/// leave; no external joins (the operational policy refuses external Commits).
pub fn default_room_policy() -> RoomPolicy {
    RoomPolicy {
        base: BaseRoomPolicy::default(),
        roles: vec![
            Role {
                role_index: 1,
                role_name: "banned".into(),
                capabilities: vec![],
                authorized_role_changes: vec![],
            },
            Role {
                role_index: ROLE_ADMIN,
                role_name: "admin".into(),
                capabilities: vec![
                    Capability::SendMessage,
                    Capability::AddParticipant,
                    Capability::RemoveParticipant,
                    Capability::RemoveSelf,
                    Capability::ChangeRole,
                    Capability::Ban,
                ],
                authorized_role_changes: vec![
                    SingleSourceRoleChangeTargets {
                        from_role_index: 0,
                        target_role_indexes: vec![ROLE_ADMIN, ROLE_MEMBER],
                    },
                    SingleSourceRoleChangeTargets {
                        from_role_index: ROLE_MEMBER,
                        target_role_indexes: vec![0, 1, ROLE_ADMIN],
                    },
                    SingleSourceRoleChangeTargets {
                        from_role_index: ROLE_ADMIN,
                        target_role_indexes: vec![ROLE_MEMBER],
                    },
                ],
            },
            Role {
                role_index: ROLE_MEMBER,
                role_name: "member".into(),
                capabilities: vec![Capability::SendMessage, Capability::RemoveSelf],
                authorized_role_changes: vec![],
            },
        ],
    }
}

/// The operational policy a lane room starts with: external Commits refused, the rest at their defaults.
fn default_operational_policy() -> Vec<u8> {
    encode_operational_parameters(&OperationalParameters {
        external_commit_allowed: false,
        ..OperationalParameters::default()
    })
}

impl Provider {
    /// Create a room hosted here for `user` (a verified user of this provider): a fresh room URI, `user` its only
    /// participant and its admin, under [`default_room_policy`] with external Commits refused. Returns the room's URI.
    pub fn lane_create_room(&self, user: &str, now_unix: u64) -> anyhow::Result<String> {
        if self.local_name(user).is_none() {
            anyhow::bail!("not a user of this provider");
        }
        let mut id = [0u8; 16];
        ring::rand::SystemRandom::new()
            .fill(&mut id)
            .map_err(|_| anyhow::anyhow!("no randomness for a room id"))?;
        let hex: String = id.iter().map(|byte| format!("{byte:02x}")).collect();
        let room = format!("mimi://{}/r/{hex}", self.domain);
        self.add_participant(&room, user, now_unix)?;
        self.set_room_policy(&room, &default_room_policy(), now_unix)?;
        self.set_member_role(&room, &mimi_core::uri::canonical(user), ROLE_ADMIN)?;
        self.set_operational_policy(&room, &default_operational_policy())
            .map_err(|_| anyhow::anyhow!("the room's operational policy could not be stored"))?;
        Ok(room)
    }
}
