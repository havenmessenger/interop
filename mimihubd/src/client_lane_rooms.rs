//! Rooms the client lane creates: hosted here, with the creating user as their first participant.
//!
//! The deployment chooses what such a room starts with, in a profile file named by `MIMI_LANE_ROOM_POLICY` (or
//! `lane_room_policy` in the config file); the client names nothing. With no file the hub uses [`LaneRoomProfile::neutral`].
//!
//! ```toml
//! # The role the room's creator holds: one the roles below define, not 0 (not a participant) or 1 (banned).
//! creator_role = 2
//! # Whether the room's operational policy allows external Commits.
//! external_commit_allowed = false
//!
//! [room_policy.base]
//! fixed_membership = false
//! parent_dependant = false
//! discoverable = false
//!
//! [[room_policy.roles]]
//! role_index = 2
//! role_name = "admin"
//! capabilities = ["SendMessage", "AddParticipant", "RemoveParticipant", "RemoveSelf", "ChangeRole", "Ban"]
//! authorized_role_changes = [{ from_role_index = 0, target_role_indexes = [2, 3] }]
//!
//! [[room_policy.roles]]
//! role_index = 3
//! role_name = "member"
//! capabilities = ["SendMessage", "RemoveSelf"]
//! # Leaving is a change of one's own role to 0: RemoveSelf alone does not let a member leave.
//! authorized_role_changes = [{ from_role_index = 3, target_role_indexes = [0] }]
//! ```
//!
//! A named file the hub cannot read, a key it does not know, a room policy that is not valid, or a creator role the
//! policy does not define stops the start.
//!
//! What the hub holds for such a room is its state before the creator's group is tracked. The creator's first Commit
//! that carries a full GroupInfo and ratchet tree seeds the room's tree, and from then on the group's own components
//! (participant list, roles, operational policy) are the room's state, as for any room hosted here.

use mimi_core::operational_parameters::{encode_operational_parameters, OperationalParameters};
use mimi_core::room_policy::{
    BaseRoomPolicy, Capability, Role, RoomPolicy, SingleSourceRoleChangeTargets,
};
use ring::rand::SecureRandom;
use serde::Deserialize;

use crate::Provider;

/// The neutral profile's creator role.
pub const ROLE_ADMIN: u32 = 2;
/// The neutral profile's role for an added participant.
pub const ROLE_MEMBER: u32 = 3;

/// What a room the lane creates starts with: its room policy, the role its creator holds, and whether its operational
/// policy allows external Commits.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaneRoomProfile {
    pub creator_role: u32,
    pub external_commit_allowed: bool,
    pub room_policy: RoomPolicy,
}

impl LaneRoomProfile {
    /// The profile with no file: admins add, remove, ban and change roles; members send and may leave; the creator is
    /// an admin; external Commits are refused.
    pub fn neutral() -> Self {
        Self {
            creator_role: ROLE_ADMIN,
            external_commit_allowed: false,
            room_policy: neutral_room_policy(),
        }
    }

    /// Read and check the profile file at `path`.
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)
            .map_err(|error| anyhow::anyhow!("cannot read {}: {error}", path.display()))?;
        Self::parse(&raw).map_err(|error| {
            anyhow::anyhow!("{} is not a lane room profile: {error}", path.display())
        })
    }

    /// A profile from its TOML text, checked.
    pub fn parse(raw: &str) -> anyhow::Result<Self> {
        let profile: Self = toml::from_str(raw)?;
        profile.room_policy.validate()?;
        if matches!(profile.creator_role, 0 | 1)
            || profile.room_policy.role(profile.creator_role).is_none()
        {
            anyhow::bail!(
                "creator_role {} is not a role the room policy defines",
                profile.creator_role
            );
        }
        Ok(profile)
    }

    /// One line for the hub's start: what a lane room starts with.
    pub fn describe(&self) -> String {
        format!(
            "creator role {}, {} role(s), external Commits {}",
            self.creator_role,
            self.room_policy.roles.len(),
            if self.external_commit_allowed {
                "allowed"
            } else {
                "refused"
            }
        )
    }

    /// The app data components a lane room's group starts with, as (component id, data): its roles_list, base room
    /// policy and operational policy. createRoom answers them so the client puts them in its GroupContext, and the hub
    /// refuses a seed of the room's tree whose GroupContext differs (`seed_check.rs`).
    pub fn components(&self) -> Vec<(u16, Vec<u8>)> {
        vec![
            (
                crate::room_tree::ROLES_LIST_COMPONENT,
                mimi_core::room_policy_wire::encode_role_data(&self.room_policy.roles),
            ),
            (
                crate::room_tree::BASE_ROOM_POLICY_COMPONENT,
                mimi_core::room_policy_wire::encode_base_room_policy(&self.room_policy.base, None),
            ),
            (
                mimi_core::operational_parameters::OPERATIONAL_POLICY_COMPONENT_ID,
                self.operational_policy(),
            ),
        ]
    }

    fn operational_policy(&self) -> Vec<u8> {
        encode_operational_parameters(&OperationalParameters {
            external_commit_allowed: self.external_commit_allowed,
            ..OperationalParameters::default()
        })
    }
}

fn neutral_room_policy() -> RoomPolicy {
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
            // A member may leave: RemoveSelf, and its own role's change to 0 (room-policy-04 §8.1.2).
            Role {
                role_index: ROLE_MEMBER,
                role_name: "member".into(),
                capabilities: vec![Capability::SendMessage, Capability::RemoveSelf],
                authorized_role_changes: vec![SingleSourceRoleChangeTargets {
                    from_role_index: ROLE_MEMBER,
                    target_role_indexes: vec![0],
                }],
            },
        ],
    }
}

impl Provider {
    /// Create a room hosted here for `user` (a verified user of this provider): a fresh room URI, `user` its only
    /// participant, in `profile`'s creator role, under its room policy and operational policy. Returns the room's URI.
    pub fn lane_create_room(
        &self,
        user: &str,
        profile: &LaneRoomProfile,
        now_unix: u64,
    ) -> anyhow::Result<String> {
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
        self.set_room_policy(&room, &profile.room_policy, now_unix)?;
        self.set_member_role(
            &room,
            &mimi_core::uri::canonical(user),
            profile.creator_role,
        )?;
        self.set_operational_policy(&room, &profile.operational_policy())
            .map_err(|_| anyhow::anyhow!("the room's operational policy could not be stored"))?;
        Ok(room)
    }
}

#[cfg(test)]
#[path = "client_lane_rooms_tests.rs"]
mod tests;
