//! The lane room profile file: what it takes, and what stops the start.

use super::{LaneRoomProfile, ROLE_ADMIN, ROLE_MEMBER};

/// The profile in the module's documentation, which a deployment copies.
const DOCUMENTED: &str = r#"
creator_role = 2
external_commit_allowed = false

[room_policy.base]
fixed_membership = false
parent_dependant = false
discoverable = false

[[room_policy.roles]]
role_index = 2
role_name = "admin"
capabilities = ["SendMessage", "AddParticipant", "RemoveParticipant", "RemoveSelf", "ChangeRole", "Ban"]
authorized_role_changes = [{ from_role_index = 0, target_role_indexes = [2, 3] }]

[[room_policy.roles]]
role_index = 3
role_name = "member"
capabilities = ["SendMessage", "RemoveSelf"]
"#;

/// The documented profile with the reserved roles 0 and 1 defined too, so a creator role naming one of them is refused
/// for being reserved, not for being undefined.
fn with_reserved_roles() -> String {
    format!(
        "{DOCUMENTED}
[[room_policy.roles]]
role_index = 0
role_name = \"outsider\"
capabilities = []

[[room_policy.roles]]
role_index = 1
role_name = \"banned\"
capabilities = []
"
    )
}

#[test]
fn the_documented_profile_parses() {
    LaneRoomProfile::parse(&with_reserved_roles()).expect("the reserved roles may be defined");
    let profile = LaneRoomProfile::parse(DOCUMENTED).expect("the documented profile");
    assert_eq!(profile.creator_role, 2);
    assert!(!profile.external_commit_allowed);
    assert_eq!(profile.room_policy.roles.len(), 2);
}

#[test]
fn the_neutral_profile_refuses_external_commits_and_is_valid() {
    let neutral = LaneRoomProfile::neutral();
    assert!(!neutral.external_commit_allowed);
    neutral.room_policy.validate().expect("valid");
    assert!(neutral.room_policy.role(neutral.creator_role).is_some());
}

/// A creator role that is not a participant, banned or undefined, an unknown key, or a room policy that is not valid is
/// refused, so the hub does not start on it.
#[test]
fn a_profile_that_is_not_valid_is_refused() {
    for (what, text) in [
        (
            "creator not a participant, role 0 defined",
            with_reserved_roles().replace("creator_role = 2", "creator_role = 0"),
        ),
        (
            "creator banned, role 1 defined",
            with_reserved_roles().replace("creator_role = 2", "creator_role = 1"),
        ),
        (
            "creator undefined",
            DOCUMENTED.replace("creator_role = 2", "creator_role = 9"),
        ),
        (
            "unknown key",
            DOCUMENTED.replace("creator_role = 2", "creator_role = 2\nopen_join = true"),
        ),
        (
            "duplicate role index",
            DOCUMENTED.replace("role_index = 3", "role_index = 2"),
        ),
        (
            "no external commit setting",
            DOCUMENTED.replace("external_commit_allowed = false\n", ""),
        ),
    ] {
        assert!(LaneRoomProfile::parse(&text).is_err(), "{what} was taken");
    }
}

#[test]
fn a_missing_file_is_refused() {
    assert!(LaneRoomProfile::load(std::path::Path::new("/nonexistent/lane-room.toml")).is_err());
}

/// The neutral profile lets a member leave: RemoveSelf and the member role's own change to 0. Revert check: drop the
/// member's authorized_role_changes and its self-removal is refused.
#[test]
fn the_neutral_profile_lets_a_member_leave() {
    let profile = LaneRoomProfile::neutral();
    assert!(
        profile
            .room_policy
            .authorize_self_removal(ROLE_MEMBER)
            .is_ok(),
        "PLANT-NEUTRAL-MEMBER-LEAVES: a member of a neutral-profile room may leave"
    );
}

/// A profile whose admins may leave and remove one another (room-policy-04 §8.1.2): the admin role's own entry from
/// itself to 0, beside the neutral profile's entries; members leave as in the neutral profile.
const ADMINS_LEAVE: &str = r#"
creator_role = 2
external_commit_allowed = false

[room_policy.base]
fixed_membership = false
parent_dependant = false
discoverable = false

[[room_policy.roles]]
role_index = 1
role_name = "banned"
capabilities = []

[[room_policy.roles]]
role_index = 2
role_name = "admin"
capabilities = ["SendMessage", "AddParticipant", "RemoveParticipant", "RemoveSelf", "ChangeRole", "Ban"]
authorized_role_changes = [
  { from_role_index = 0, target_role_indexes = [2, 3] },
  { from_role_index = 3, target_role_indexes = [0, 1, 2] },
  { from_role_index = 2, target_role_indexes = [0, 3] },
]

[[room_policy.roles]]
role_index = 3
role_name = "member"
capabilities = ["SendMessage", "RemoveSelf"]
authorized_role_changes = [{ from_role_index = 3, target_role_indexes = [0] }]
"#;

/// With the admin role's entry from itself to 0 a deployment's admins may leave and remove another admin; the neutral
/// profile, which has no such entry, refuses both (DIV-22). A member may leave under either, and removes no one else.
/// Revert check: refuse every self-removal, and the admin's leave is refused; drop the actor's RemoveParticipant check,
/// and a member removes another member.
#[test]
fn a_profile_may_let_admins_leave_and_remove_admins() {
    let admins_leave = LaneRoomProfile::parse(ADMINS_LEAVE).unwrap().room_policy;
    assert!(
        admins_leave.authorize_self_removal(ROLE_ADMIN).is_ok(),
        "PLANT-ADMIN-LEAVES: an admin may leave under a profile that lets admins leave"
    );
    assert!(
        admins_leave
            .authorize_role_change(ROLE_ADMIN, ROLE_ADMIN, 0)
            .is_ok(),
        "an admin may remove another admin"
    );
    assert!(admins_leave.authorize_self_removal(ROLE_MEMBER).is_ok());
    // The member's entry from itself to 0 is for leaving only: without RemoveParticipant a member removes no one.
    assert!(
        admins_leave
            .authorize_role_change(ROLE_MEMBER, ROLE_MEMBER, 0)
            .is_err(),
        "PLANT-MEMBER-REMOVES-NO-ONE: a member removed another member"
    );
    assert!(
        admins_leave
            .authorize_role_change(ROLE_MEMBER, ROLE_ADMIN, 0)
            .is_err(),
        "a member removed an admin"
    );

    let neutral = LaneRoomProfile::neutral().room_policy;
    assert!(neutral.authorize_self_removal(ROLE_ADMIN).is_err());
    assert!(neutral
        .authorize_role_change(ROLE_ADMIN, ROLE_ADMIN, 0)
        .is_err());
    assert!(neutral.authorize_self_removal(ROLE_MEMBER).is_ok());
}
