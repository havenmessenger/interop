//! The room-policy-04 wire values: the layouts are §3 (`RoleData`) and §5 (`BaseRoomPolicy`). The first two tests decode
//! bytes written out by hand, so the codec is not checked against its own encoder alone.

use super::*;

fn hex(h: &str) -> Vec<u8> {
    let h: String = h.split_whitespace().collect();
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        .collect()
}

fn run(content: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    tls_codec::vlen::write_length(&mut out, content.len()).unwrap();
    out.extend_from_slice(content);
    out
}

/// One role: index 2, "admin", no description, capabilities 0x0000 and 0x0100, no constraints, no role changes.
const ONE_ROLE: &str = "1b 00000002 05 61646d696e 00 04 0000 0100 00000000 00 00000000 00 00";

#[test]
fn a_role_written_by_hand_is_read_field_by_field() {
    let roles = decode_role_data(&hex(ONE_ROLE)).unwrap();
    assert_eq!(roles.len(), 1);
    assert_eq!(roles[0].role_index, 2);
    assert_eq!(roles[0].role_name, "admin");
    assert_eq!(
        roles[0].capabilities,
        vec![Capability::AddParticipant, Capability::SendMessage]
    );
    assert!(roles[0].authorized_role_changes.is_empty());
}

#[test]
fn a_base_policy_written_by_hand_is_read_field_by_field() {
    // fixed_membership 1, parent_dependant 0, no parent, multi_device 1, max_clients 100, no max_users,
    // pseudonyms_allowed 0, persistent_room 1, discoverable 1, no component ids.
    let base = decode_base_room_policy(&hex("01 00 00 01 01 00000064 00 00 01 01 00")).unwrap();
    assert_eq!(
        base,
        BaseRoomPolicy {
            fixed_membership: true,
            parent_dependant: false,
            max_clients: Some(100),
            max_users: None,
            discoverable: true,
        }
    );
}

fn sample_roles() -> Vec<Role> {
    vec![
        Role {
            role_index: 2,
            role_name: "admin".into(),
            capabilities: vec![
                Capability::SendMessage,
                Capability::AddParticipant,
                Capability::RemoveParticipant,
                Capability::Ban,
                Capability::Kick,
                Capability::ChangeRole,
            ],
            authorized_role_changes: vec![
                SingleSourceRoleChangeTargets {
                    from_role_index: 0,
                    target_role_indexes: vec![2, 3],
                },
                SingleSourceRoleChangeTargets {
                    from_role_index: 3,
                    target_role_indexes: vec![0, 1],
                },
            ],
        },
        Role {
            role_index: 3,
            role_name: "member".into(),
            capabilities: vec![Capability::SendMessage],
            authorized_role_changes: vec![],
        },
    ]
}

#[test]
fn roles_and_base_policy_round_trip() {
    let roles = sample_roles();
    assert_eq!(decode_role_data(&encode_role_data(&roles)).unwrap(), roles);
    let base = BaseRoomPolicy {
        fixed_membership: false,
        parent_dependant: true,
        max_clients: Some(8),
        max_users: Some(4),
        discoverable: true,
    };
    let bytes = encode_base_room_policy(&base, Some("mimi://parent.example/r/p"));
    assert_eq!(decode_base_room_policy(&bytes).unwrap(), base);
}

#[test]
fn each_enforced_capability_has_its_registry_value_and_the_others_are_dropped() {
    for (value, capability) in [
        (0x0000u16, Capability::AddParticipant),
        (0x0001, Capability::RemoveParticipant),
        (0x000a, Capability::Ban),
        (0x000c, Capability::Kick),
        (0x000f, Capability::ChangeRole),
        (0x0100, Capability::SendMessage),
    ] {
        assert_eq!(capability_from_wire(value), Some(capability));
        assert_eq!(capability_to_wire(capability), value);
    }
    // Other registry values (upload, call, room attributes) are read and not carried; a repeat counts once.
    let mut role = String::from("00000002 01 61 00 ");
    role.push_str("0a 0002 0003 0100 0100 0010");
    role.push_str(" 00000000 00 00000000 00 00");
    let body = hex(&role);
    let wrapped = [run(&body)].concat();
    let roles = decode_role_data(&wrapped).unwrap();
    assert_eq!(roles[0].capabilities, vec![Capability::SendMessage]);
}

fn refused(bytes: &[u8]) -> String {
    decode_role_data(bytes)
        .expect_err("this role list must be refused")
        .to_string()
}

#[test]
fn a_role_list_that_does_not_end_where_it_says_is_refused() {
    let mut trailing = hex(ONE_ROLE);
    trailing.push(0);
    assert!(refused(&trailing).contains("trailing"));
    let mut short = hex(ONE_ROLE);
    short.pop();
    assert!(decode_role_data(&short).is_err());
}

#[test]
fn every_truncation_of_a_valid_value_is_refused_without_a_panic() {
    let roles = encode_role_data(&sample_roles());
    for cut in 0..roles.len() {
        assert!(
            decode_role_data(&roles[..cut]).is_err(),
            "role list cut at {cut}"
        );
    }
    let base = encode_base_room_policy(&BaseRoomPolicy::default(), None);
    for cut in 0..base.len() {
        assert!(
            decode_base_room_policy(&base[..cut]).is_err(),
            "base policy cut at {cut}"
        );
    }
}

#[test]
fn a_repeated_role_index_is_refused() {
    let mut roles = sample_roles();
    roles[1].role_index = 2;
    assert!(refused(&encode_role_data(&roles)).contains("appears twice"));
}

#[test]
fn a_minimum_above_its_maximum_is_refused() {
    // minimum_participants 5, maximum 3.
    let role = "00000002 01 61 00 00 00000005 01 00000003 00000000 00 00";
    assert!(refused(&run(&hex(role))).contains("exceeds the maximum"));
    // The same for the active-participant pair.
    let role = "00000002 01 61 00 00 00000000 00 00000005 01 00000003 00";
    assert!(refused(&run(&hex(role))).contains("exceeds the maximum"));
    // A minimum equal to the maximum is allowed.
    let role = "00000002 01 61 00 00 00000003 01 00000003 00000000 00 00";
    assert!(decode_role_data(&run(&hex(role))).is_ok());
}

#[test]
fn a_flag_that_is_not_0_or_1_is_refused() {
    let mut bytes = encode_base_room_policy(&BaseRoomPolicy::default(), None);
    bytes[0] = 2;
    assert!(decode_base_room_policy(&bytes).is_err());
}

#[test]
fn a_parent_dependent_room_names_a_parent_and_any_other_does_not() {
    let mut base = BaseRoomPolicy::default();
    base.parent_dependant = true;
    assert!(decode_base_room_policy(&encode_base_room_policy(&base, None)).is_err());
    base.parent_dependant = false;
    assert!(decode_base_room_policy(&encode_base_room_policy(
        &base,
        Some("mimi://p.example/r/1")
    ))
    .is_err());
    let mut two = encode_base_room_policy(&BaseRoomPolicy::default(), None);
    // parent_room becomes two URIs.
    let uris = [run(b"mimi://a.example/r/1"), run(b"mimi://b.example/r/2")].concat();
    two.splice(2..3, run(&uris));
    assert!(decode_base_room_policy(&two).is_err());
}

#[test]
fn a_role_name_that_is_not_utf8_is_refused() {
    let role = "00000002 01 ff 00 00 00000000 00 00000000 00 00";
    assert!(refused(&run(&hex(role))).contains("UTF-8"));
}

#[test]
fn a_declared_length_past_the_budget_is_refused_from_the_prefix_alone() {
    let mut prefix = Vec::new();
    tls_codec::vlen::write_length(&mut prefix, MAX_RUN_AGGREGATE_BYTES + 1).unwrap();
    assert!(decode_role_data(&prefix).is_err());
    assert!(decode_base_room_policy(&[0, 0, 0]).is_err());
    // The 8-byte varint form is refused without reaching tls_codec.
    assert!(decode_role_data(&[0xC0, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
}

#[test]
fn more_roles_than_the_cap_are_refused() {
    let one = hex("00000000 01 61 00 00 00000000 00 00000000 00 00");
    let mut list = Vec::new();
    for index in 0..=(MAX_ROLES as u32) {
        let mut role = one.clone();
        role[..4].copy_from_slice(&index.to_be_bytes());
        list.extend_from_slice(&role);
    }
    assert!(refused(&run(&list)).contains("more than"));
}

#[test]
fn a_long_name_description_or_capability_list_is_refused() {
    let long = vec![b'a'; MAX_TEXT + 1];
    let role = [
        hex("00000002"),
        run(&long),
        run(b""),
        run(b""),
        hex("00000000 00 00000000 00 00"),
    ]
    .concat();
    assert!(decode_role_data(&run(&role)).is_err());
    let caps = vec![0u8; (MAX_CAPABILITIES + 1) * 2];
    let role = [
        hex("00000002 01 61 00"),
        run(&caps),
        hex("00000000 00 00000000 00 00"),
    ]
    .concat();
    assert!(decode_role_data(&run(&role)).is_err());
}

#[test]
fn a_role_list_with_the_reserved_names_is_for_the_policy_to_judge() {
    // The codec reads it; RoomPolicy::validate refuses role 1 under another name.
    let roles = vec![Role {
        role_index: 1,
        role_name: "gone".into(),
        capabilities: vec![],
        authorized_role_changes: vec![],
    }];
    let decoded = decode_role_data(&encode_role_data(&roles)).unwrap();
    let policy = crate::room_policy::RoomPolicy {
        base: BaseRoomPolicy::default(),
        roles: decoded,
    };
    assert!(policy.validate().is_err());
}
