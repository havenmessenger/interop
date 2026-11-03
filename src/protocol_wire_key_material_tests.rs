//! `KeyMaterialResponse` against the §5.2 wire, built here byte by byte rather than through the encoder, so the layout under
//! test is the draft's and not this crate's own: every client of the user is read, whatever the user code is, and what was read
//! is written back unchanged.

use super::*;
use crate::test_fixtures::{capabilities, key_package};

const USER: &str = "mimi://example.org/u/alice";
const CLIENT_A: &str = "mimi://example.org/d/alice-a";
const CLIENT_B: &str = "mimi://example.org/d/alice-b";

fn uri(value: &str) -> Vec<u8> {
    VLBytes::new(value.as_bytes().to_vec())
        .tls_serialize_detached()
        .unwrap()
}

/// `ClientKeyMaterial` for a `success` client.
fn success(client: &str, key_package: &[u8]) -> Vec<u8> {
    [vec![0], uri(client), key_package.to_vec()].concat()
}

fn exhausted(client: &str) -> Vec<u8> {
    [vec![1], uri(client)].concat()
}

fn nothing_compatible(client: &str, capabilities: Option<&[u8]>) -> Vec<u8> {
    let tail = match capabilities {
        Some(bytes) => [vec![1], bytes.to_vec()].concat(),
        None => vec![0],
    };
    [vec![2], uri(client), tail].concat()
}

/// A whole `KeyMaterialResponse`: protocol, user status, user URI, then the clients window.
fn response(user_status: u8, user: &str, clients: &[Vec<u8>]) -> Vec<u8> {
    let window = VLBytes::new(clients.concat())
        .tls_serialize_detached()
        .unwrap();
    [vec![PROTOCOL_MLS10, user_status], uri(user), window].concat()
}

/// Decode, check the result is `Clients`, and require that writing it back gives the bytes that came in.
fn round_trips(bytes: &[u8]) -> KeyMaterialResponse {
    let decoded = KeyMaterialResponse::decode(bytes).unwrap();
    assert_eq!(
        decoded.encode().unwrap(),
        bytes,
        "decode then encode must be the identity"
    );
    decoded
}

#[test]
fn two_clients_that_both_supplied_material_are_both_read() {
    let (a, b) = (key_package(b"a", 1), key_package(b"b", 1));
    let bytes = response(0, USER, &[success(CLIENT_A, &a), success(CLIENT_B, &b)]);
    let KeyMaterialResponse::Clients {
        clients,
        user_status,
        ..
    } = round_trips(&bytes)
    else {
        panic!("two clients decode to Clients");
    };
    assert_eq!(user_status, KeyMaterialUserCode::Success);
    assert_eq!(clients.len(), 2);
    assert_eq!(clients[0].key_package.as_deref(), Some(a.as_slice()));
    assert_eq!(clients[1].key_package.as_deref(), Some(b.as_slice()));
    assert_eq!(clients[1].client_uri, IdentifierUri(CLIENT_B.into()));
}

#[test]
fn a_partial_success_names_the_client_that_supplied_none() {
    let a = key_package(b"a", 1);
    let bytes = response(1, USER, &[success(CLIENT_A, &a), exhausted(CLIENT_B)]);
    let KeyMaterialResponse::Clients {
        clients,
        user_status,
        ..
    } = round_trips(&bytes)
    else {
        panic!("a mixed response decodes to Clients");
    };
    assert_eq!(user_status, KeyMaterialUserCode::PartialSuccess);
    assert_eq!(clients[0].status, KeyMaterialClientCode::Success);
    assert_eq!(
        clients[1].status,
        KeyMaterialClientCode::KeyMaterialExhausted
    );
    assert_eq!(clients[1].key_package, None);
}

#[test]
fn a_client_with_nothing_compatible_carries_optional_capabilities() {
    let caps = capabilities();
    let a = key_package(b"a", 1);
    let with = response(
        1,
        USER,
        &[
            success(CLIENT_A, &a),
            nothing_compatible(CLIENT_B, Some(&caps)),
        ],
    );
    let KeyMaterialResponse::Clients { clients, .. } = round_trips(&with) else {
        panic!("Clients");
    };
    assert_eq!(clients[1].capabilities.as_deref(), Some(caps.as_slice()));
    let without = response(
        1,
        USER,
        &[success(CLIENT_A, &a), nothing_compatible(CLIENT_B, None)],
    );
    let KeyMaterialResponse::Clients { clients, .. } = round_trips(&without) else {
        panic!("Clients");
    };
    assert_eq!(clients[1].capabilities, None);
}

#[test]
fn a_user_code_that_carries_no_client_decodes_with_none() {
    for code in [2u8, 4, 7] {
        let decoded = round_trips(&response(code, USER, &[]));
        let KeyMaterialResponse::Clients {
            clients,
            user_status,
            ..
        } = decoded
        else {
            panic!("user code {code} decodes to Clients");
        };
        assert!(clients.is_empty());
        assert_eq!(user_status.to_u8(), code);
    }
}

#[test]
fn no_compatible_material_may_list_clients_or_none() {
    round_trips(&response(3, USER, &[]));
    round_trips(&response(3, USER, &[nothing_compatible(CLIENT_A, None)]));
}

#[test]
fn an_exhausted_client_under_no_compatible_material_is_read_and_written_back_unchanged() {
    // The reading in mimi-protocol issue 184: every client of a known user has `keyMaterialExhausted`, and the
    // user code is `noCompatibleMaterial` with the clients listed.
    let bytes = response(3, USER, &[exhausted(CLIENT_A), exhausted(CLIENT_B)]);
    let KeyMaterialResponse::Clients {
        user_status,
        clients,
        ..
    } = round_trips(&bytes)
    else {
        panic!("expected the clients to be kept");
    };
    assert_eq!(user_status, KeyMaterialUserCode::NoCompatibleMaterial);
    assert_eq!(clients.len(), 2);
    // The single-client form that names the user as its own client, as that reading has it for one device.
    round_trips(&response(3, USER, &[exhausted(USER)]));
}

#[test]
fn a_user_code_that_must_not_carry_clients_refuses_them() {
    for code in [2u8, 4, 7] {
        let bytes = response(code, USER, &[exhausted(CLIENT_A)]);
        assert!(
            KeyMaterialResponse::decode(&bytes).is_err(),
            "user code {code}"
        );
    }
}

#[test]
fn success_and_partial_success_enumerate_their_clients() {
    for code in [0u8, 1] {
        assert!(KeyMaterialResponse::decode(&response(code, USER, &[])).is_err());
    }
}

#[test]
fn success_means_material_for_every_client() {
    let a = key_package(b"a", 1);
    let bytes = response(0, USER, &[success(CLIENT_A, &a), exhausted(CLIENT_B)]);
    assert!(KeyMaterialResponse::decode(&bytes).is_err());
}

#[test]
fn a_denial_still_carries_no_client() {
    let denied = response(5, USER, &[]);
    assert!(matches!(
        round_trips(&denied),
        KeyMaterialResponse::Denied {
            code: KeyMaterialUserCode::NoConsent,
            ..
        }
    ));
    assert!(KeyMaterialResponse::decode(&response(5, USER, &[exhausted(CLIENT_A)])).is_err());
}

#[test]
fn the_shapes_this_hub_emits_keep_their_own_variants() {
    let a = key_package(b"a", 1);
    // One client whose URI is the user's: the same bytes `Success` writes.
    let one = response(0, USER, &[success(USER, &a)]);
    assert!(matches!(
        round_trips(&one),
        KeyMaterialResponse::Success { .. }
    ));
    let spent = response(1, USER, &[exhausted(USER)]);
    assert!(matches!(
        round_trips(&spent),
        KeyMaterialResponse::Exhausted { .. }
    ));
    // One client under its own URI would not be written back identically as `Success`, so it stays `Clients`.
    let own = response(0, USER, &[success(CLIENT_A, &a)]);
    assert!(matches!(
        round_trips(&own),
        KeyMaterialResponse::Clients { .. }
    ));
}

#[test]
fn a_foreign_suite_key_package_in_any_client_is_refused() {
    let (a, foreign) = (key_package(b"a", 1), key_package(b"b", 3));
    let bytes = response(
        0,
        USER,
        &[success(CLIENT_A, &a), success(CLIENT_B, &foreign)],
    );
    assert!(KeyMaterialResponse::decode(&bytes).is_err());
}

#[test]
fn a_truncated_or_overlong_response_is_refused() {
    let a = key_package(b"a", 1);
    let good = response(1, USER, &[success(CLIENT_A, &a), exhausted(CLIENT_B)]);
    for cut in [1, 5, good.len() - 1] {
        assert!(
            KeyMaterialResponse::decode(&good[..cut]).is_err(),
            "cut at {cut}"
        );
    }
    let mut trailing = good.clone();
    trailing.push(0);
    assert!(KeyMaterialResponse::decode(&trailing).is_err());
}

#[test]
fn an_unknown_client_status_is_refused() {
    let bytes = response(1, USER, &[[vec![9], uri(CLIENT_A)].concat()]);
    assert!(KeyMaterialResponse::decode(&bytes).is_err());
}

#[test]
fn a_run_of_too_many_clients_is_refused_by_the_run_budget() {
    let many: Vec<Vec<u8>> = (0..=MAX_RUN_ELEMENTS)
        .map(|_| exhausted(CLIENT_A))
        .collect();
    let error = KeyMaterialResponse::decode(&response(1, USER, &many)).unwrap_err();
    assert!(
        matches!(error, WireError::RunBudgetExceeded { .. }),
        "{error}"
    );
}

#[test]
fn encoding_a_client_whose_fields_do_not_fit_its_status_is_refused() {
    let bad = KeyMaterialResponse::Clients {
        user_uri: IdentifierUri(USER.into()),
        user_status: KeyMaterialUserCode::PartialSuccess,
        clients: vec![ClientKeyMaterial {
            status: KeyMaterialClientCode::KeyMaterialExhausted,
            client_uri: IdentifierUri(CLIENT_A.into()),
            key_package: Some(vec![1]),
            capabilities: None,
        }],
    };
    assert!(bad.encode().is_err());
}
