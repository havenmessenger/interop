use openmls::prelude::{BasicCredential, Credential, CredentialType};

use super::{is_successor, stated_uri, user_uri, VerifiedLogs, DID_WEBVH};
use crate::didwebvh_fixtures::{log, mls_credential, PortableLog};

const ALICE: &str = "mimi://example.com/u/alice";
/// A signature key no credential here authorizes, for Basic credentials (which bind none).
const ANY_KEY: [u8; 32] = [7; 32];
const DEVICE: [u8; 32] = [0x11; 32];
const OTHER_DEVICE: [u8; 32] = [0x22; 32];

fn basic(identity: &[u8]) -> Credential {
    BasicCredential::new(identity.to_vec()).into()
}

/// A credential of a type this hub does not read, carrying `content` (here, the bytes of a user URI).
fn other(content: &[u8]) -> Credential {
    Credential::new(CredentialType::Other(0xF0F0), content.to_vec())
}

#[test]
fn a_basic_credential_names_its_identity() {
    assert_eq!(
        stated_uri(&basic(ALICE.as_bytes()), &ANY_KEY).as_deref(),
        Some(ALICE)
    );
    assert_eq!(
        user_uri(&basic(b"mimi://EXAMPLE.com/u/alice"), &ANY_KEY),
        Some(mimi_core::uri::canonical("mimi://EXAMPLE.com/u/alice"))
    );
    assert_eq!(
        user_uri(&basic(&[0xff, 0xfe]), &ANY_KEY),
        None,
        "an identity that is not UTF-8 names no user"
    );
}

/// A credential of another type names no user, even when its content is the bytes of a user URI: it is never read as a
/// Basic credential. Revert check: read the content whatever the type, and Alice is named.
#[test]
fn a_credential_of_another_type_names_no_user() {
    assert_eq!(
        user_uri(&other(ALICE.as_bytes()), &ANY_KEY),
        None,
        "PLANT-CREDENTIAL-TYPE: a credential of another type was read as a URI"
    );
    assert_eq!(
        user_uri(
            &Credential::new(CredentialType::X509, ALICE.as_bytes().to_vec()),
            &ANY_KEY
        ),
        None
    );
}

/// A did_webvh credential names the one `mimi:` URI of its head's `alsoKnownAs`, for a leaf key its log authorizes, and
/// no one for any other key (§Binding to the LeafNode: "The `signature_key` of the LeafNode containing the credential
/// MUST equal the 32-byte public key of an authorized key in the head's DID document"). Revert check: skip the binding,
/// and the unauthorized key names Alice.
#[test]
fn a_did_webvh_credential_names_its_mimi_uri_for_an_authorized_key_only() {
    let credential = mls_credential(&log("alice", 1, &[DEVICE], &[ALICE]).credential().unwrap());
    assert_eq!(user_uri(&credential, &DEVICE).as_deref(), Some(ALICE));
    assert_eq!(
        user_uri(&credential, &OTHER_DEVICE),
        None,
        "PLANT-DIDWEBVH-BINDING: a key the log does not authorize named its user"
    );
}

/// The user URI is read exactly as the reference implementation reads it: the one entry whose scheme is `mimi`, in any
/// case, among the head's `alsoKnownAs`; none, or more than one, names no user, so the leaf binds no user.
#[test]
fn a_did_webvh_credential_names_a_user_only_by_exactly_one_mimi_uri() {
    let named = |also_known_as: &[&str]| {
        user_uri(
            &mls_credential(
                &log("alice", 1, &[DEVICE], also_known_as)
                    .credential()
                    .unwrap(),
            ),
            &DEVICE,
        )
    };
    assert_eq!(
        named(&[ALICE, "mimi://example.com/u/alice2"]),
        None,
        "PLANT-DIDWEBVH-ONE-URI: two mimi: entries named a user"
    );
    assert_eq!(named(&[ALICE, "MIMI://example.com/u/other"]), None);
    assert_eq!(named(&["https://example.com/alice"]), None);
    assert_eq!(named(&[]), None);
    assert_eq!(
        named(&["https://example.com/alice", "MIMI://Example.com/u/alice"]),
        Some(mimi_core::uri::canonical("MIMI://Example.com/u/alice"))
    );
}

/// A did_webvh credential is read only under the credential type this hub reads for it, and a log that does not verify
/// names no one.
#[test]
fn a_did_webvh_credential_names_no_one_under_another_type_or_with_a_broken_log() {
    let did_webvh = log("alice", 1, &[DEVICE], &[ALICE]).credential().unwrap();
    let under_another_type =
        Credential::new(CredentialType::Other(0xF013), did_webvh.encode().unwrap());
    assert_ne!(DID_WEBVH.credential_type(), 0xF013);
    assert_eq!(user_uri(&under_another_type, &DEVICE), None);
    let mut content = did_webvh.encode().unwrap();
    let at = content.len() / 2;
    content[at] ^= 0x01;
    let broken = Credential::new(CredentialType::Other(DID_WEBVH.credential_type()), content);
    assert_eq!(
        user_uri(&broken, &DEVICE),
        None,
        "a log that does not verify names no one"
    );
}

#[test]
fn a_basic_credential_succeeds_one_with_the_same_identity_only() {
    let alice = basic(ALICE.as_bytes());
    assert!(is_successor((&alice, &ANY_KEY), (&alice, &ANY_KEY)));
    assert!(!is_successor(
        (&alice, &ANY_KEY),
        (&basic(b"mimi://example.com/u/bob"), &ANY_KEY)
    ));
    assert!(
        !is_successor((&alice, &ANY_KEY), (&other(ALICE.as_bytes()), &ANY_KEY)),
        "a change of credential type is not a successor"
    );
    let other = other(ALICE.as_bytes());
    assert!(!is_successor((&other, &ANY_KEY), (&other, &ANY_KEY)));
}

/// A did_webvh credential succeeds another when it carries the same log with entries appended (§Successor Credentials:
/// "the same SCID and the earlier credential's log is a prefix of the new one") and still names the same user; an older
/// log, another user's log, or a log naming another URI does not. Revert check: drop the URI comparison, and the
/// renamed log succeeds.
#[test]
fn a_did_webvh_credential_succeeds_its_own_log_extended() {
    let mut alice = log("alice", 1, &[DEVICE], &[ALICE]);
    let first = mls_credential(&alice.credential().unwrap());
    alice
        .append(
            "2026-11-26T10:00:02Z",
            &mls_didwebvh::controller::Parameters::default(),
            &mls_didwebvh::controller::UpdateKey::from_seed(&[1; 32]),
            &[DEVICE, OTHER_DEVICE],
        )
        .unwrap();
    let second = mls_credential(&alice.credential().unwrap());
    assert!(is_successor((&first, &DEVICE), (&second, &OTHER_DEVICE)));
    assert!(
        !is_successor((&second, &OTHER_DEVICE), (&first, &DEVICE)),
        "an older log is not a successor"
    );
    let bob = mls_credential(
        &log("bob", 2, &[DEVICE], &["mimi://example.com/u/bob"])
            .credential()
            .unwrap(),
    );
    assert!(!is_successor((&first, &DEVICE), (&bob, &DEVICE)));
    assert!(
        !is_successor((&first, &DEVICE), (&basic(ALICE.as_bytes()), &DEVICE)),
        "a change of credential type is not a successor"
    );

    let mut renamed = PortableLog::create(
        "example.com",
        "carol",
        3,
        &[DEVICE],
        &["mimi://example.com/u/carol".into()],
    );
    let before = mls_credential(&renamed.credential().unwrap());
    renamed.append(
        "example.com",
        &[DEVICE],
        &["mimi://example.com/u/mallory".into()],
    );
    let after = mls_credential(&renamed.credential().expect("a document change verifies"));
    assert!(
        !is_successor((&before, &DEVICE), (&after, &DEVICE)),
        "PLANT-DIDWEBVH-SUCCESSOR-URI: a successor log rebound the client to another user"
    );
}

/// A DID created `portable` may move to another domain, under the draft's rule ("The
/// portability rules of {{DIDWEBVH}}, including that `portable` can only be set in the first entry and that a moved DID
/// lists its previous DID in `alsoKnownAs`, MUST be checked for every entry"; "The SCID of the log is the credential's
/// identity. The DID string can change if the controller moves the DID, but the SCID cannot"). The hub names the user by
/// the `mimi:` URI and never compares the DID's domain with it: a portable DID on one domain names a user of another
/// provider; after a move the same user is named and the moved log succeeds the old one; a move that does not list the
/// previous DID does not verify and names no one.
#[test]
fn a_portable_did_names_its_mimi_uri_wherever_the_did_lives() {
    let agent = "mimi://b.example/u/agent7".to_string();
    let mut log = PortableLog::create("fleet-a.example", "agent7", 4, &[DEVICE], &[agent.clone()]);
    let on_a = mls_credential(&log.credential().expect("a portable first entry verifies"));
    assert_eq!(
        user_uri(&on_a, &DEVICE).as_deref(),
        Some(agent.as_str()),
        "the DID's domain (fleet-a.example) is not the URI's provider (b.example), and the URI is still read"
    );

    let mut unlisted =
        PortableLog::create("fleet-a.example", "agent8", 5, &[DEVICE], &[agent.clone()]);
    unlisted.append("fleet-c.example", &[DEVICE], &[agent.clone()]);
    assert!(
        unlisted.credential().is_none(),
        "a move that does not list the previous DID in alsoKnownAs does not verify"
    );

    let previous = log.did_at("fleet-a.example");
    log.append("fleet-c.example", &[DEVICE], &[previous, agent.clone()]);
    let on_c = mls_credential(
        &log.credential()
            .expect("a move listing the previous DID verifies"),
    );
    assert_eq!(user_uri(&on_c, &DEVICE).as_deref(), Some(agent.as_str()));
    assert!(
        is_successor((&on_a, &DEVICE), (&on_c, &DEVICE)),
        "the moved log keeps its SCID and extends the old one"
    );
}

/// A user renamed in the log (a new `mimi:` URI, the same SCID) is not a successor, whether the DID stays or moves with
/// it: the hub binds a client to the user its URI names, so a renamed member leaves each room and joins again under its
/// new URI. Both logs verify, and both are the same identity to the draft (same SCID, the old log a prefix of the new),
/// so this refusal is the URI rule's alone.
#[test]
fn a_user_renamed_in_its_log_is_not_a_successor() {
    let old = "mimi://fleet-a.example/u/agent9".to_string();
    let new = "mimi://fleet-b.example/u/agent9".to_string();
    let mut log = PortableLog::create("fleet-a.example", "agent9", 6, &[DEVICE], &[old.clone()]);
    let before = mls_credential(&log.credential().unwrap());
    let previous = log.did_at("fleet-a.example");
    log.append("fleet-b.example", &[DEVICE], &[previous, new.clone()]);
    let after = mls_credential(&log.credential().expect("a move with a new URI verifies"));
    assert_eq!(user_uri(&after, &DEVICE).as_deref(), Some(new.as_str()));
    let (Some(before_log), Some(after_log)) = (
        super::verified_log(&before, &DEVICE),
        super::verified_log(&after, &DEVICE),
    ) else {
        panic!("both logs verify and bind");
    };
    assert!(
        mls_didwebvh::rules::is_valid_successor(&before_log, &after_log),
        "to the draft the renamed log is the same identity, extended"
    );
    assert!(
        !is_successor((&before, &DEVICE), (&after, &DEVICE)),
        "PLANT-DIDWEBVH-RENAME: a renamed user's leaf was taken as a successor"
    );
}

/// A credential's verification is remembered by its bytes, outcome and all, and the oldest is let go past the bound.
#[test]
fn verified_logs_are_remembered_within_their_bound() {
    let logs = VerifiedLogs::with_limits(usize::MAX, 2);
    let one = log("alice", 1, &[DEVICE], &[ALICE])
        .credential()
        .unwrap()
        .encode()
        .unwrap();
    let two = log("bob", 2, &[DEVICE], &[ALICE])
        .credential()
        .unwrap()
        .encode()
        .unwrap();
    let three = log("carol", 3, &[DEVICE], &[ALICE])
        .credential()
        .unwrap()
        .encode()
        .unwrap();
    let first = logs.verify(&one).unwrap();
    assert!(std::sync::Arc::ptr_eq(&first, &logs.verify(&one).unwrap()));
    assert!(logs.verify(b"not a credential").is_none());
    assert_eq!(logs.remembered(), 2);
    logs.verify(&two).unwrap();
    logs.verify(&three).unwrap();
    assert_eq!(logs.remembered(), 2);
    assert!(
        !std::sync::Arc::ptr_eq(&first, &logs.verify(&one).unwrap()),
        "the oldest was let go and verified again"
    );
}

/// Nothing outside this module reads a credential's content, a did_webvh log, or the Basic-only helpers that do: every
/// read of a user from a credential goes through `credential`, so a credential type is handled in one place. Revert
/// check: read `serialized_content()` in another hub module, and this fails naming it.
#[test]
fn no_other_module_reads_a_credential() {
    // An added client's identity from the Commit decoder is a Basic credential's only, so its user is read here too
    // (`added_user`), never from that field elsewhere.
    const READS: [&str; 9] = [
        "serialized_content(",
        "BasicCredential::try_from",
        "keypackage_basic_identity",
        "requester_credential_identity",
        "verify_credential(",
        "DidWebvhCredential::decode",
        "added.identity",
        "client.identity",
        "add.identity",
    ];
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut found = Vec::new();
    let mut scanned = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if path.extension().is_none_or(|ext| ext != "rs") {
            continue;
        }
        // Test code builds and inspects credentials freely; the rule is for the hub's own code.
        if name == "credential.rs"
            || name.ends_with("_tests.rs")
            || name == "mls_fixtures.rs"
            || name == "didwebvh_fixtures.rs"
        {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        // The hub's code is what comes before an inline test module, if the file has one.
        let code = text.split("#[cfg(test)]\nmod tests").next().unwrap();
        let squeezed: String = code.chars().filter(|c| !c.is_whitespace()).collect();
        for read in READS {
            if squeezed.contains(read) {
                found.push(format!("{name}: {read}"));
            }
        }
        scanned += 1;
    }
    assert!(
        scanned > 40,
        "the scan found only {scanned} hub source files in {}",
        dir.display()
    );
    assert!(
        found.is_empty(),
        "PLANT-CREDENTIAL-GUARD: credential reads outside credential.rs: {found:?}"
    );
}

/// The did_webvh code points the linked mls-didwebvh crate defaults to: credential type 0x0008 and record component
/// 0xF013. The draft asks IANA for "TBD1 (suggested value 0x0008)" and has implementations "use the suggested value
/// 0xF013" until IANA assigns one; the crate, and the implementation built on it, use 0x0008. A new revision that
/// changes either is a deliberate change of what this hub interoperates with.
#[test]
fn the_did_webvh_crate_gives_its_code_points() {
    let points = mls_didwebvh::CodePoints::DEFAULT;
    assert_eq!(
        (points.credential_type(), points.heads_component()),
        (0x0008, 0xF013)
    );
    assert_eq!(DID_WEBVH, points, "the hub reads the crate's code points");
}
