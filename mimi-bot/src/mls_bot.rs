//! The real MLS client logic: join a room from an inbound Welcome, process an inbound application
//! message, and produce a reply. No mock state anywhere in this module - every operation is a real
//! `openmls` call over `mimi-bot`'s own [`crate::identity::Identity`].
//!
//! Wire contract for the two byte blobs this module consumes/produces (grounded against
//! `mimi-core::gate::mimi_gate_welcome` and `mimi-hubd`'s own `real_mls_envelope_bytes` test
//! helper, not assumed): a Welcome fetched from `GET /mimi/v1/welcome` is an `MlsMessageIn`-wrapped
//! `Welcome` (`MlsMessageBodyIn::Welcome`); a message fetched from `GET /mimi/v1/message` (or sent
//! via `POST /mimi/v1/submitMessage`) is an `MlsMessageIn`/`MlsMessageOut`-wrapped
//! `PrivateMessage`/`PublicMessage` (whichever wire format the sender's own `MlsGroup` local policy
//! chose - `process_message` accepts either).

use std::collections::HashMap;

use mimi_core::uri::MimiUri;
use openmls::group::{MlsGroup, MlsGroupJoinConfig, StagedWelcome};
use openmls::prelude::{MlsMessageBodyIn, MlsMessageIn, ProcessedMessageContent, ProtocolMessage};
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};

use crate::identity::Identity;

#[derive(Debug, thiserror::Error)]
pub enum BotError {
    #[error("malformed MlsMessage: {0}")]
    Decode(String),
    #[error("expected a Welcome, got a different MlsMessage body")]
    NotAWelcome,
    #[error("could not join the group from this Welcome: {0}")]
    JoinFailed(String),
    #[error("could not process the incoming message: {0}")]
    ProcessFailed(String),
    #[error("could not create the reply message: {0}")]
    ReplyFailed(String),
    #[error("sender credential is not valid UTF-8, cannot address a reply")]
    NonUtf8SenderIdentity,
    #[error("sender credential is not a mimi:// user URI: {0}")]
    SenderNotAMimiUserUri(String),
    #[error("already at the concurrent-room cap ({0}); dropping this invitation")]
    RoomCapReached(usize),
    #[error("Welcome names a group with {member_count} members (max {max}); refusing to join - resource-exhaustion guard, not a trust decision")]
    WelcomeTooLarge { member_count: usize, max: usize },
}

/// Malicious-input resource control (neutral capacity admission, not a trust decision - same
/// framing as `Rooms::max_rooms`): the largest group mimi-bot will materialize from a single
/// Welcome. Generous above any real interop-test scenario (this bot is a 1:1 test partner) while
/// still bounding a hostile Welcome's resource cost.
const MAX_WELCOME_MEMBERS: usize = 256;

/// One room mimi-bot has joined: the live `MlsGroup` handle (state lives in `Identity::provider`'s
/// in-process storage - see `identity.rs`'s module doc on why this does not survive a restart).
/// `room_uri` is remembered from the Welcome that created this Room - a second gutcheck pass found
/// that trusting a PER-EVENT `room_uri` (queue metadata, not cryptographically tied to the MLS
/// `group_id`) for where to route a REPLY lets a submitter address a real group-A ciphertext under
/// a claimed `room=B`, misrouting the reply. The `Room`'s OWN join-time `room_uri` is what every
/// later reply for this group uses instead - the group is still selected by the ciphertext's own
/// `group_id` (secure), only the OUTGOING reply's destination now comes from this remembered value.
pub struct Room {
    pub group: MlsGroup,
    pub room_uri: String,
}

/// `(room_uri, recipient_username_bytes, reply_message_bytes)` - which room to fan the reply into
/// (the Room's OWN remembered room_uri, not a per-event claim), who the sender was (for rate
/// limiting), and the real `MlsMessageOut`-serialized ciphertext to send.
pub type ReplyToSend = (String, Vec<u8>, Vec<u8>);

/// mimi-bot's joined-room registry, capped at `max_rooms` (a resource-exhaustion guard per the
/// plan's own risk callout, not a trust boundary - mimi-bot still accepts every invitation up to
/// the cap, unconditionally).
pub struct Rooms {
    by_group_id: HashMap<Vec<u8>, Room>,
    max_rooms: usize,
}

impl Rooms {
    pub fn new(max_rooms: usize) -> Self {
        Self {
            by_group_id: HashMap::new(),
            max_rooms,
        }
    }

    pub fn len(&self) -> usize {
        self.by_group_id.len()
    }

    /// Process one Welcome fetched from `GET /mimi/v1/welcome`: decode, gate-shaped-decode
    /// (ciphersuite correctness is enforced upstream by the provider's own K5 gate before this
    /// bot ever sees the bytes; this call still fails closed on anything undecodable), and join.
    /// Unconditional accept, per this dispatch's design (see README.md Security section) - the
    /// ONLY refusal here is the resource cap, never a trust decision about the inviter.
    ///
    /// The MlsMessage body variant is decoded FIRST, and the room-count cap is checked only once
    /// we know this is actually a Welcome (a second gutcheck pass found the cap checked BEFORE
    /// decoding meant that once at the cap, EVERY leased event - including an ordinary application
    /// message for an already-tracked room - was misclassified as a rejected Welcome by the
    /// caller's fallback logic and permanently acked without ever being processed).
    pub fn accept_welcome(
        &mut self,
        identity: &Identity,
        room_uri: &str,
        welcome_bytes: &[u8],
    ) -> Result<Vec<u8>, BotError> {
        let mut slice = welcome_bytes;
        let msg = MlsMessageIn::tls_deserialize(&mut slice)
            .map_err(|e| BotError::Decode(format!("{e:?}")))?;
        let welcome = match msg.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => return Err(BotError::NotAWelcome),
        };
        if self.by_group_id.len() >= self.max_rooms {
            return Err(BotError::RoomCapReached(self.max_rooms));
        }
        // `ratchet_tree: None` - mimi-bot has no side channel to fetch the tree separately, so it
        // can only join a Welcome whose sender included the ratchet_tree GroupInfo extension
        // (`use_ratchet_tree_extension(true)` on the inviter's own MlsGroupCreateConfig - the
        // common/default way a real implementation lets a brand-new joiner reconstruct the tree).
        // A conformant Welcome that omits it is honestly rejected below (JoinFailed), not silently
        // half-joined - documented in README.md's Security section as a real interop precondition.
        let join_config = MlsGroupJoinConfig::builder().build();
        let staged =
            StagedWelcome::new_from_welcome(&identity.provider, &join_config, welcome, None)
                .map_err(|e| BotError::JoinFailed(format!("{e:?}")))?;
        // Malicious-input resource control: a hostile Welcome could name a group whose tree is
        // enormous (a resource-exhaustion attempt via a single accepted invitation, on top of the
        // room-count cap above which only bounds HOW MANY rooms, not the SIZE of any one of them).
        // Check the member count from the STAGED welcome (cheap - already parsed) before spending
        // the cost of materializing the full group.
        let member_count = staged.members().count();
        if member_count > MAX_WELCOME_MEMBERS {
            return Err(BotError::WelcomeTooLarge {
                member_count,
                max: MAX_WELCOME_MEMBERS,
            });
        }
        let group = staged
            .into_group(&identity.provider)
            .map_err(|e| BotError::JoinFailed(format!("{e:?}")))?;
        let group_id = group.group_id().as_slice().to_vec();
        self.by_group_id.insert(
            group_id.clone(),
            Room {
                group,
                room_uri: room_uri.to_string(),
            },
        );
        Ok(group_id)
    }

    /// Process one message fetched from `GET /mimi/v1/message` against whichever room it belongs
    /// to. Returns `Some((group_id, reply_bytes))` when the message was an application message
    /// mimi-bot should echo back; `None` when it was a Commit (already merged into the group's
    /// state - no reply needed) or the message could not be matched to a room we're tracking
    /// (dropped, not an error - a room from before a restart, see identity.rs's module doc).
    pub fn process_and_reply(
        &mut self,
        identity: &Identity,
        message_bytes: &[u8],
    ) -> Result<Option<ReplyToSend>, BotError> {
        let mut slice = message_bytes;
        let msg = MlsMessageIn::tls_deserialize(&mut slice)
            .map_err(|e| BotError::Decode(format!("{e:?}")))?;
        let protocol_message: ProtocolMessage = msg
            .try_into_protocol_message()
            .map_err(|e| BotError::Decode(format!("{e:?}")))?;
        let group_id_bytes = protocol_message.group_id().as_slice().to_vec();
        let Some(room) = self.by_group_id.get_mut(&group_id_bytes) else {
            // Not a room we're currently tracking (e.g. from a pre-restart membership) - drop
            // silently rather than error; this is expected under the disclosed memory-only
            // simplification, not a protocol violation.
            return Ok(None);
        };

        let processed = room
            .group
            .process_message(&identity.provider, protocol_message)
            .map_err(|e| BotError::ProcessFailed(format!("{e:?}")))?;
        let sender_credential = processed.credential().clone();

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app_msg) => {
                // Self-echo loop prevention: `submit_room_event` no longer excludes any sender
                // from fan-out (a second gutcheck pass found a caller-supplied exclusion hint let
                // a lying submitter suppress delivery to a REAL other participant), so mimi-bot's
                // own prior echo now arrives back in its own inbox like any other room traffic.
                // Recognize it by credential identity and drop it here rather than replying to
                // its own echo forever.
                if sender_credential.serialized_content() == identity.own_uri().as_bytes() {
                    return Ok(None);
                }
                let plaintext = app_msg.into_bytes();
                let sender_username = sender_recipient_username(&sender_credential)?;
                let reply_text =
                    format!("[mimi-bot] echo: {}", String::from_utf8_lossy(&plaintext));
                let reply_out = room
                    .group
                    .create_message(&identity.provider, identity.signer(), reply_text.as_bytes())
                    .map_err(|e| BotError::ReplyFailed(format!("{e:?}")))?;
                let reply_bytes = reply_out
                    .tls_serialize_detached()
                    .map_err(|e| BotError::ReplyFailed(format!("{e:?}")))?;
                // room.room_uri (remembered at join time), NOT any per-event queue metadata - see
                // the Room/ReplyToSend doc comments for why trusting a per-event room_uri claim
                // for the OUTGOING reply destination was a real misrouting risk.
                Ok(Some((
                    room.room_uri.clone(),
                    sender_username.into_bytes(),
                    reply_bytes,
                )))
            }
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                room.group
                    .merge_staged_commit(&identity.provider, *staged_commit)
                    .map_err(|e| BotError::ProcessFailed(format!("merge_staged_commit: {e:?}")))?;
                // RFC 9420 removal handling: a Commit that removes mimi-bot's own leaf flips the
                // group to MlsGroupState::Inactive on merge (openmls's own tracked state - not
                // something we infer from the member list ourselves). Stop tracking the room
                // immediately: no further sends, and the group's own secrets are dropped along
                // with the Room value (Rust drop, not a separate wipe step) rather than retained
                // past the point of membership - the room-cap/resource-guard purpose this
                // registry serves is also why a stale inactive room must not linger.
                if !room.group.is_active() {
                    self.by_group_id.remove(&group_id_bytes);
                }
                Ok(None)
            }
            // Proposal-only messages (no Commit yet) and external-join messages: nothing to merge
            // or reply to. mimi-bot never itself proposes external joins/commits (INV-MLS-001a/1b
            // scope - it only ever accepts what it's sent), so these are inert to it either way.
            _ => Ok(None),
        }
    }
}

/// Extract the bare local username to reply to from a sender's credential, per Haven's
/// `BasicCredential::new(uri.as_bytes())` convention (see `mimi-core::protocol_wire`'s
/// `requester_credential_identity` doc) - the credential identity bytes decode as a `mimi://` user
/// URI, and `?recipient=` on `submitMessage` is the bare `path` segment (mirrors mimi-provider's
/// own bare-username convention for `?user=`/`?recipient=`, confirmed against its `http.rs`).
fn sender_recipient_username(
    credential: &openmls::prelude::Credential,
) -> Result<String, BotError> {
    let identity_bytes = credential.serialized_content();
    let identity_str =
        std::str::from_utf8(identity_bytes).map_err(|_| BotError::NonUtf8SenderIdentity)?;
    let uri = MimiUri::parse(identity_str)
        .map_err(|e| BotError::SenderNotAMimiUserUri(format!("{identity_str:?}: {e}")))?;
    if uri.kind != Some(mimi_core::uri::MimiKind::User) {
        return Err(BotError::SenderNotAMimiUserUri(identity_str.to_string()));
    }
    Ok(uri.path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openmls::ciphersuite::signature::SignaturePublicKey;
    use openmls::credentials::{BasicCredential, CredentialWithKey};
    use openmls::group::MlsGroupCreateConfig;
    use openmls::prelude::{Ciphersuite, KeyPackageIn, OpenMlsCrypto, SignatureScheme};
    use openmls_rust_crypto::OpenMlsRustCrypto;
    use openmls_traits::signatures::{Signer as SignerTrait, SignerError};
    use openmls_traits::OpenMlsProvider;
    // tls_codec's Serialize/Deserialize traits are already in scope via `use super::*` (mls_bot.rs
    // imports them as TlsDeserialize/TlsSerialize).

    const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    struct TestSigner {
        key: Vec<u8>,
        scheme: SignatureScheme,
    }
    impl SignerTrait for TestSigner {
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

    /// A real external MIMI implementation stand-in: its own provider/signer/credential, used to
    /// create a group and invite mimi-bot's real `Identity` into it exactly the way a hackathon
    /// attendee's own client would.
    struct TestParty {
        provider: OpenMlsRustCrypto,
        signer: TestSigner,
        cwk: CredentialWithKey,
    }
    impl TestParty {
        fn new(uri: &str) -> Self {
            let provider = OpenMlsRustCrypto::default();
            let scheme = SignatureScheme::ED25519;
            let (priv_b, pub_b) = provider.crypto().signature_key_gen(scheme).unwrap();
            let pk = SignaturePublicKey::try_from(pub_b).unwrap();
            let cwk = CredentialWithKey {
                credential: BasicCredential::new(uri.as_bytes().to_vec()).into(),
                signature_key: pk,
            };
            Self {
                provider,
                signer: TestSigner {
                    key: priv_b,
                    scheme,
                },
                cwk,
            }
        }
    }

    fn tester_group_config() -> MlsGroupCreateConfig {
        // use_ratchet_tree_extension(true): mimi-bot's join_config passes ratchet_tree: None (no
        // side channel), so the INVITER must carry the tree in the Welcome's GroupInfo - see the
        // comment on accept_welcome above.
        MlsGroupCreateConfig::builder()
            .ciphersuite(SUITE)
            .use_ratchet_tree_extension(true)
            .build()
    }

    /// Build a real KeyPackage for `bot_identity`, exactly the bytes it would publish via
    /// `POST /mimi/v1/keyMaterial/ingest`, decoded+validated the way a real inviter would before
    /// using it in `add_members` - proves the wire bytes are usable, not just well-formed.
    fn bot_key_package_for_add(
        bot_identity: &Identity,
        tester: &TestParty,
    ) -> openmls::prelude::KeyPackage {
        let kp_bytes = bot_identity.fresh_key_package_bytes(0).unwrap();
        let mut slice = kp_bytes.as_slice();
        KeyPackageIn::tls_deserialize(&mut slice)
            .unwrap()
            .validate(
                tester.provider.crypto(),
                openmls::versions::ProtocolVersion::Mls10,
            )
            .unwrap()
    }

    #[test]
    fn full_round_trip_join_echo_and_tester_decrypts_the_reply() {
        let tester = TestParty::new("mimi://a.example/u/alice");
        let bot_identity = Identity::generate("mimi://bot.example.org/u/mimi-bot").unwrap();

        let cfg = tester_group_config();
        let mut tester_group =
            MlsGroup::new(&tester.provider, &tester.signer, &cfg, tester.cwk.clone()).unwrap();

        let kp = bot_key_package_for_add(&bot_identity, &tester);
        let (_commit, welcome_out, _group_info) = tester_group
            .add_members(&tester.provider, &tester.signer, &[kp])
            .unwrap();
        tester_group.merge_pending_commit(&tester.provider).unwrap();
        let welcome_bytes = welcome_out.tls_serialize_detached().unwrap();

        // mimi-bot accepts the Welcome exactly as it would arrive from GET /mimi/v1/welcome.
        let mut rooms = Rooms::new(10);
        let group_id = rooms
            .accept_welcome(&bot_identity, "mimi://a.example/r/x", &welcome_bytes)
            .unwrap();
        assert_eq!(rooms.len(), 1);
        assert_eq!(group_id, tester_group.group_id().as_slice().to_vec());

        // Tester sends a real application message into the (now 2-member) group.
        let app_out = tester_group
            .create_message(&tester.provider, &tester.signer, b"hello mimi-bot")
            .unwrap();
        let app_bytes = app_out.tls_serialize_detached().unwrap();

        // mimi-bot processes it exactly as it would arrive from GET /mimi/v1/message, and produces
        // a real echo reply addressed back to the tester's bare username, into the Room's OWN
        // remembered room_uri (not a per-event claim).
        let (reply_room_uri, recipient, reply_bytes) = rooms
            .process_and_reply(&bot_identity, &app_bytes)
            .unwrap()
            .expect("an application message must produce a reply");
        assert_eq!(reply_room_uri, "mimi://a.example/r/x");
        assert_eq!(
            recipient, b"alice",
            "reply must be addressed to the sender's bare username"
        );

        // Round-trip proof: the TESTER'S OWN group decrypts the reply and sees the real echo text -
        // not a canned response, the actual openmls ciphertext mimi-bot produced.
        let mut reply_slice = reply_bytes.as_slice();
        let reply_in = MlsMessageIn::tls_deserialize(&mut reply_slice).unwrap();
        let reply_protocol: ProtocolMessage = reply_in.try_into_protocol_message().unwrap();
        let processed = tester_group
            .process_message(&tester.provider, reply_protocol)
            .unwrap();
        let plaintext = match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(am) => am.into_bytes(),
            other => panic!("expected an application message, got {other:?}"),
        };
        assert_eq!(
            String::from_utf8(plaintext).unwrap(),
            "[mimi-bot] echo: hello mimi-bot"
        );
    }

    #[test]
    fn a_commit_removing_mimi_bot_stops_tracking_the_room_rfc9420() {
        let tester = TestParty::new("mimi://a.example/u/alice");
        let bot_identity = Identity::generate("mimi://bot.example.org/u/mimi-bot").unwrap();

        let cfg = tester_group_config();
        let mut tester_group =
            MlsGroup::new(&tester.provider, &tester.signer, &cfg, tester.cwk.clone()).unwrap();
        let kp = bot_key_package_for_add(&bot_identity, &tester);
        let (_commit, welcome_out, _gi) = tester_group
            .add_members(&tester.provider, &tester.signer, &[kp])
            .unwrap();
        tester_group.merge_pending_commit(&tester.provider).unwrap();
        let welcome_bytes = welcome_out.tls_serialize_detached().unwrap();

        let mut rooms = Rooms::new(10);
        rooms
            .accept_welcome(&bot_identity, "mimi://a.example/r/x", &welcome_bytes)
            .unwrap();
        assert_eq!(rooms.len(), 1);

        // Tester removes mimi-bot (find its leaf index by credential identity, not an assumed
        // constant - the real, general way any implementation would locate a member to remove).
        let bot_leaf = tester_group
            .members()
            .find(|m| m.credential.serialized_content() == b"mimi://bot.example.org/u/mimi-bot")
            .expect("mimi-bot must be a member before it can be removed")
            .index;
        let (remove_commit, _welcome, _gi) = tester_group
            .remove_members(&tester.provider, &tester.signer, &[bot_leaf])
            .unwrap();
        tester_group.merge_pending_commit(&tester.provider).unwrap();
        let remove_bytes = remove_commit.tls_serialize_detached().unwrap();

        let result = rooms
            .process_and_reply(&bot_identity, &remove_bytes)
            .unwrap();
        assert!(result.is_none(), "a Remove-Commit produces no reply");
        assert_eq!(
            rooms.len(),
            0,
            "the room must stop being tracked once mimi-bot is removed"
        );

        // A follow-up event for the same (now-forgotten) group is dropped, not an error - same
        // contract as any other untracked-room event.
        let app_out = tester_group
            .create_message(&tester.provider, &tester.signer, b"anyone still there?")
            .unwrap();
        let app_bytes = app_out.tls_serialize_detached().unwrap();
        let result2 = rooms.process_and_reply(&bot_identity, &app_bytes).unwrap();
        assert!(result2.is_none());
    }

    #[test]
    fn accept_welcome_rejects_a_welcome_naming_too_large_a_group() {
        // A real KeyPackage build + a real Welcome, but for a group whose member count exceeds
        // MAX_WELCOME_MEMBERS - proves the pre-check runs on the ACTUAL parsed member count, not a
        // trust decision about the inviter.
        let tester = TestParty::new("mimi://a.example/u/alice");
        let bot_identity = Identity::generate("mimi://bot.example.org/u/mimi-bot").unwrap();
        let cfg = tester_group_config();
        let mut tester_group =
            MlsGroup::new(&tester.provider, &tester.signer, &cfg, tester.cwk.clone()).unwrap();

        // Pad the group past the cap with throwaway members before inviting mimi-bot.
        let mut filler_kps = Vec::new();
        for i in 0..MAX_WELCOME_MEMBERS {
            let filler = TestParty::new(&format!("mimi://a.example/u/filler{i}"));
            let filler_kp_bytes = {
                let lifetime = openmls::prelude::Lifetime::new(60 * 60 * 24);
                openmls::prelude::KeyPackage::builder()
                    .key_package_extensions(openmls::prelude::Extensions::empty())
                    .key_package_lifetime(lifetime)
                    .build(SUITE, &tester.provider, &filler.signer, filler.cwk.clone())
                    .unwrap()
                    .key_package()
                    .tls_serialize_detached()
                    .unwrap()
            };
            let mut slice = filler_kp_bytes.as_slice();
            let filler_kp = KeyPackageIn::tls_deserialize(&mut slice)
                .unwrap()
                .validate(
                    tester.provider.crypto(),
                    openmls::versions::ProtocolVersion::Mls10,
                )
                .unwrap();
            filler_kps.push(filler_kp);
        }
        tester_group
            .add_members(&tester.provider, &tester.signer, &filler_kps)
            .unwrap();
        tester_group.merge_pending_commit(&tester.provider).unwrap();

        // Now invite mimi-bot into the now-oversized group.
        let kp = bot_key_package_for_add(&bot_identity, &tester);
        let (_commit, welcome_out, _gi) = tester_group
            .add_members(&tester.provider, &tester.signer, &[kp])
            .unwrap();
        let welcome_bytes = welcome_out.tls_serialize_detached().unwrap();

        let mut rooms = Rooms::new(10);
        let err = rooms
            .accept_welcome(&bot_identity, "mimi://a.example/r/x", &welcome_bytes)
            .unwrap_err();
        assert!(
            matches!(err, BotError::WelcomeTooLarge { .. }),
            "expected WelcomeTooLarge, got {err:?}"
        );
        assert_eq!(
            rooms.len(),
            0,
            "a rejected Welcome must not be tracked as a room"
        );
    }

    #[test]
    fn accept_welcome_refuses_once_the_room_cap_is_reached() {
        let tester = TestParty::new("mimi://a.example/u/alice");
        let bot_identity = Identity::generate("mimi://bot.example.org/u/mimi-bot").unwrap();
        let cfg = tester_group_config();
        let mut rooms = Rooms::new(1);

        let mut tester_group =
            MlsGroup::new(&tester.provider, &tester.signer, &cfg, tester.cwk.clone()).unwrap();
        let kp = bot_key_package_for_add(&bot_identity, &tester);
        let (_c, welcome_out, _gi) = tester_group
            .add_members(&tester.provider, &tester.signer, &[kp])
            .unwrap();
        let welcome_bytes = welcome_out.tls_serialize_detached().unwrap();
        rooms
            .accept_welcome(&bot_identity, "mimi://a.example/r/x", &welcome_bytes)
            .unwrap();
        assert_eq!(rooms.len(), 1);

        // Second room: refused, at the cap - a resource guard, not a trust decision (mimi-bot
        // still would have accepted this invitation unconditionally were it not at the cap).
        let mut tester_group2 =
            MlsGroup::new(&tester.provider, &tester.signer, &cfg, tester.cwk.clone()).unwrap();
        let kp2 = bot_key_package_for_add(&bot_identity, &tester);
        let (_c, welcome_out2, _gi) = tester_group2
            .add_members(&tester.provider, &tester.signer, &[kp2])
            .unwrap();
        let welcome_bytes2 = welcome_out2.tls_serialize_detached().unwrap();
        let err = rooms
            .accept_welcome(&bot_identity, "mimi://a.example/r/y", &welcome_bytes2)
            .unwrap_err();
        assert!(matches!(err, BotError::RoomCapReached(1)));
    }

    #[test]
    fn at_the_room_cap_a_non_welcome_body_still_reports_not_a_welcome_not_room_cap() {
        // Second-gutcheck regression test: the cap check must run AFTER the body is identified as
        // a Welcome, not before - otherwise, once at the cap, an ordinary application message for
        // an ALREADY-tracked room gets misclassified as "rejected Welcome" by the poll loop's
        // fallback logic and is acked without ever being processed (the bot silently stops
        // handling all traffic once busy). Proven here at the `accept_welcome` level: garbage
        // bytes at the cap must still classify as Decode/NotAWelcome, never RoomCapReached.
        let bot_identity = Identity::generate("mimi://bot.example.org/u/mimi-bot").unwrap();
        let mut rooms = Rooms::new(0); // already "at the cap" from the start
        let err = rooms
            .accept_welcome(
                &bot_identity,
                "mimi://a.example/r/x",
                b"not a welcome at all",
            )
            .unwrap_err();
        assert!(
            matches!(err, BotError::Decode(_)),
            "a non-Welcome body must be classified by content FIRST, not short-circuited by the cap; got {err:?}"
        );
    }

    #[test]
    fn accept_welcome_rejects_a_non_welcome_body() {
        let bot_identity = Identity::generate("mimi://bot.example.org/u/mimi-bot").unwrap();
        let mut rooms = Rooms::new(10);
        let err = rooms
            .accept_welcome(
                &bot_identity,
                "mimi://a.example/r/x",
                b"not a welcome at all",
            )
            .unwrap_err();
        assert!(matches!(err, BotError::Decode(_)));
    }

    #[test]
    fn process_and_reply_drops_a_message_for_an_untracked_room() {
        // A real application message from a group mimi-bot never joined - must be dropped
        // (Ok(None)), not treated as an error, per the disclosed memory-only-state simplification
        // (identity.rs's module doc).
        let tester = TestParty::new("mimi://a.example/u/alice");
        let cfg = tester_group_config();
        let mut solo_group =
            MlsGroup::new(&tester.provider, &tester.signer, &cfg, tester.cwk.clone()).unwrap();
        let app_out = solo_group
            .create_message(&tester.provider, &tester.signer, b"nobody home")
            .unwrap();
        let app_bytes = app_out.tls_serialize_detached().unwrap();

        let bot_identity = Identity::generate("mimi://bot.example.org/u/mimi-bot").unwrap();
        let mut rooms = Rooms::new(10);
        let result = rooms.process_and_reply(&bot_identity, &app_bytes).unwrap();
        assert!(result.is_none());
    }
}
