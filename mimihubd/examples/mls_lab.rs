//! An MLS client for lab walks against a hub: the members of one room, each with its own keys and group state, making
//! the Commits and messages a walk submits through a provider's server. It reads one JSON request per line on stdin and
//! answers one JSON line on stdout, so a walk written in any language drives it as a child process.
//!
//! ```text
//! {"op":"create","room":"<room URI>","creator":"<user URI>","creator_role":2,"components":[{"id":1,"data":"<b64>"}]}
//! {"op":"add","by":"<user URI>","joiner":"<user URI>","role":3}   -> {"ok":true,"bytes":"<UpdateRequest, b64>",
//!                                                                     "commit":"<the Commit alone, b64>"}
//! {"op":"accepted","by":"<user URI>"}   the hub took by's pending Commit: merge it, and let its joiner join
//! {"op":"refused","by":"<user URI>"}    the hub refused it: clear it
//! {"op":"message","by":"<user URI>","text":"..."}                 -> {"ok":true,"bytes":"<MLSMessage, b64>"}
//! {"op":"key_package","user":"<user URI>"}                          -> {"ok":true,"bytes":"<KeyPackage, b64>"}
//! {"op":"km_request","by":"<user URI>","target":"<user URI>","room":"<room URI>"} -> a signed KeyMaterialRequest
//! {"op":"km_response","joiner":"<user URI>","response":"<b64>"}    the KeyPackage a keyMaterial answer gave, for an add
//! {"op":"join","user":"<user URI>","welcome":"<b64>"}              join from a Welcome a member's provider delivered
//! ```
//!
//! An `accepted` with `"remote": true` settles an add whose joiner is a member of another provider: it joins later, from
//! the Welcome its own provider delivers (`join`). The group carries its ratchet tree in the Welcome, so a joiner needs
//! nothing else.
//!
//! The room's group starts as the hub's `createRoom` answer says: its app data components, and a participant list
//! naming the creator in `creator_role`. An `add` is one Commit adding the joiner's client and the joiner to the
//! participant list together, sent with a Full GroupInfo and the full ratchet tree, as a room's first Commit must be to
//! give the hub its tree. A member who is not in the group yet joins from the Welcome of the Commit that added it. A
//! refused Commit's committer is dropped from the lab, since it applied its Commit before the hub answered.
//!
//! Wire formats (RFC 9420 §6): handshake messages go out as PublicMessage, so the hub can read a Commit's changes, and
//! application messages as PrivateMessage, which openmls's `create_message` always produces; a member takes either in.
//! The groups' policy is openmls's `MIXED_PLAINTEXT_WIRE_FORMAT_POLICY` for that reason.

use std::collections::HashMap;
use std::io::{BufRead, Write};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use mimi_core::participant_list::{
    encode_participant_list_data, encode_participant_list_update, ParticipantListData,
    ParticipantListUpdate, UserRolePair,
};
use mimi_core::protocol_wire::{GroupInfoOption, GroupInfoRepresentation, HandshakeBundle};
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::signatures::{Signer, SignerError};
use openmls_traits::OpenMlsProvider;
use serde_json::{json, Value};

const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
/// The participant list's app data component (protocol-07 §7.5).
const PARTICIPANT_LIST_COMPONENT: u16 = 0x0022;

struct KeySigner(Vec<u8>);

impl Signer for KeySigner {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        OpenMlsRustCrypto::default()
            .crypto()
            .sign(SignatureScheme::ED25519, payload, &self.0)
            .map_err(|_| SignerError::SigningError)
    }
    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

/// One member's client: its keys, its credential naming the user URI, and its group once it is in one.
struct Member {
    provider: OpenMlsRustCrypto,
    signer: KeySigner,
    credential: CredentialWithKey,
    group: Option<MlsGroup>,
    /// The Welcome, the joiner and its role of this member's Commit the hub has not answered yet.
    pending: Option<(Welcome, String, u32)>,
}

impl Member {
    fn new(uri: &str) -> Result<Self, String> {
        let provider = OpenMlsRustCrypto::default();
        let (private, public) = provider
            .crypto()
            .signature_key_gen(SignatureScheme::ED25519)
            .map_err(|e| format!("{e:?}"))?;
        Ok(Self {
            provider,
            signer: KeySigner(private),
            credential: CredentialWithKey {
                credential: BasicCredential::new(uri.as_bytes().to_vec()).into(),
                signature_key: SignaturePublicKey::from(public),
            },
            group: None,
            pending: None,
        })
    }

    fn key_package(&self) -> Result<KeyPackage, String> {
        Ok(KeyPackage::builder()
            .leaf_node_capabilities(capabilities())
            .build(SUITE, &self.provider, &self.signer, self.credential.clone())
            .map_err(|e| format!("{e:?}"))?
            .key_package()
            .clone())
    }
}

/// What every leaf advertises: the suite, the app data dictionary and AppDataUpdate, basic credentials.
fn capabilities() -> Capabilities {
    Capabilities::new(
        None,
        Some(&[SUITE]),
        Some(&[ExtensionType::AppDataDictionary]),
        Some(&[ProposalType::AppDataUpdate]),
        Some(&[CredentialType::Basic]),
    )
}

fn list(pairs: &[(String, u32)]) -> Result<Vec<u8>, String> {
    encode_participant_list_data(&ParticipantListData {
        participants: pairs
            .iter()
            .map(|(user, role)| UserRolePair {
                user_uri: user.clone(),
                role_index: *role,
            })
            .collect(),
    })
    .map_err(|e| format!("{e:?}"))
}

/// The lab's members, and the participant list as the room's group holds it.
struct Lab {
    members: HashMap<String, Member>,
    listed: Vec<(String, u32)>,
    /// KeyPackages a keyMaterial answer gave, by the user they are for, for that user's add.
    fetched: HashMap<String, KeyPackage>,
}

impl Lab {
    fn member(&mut self, uri: &str) -> Result<&mut Member, String> {
        if !self.members.contains_key(uri) {
            self.members.insert(uri.to_string(), Member::new(uri)?);
        }
        self.members
            .get_mut(uri)
            .ok_or_else(|| "no member".to_string())
    }

    fn create(&mut self, request: &Value) -> Result<Value, String> {
        let room = text(request, "room")?;
        let creator = text(request, "creator")?;
        let role = u32::try_from(request["creator_role"].as_u64().ok_or("creator_role")?)
            .map_err(|e| e.to_string())?;
        let mut dictionary = AppDataDictionary::new();
        for component in request["components"].as_array().ok_or("components")? {
            let id = u16::try_from(component["id"].as_u64().ok_or("component id")?)
                .map_err(|e| e.to_string())?;
            let data = STANDARD
                .decode(component["data"].as_str().ok_or("component data")?)
                .map_err(|e| e.to_string())?;
            let _ = dictionary.insert(id, data);
        }
        self.listed = vec![(creator.clone(), role)];
        let _ = dictionary.insert(PARTICIPANT_LIST_COMPONENT, list(&self.listed)?);
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(SUITE)
            .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .capabilities(capabilities())
            .with_group_context_extensions(
                Extensions::single(Extension::AppDataDictionary(
                    AppDataDictionaryExtension::new(dictionary),
                ))
                .map_err(|e| format!("{e:?}"))?,
            )
            .build();
        let member = self.member(&creator)?;
        let group = MlsGroup::new_with_group_id(
            &member.provider,
            &member.signer,
            &config,
            GroupId::from_slice(room.as_bytes()),
            member.credential.clone(),
        )
        .map_err(|e| format!("{e:?}"))?;
        member.group = Some(group);
        Ok(json!({"ok": true}))
    }

    fn add(&mut self, request: &Value) -> Result<Value, String> {
        let by = text(request, "by")?;
        let joiner = text(request, "joiner")?;
        let role =
            u32::try_from(request["role"].as_u64().ok_or("role")?).map_err(|e| e.to_string())?;
        let key_package = match self.fetched.remove(&joiner) {
            Some(fetched) => fetched,
            None => self.member(&joiner)?.key_package()?,
        };
        let mut after = self.listed.clone();
        after.push((joiner.clone(), role));
        let list_after = list(&after)?;
        let update = encode_participant_list_update(&ParticipantListUpdate {
            added_participants: vec![UserRolePair {
                user_uri: joiner.clone(),
                role_index: role,
            }],
            ..ParticipantListUpdate::default()
        })
        .map_err(|e| format!("{e:?}"))?;
        let member = self.member(&by)?;
        let group = member.group.as_mut().ok_or("not in the group")?;
        let mut stage = group
            .commit_builder()
            .propose_adds([key_package])
            .add_proposals([Proposal::AppDataUpdate(Box::new(
                AppDataUpdateProposal::update(PARTICIPANT_LIST_COMPONENT, update),
            ))])
            .load_psks(member.provider.storage())
            .map_err(|e| format!("{e:?}"))?;
        let mut updater = stage.app_data_dictionary_updater();
        updater.set(openmls::component::ComponentData::from_parts(
            PARTICIPANT_LIST_COMPONENT,
            list_after.into(),
        ));
        stage.with_app_data_dictionary_updates(updater.changes());
        let (commit, welcome, _) = stage
            .build(
                member.provider.rand(),
                member.provider.crypto(),
                &member.signer,
                |_| true,
            )
            .map_err(|e| format!("{e:?}"))?
            .stage_commit(&member.provider)
            .map_err(|e| format!("{e:?}"))?
            .into_contents();
        let welcome = welcome.ok_or("an add has a Welcome")?;
        // The GroupInfo and tree after the Commit, from the committer's view of the group with it applied.
        let after_group = {
            group
                .merge_pending_commit(&member.provider)
                .map_err(|e| format!("{e:?}"))?;
            let info: MlsMessageIn = group
                .export_group_info(member.provider.crypto(), &member.signer, false)
                .map_err(|e| format!("{e:?}"))?
                .into();
            let info = match info.extract() {
                MlsMessageBodyIn::GroupInfo(info) => info
                    .tls_serialize_detached()
                    .map_err(|e| format!("{e:?}"))?,
                _ => return Err("not a GroupInfo".into()),
            };
            let tree = group
                .export_ratchet_tree()
                .tls_serialize_detached()
                .map_err(|e| format!("{e:?}"))?;
            (info, tree)
        };
        let bare_welcome = welcome
            .tls_serialize_detached()
            .map_err(|e| format!("{e:?}"))?;
        let bundle = HandshakeBundle::Commit {
            proposal_or_commit: commit
                .tls_serialize_detached()
                .map_err(|e| format!("{e:?}"))?,
            welcome: Some(bare_welcome),
            group_info_option: GroupInfoOption {
                representation: GroupInfoRepresentation::Full,
                payload: after_group.0,
            },
            ratchet_tree_option: [&[1u8][..], &after_group.1].concat(),
        }
        .encode()
        .map_err(|e| format!("{e:?}"))?;
        member.pending = Some((welcome, joiner, role));
        Ok(
            json!({"ok": true, "bytes": STANDARD.encode(bundle), "commit": STANDARD.encode(
                commit.tls_serialize_detached().map_err(|e| format!("{e:?}"))?
            )}),
        )
    }

    /// The hub took `by`'s Commit: its group is already at the new epoch; the joiner joins from the Welcome.
    fn accepted(&mut self, request: &Value) -> Result<Value, String> {
        let by = text(request, "by")?;
        let member = self.member(&by)?;
        let (welcome, joiner, role) = member.pending.take().ok_or("nothing pending")?;
        if request["remote"].as_bool() == Some(true) {
            self.listed.push((joiner, role));
            return Ok(json!({"ok": true, "listed": self.listed.len()}));
        }
        let tree = member
            .group
            .as_ref()
            .ok_or("not in the group")?
            .export_ratchet_tree();
        let joining = self.member(&joiner)?;
        let group = StagedWelcome::new_from_welcome(
            &joining.provider,
            &MlsGroupJoinConfig::builder()
                .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
                .build(),
            welcome,
            Some(tree.into()),
        )
        .map_err(|e| format!("{e:?}"))?
        .into_group(&joining.provider)
        .map_err(|e| format!("{e:?}"))?;
        joining.group = Some(group);
        self.listed.push((joiner, role));
        Ok(json!({"ok": true, "listed": self.listed.len()}))
    }

    fn refused(&mut self, request: &Value) -> Result<Value, String> {
        let by = text(request, "by")?;
        let member = self.member(&by)?;
        // The committer applied its Commit to read the GroupInfo after it; the hub did not, so that group is ahead of
        // the room's and is dropped.
        member.pending = None;
        member.group = None;
        Ok(
            json!({"ok": true, "note": "the committer's group is dropped: it moved on without the hub"}),
        )
    }

    /// A KeyPackage for `user`, its private keys kept here for the join, to publish through its provider.
    fn key_package(&mut self, request: &Value) -> Result<Value, String> {
        let user = text(request, "user")?;
        let key_package = self.member(&user)?.key_package()?;
        Ok(json!({"ok": true, "bytes": STANDARD.encode(
            key_package.tls_serialize_detached().map_err(|e| format!("{e:?}"))?
        )}))
    }

    /// `by`'s keyMaterial request for `target` in `room` (protocol-07 §5.2), signed with `by`'s MLS key.
    fn km_request(&mut self, request: &Value) -> Result<Value, String> {
        let by = text(request, "by")?;
        let target = text(request, "target")?;
        let room = text(request, "room")?;
        let member = self.member(&by)?;
        let mut km = mimi_core::protocol_wire::KeyMaterialRequest::minimal(&by, &target)
            .map_err(|e| format!("{e:?}"))?;
        km.room_id = mimi_core::protocol_wire::IdentifierUri(room);
        km.requester_signature_key = member.credential.signature_key.clone();
        km.requester_credential = member.credential.credential.clone();
        km.sign(&member.signer).map_err(|e| format!("{e:?}"))?;
        Ok(
            json!({"ok": true, "bytes": STANDARD.encode(km.encode().map_err(|e| format!("{e:?}"))?)}),
        )
    }

    /// Read a keyMaterial answer: keep the KeyPackage it gave for `joiner`'s add.
    fn km_response(&mut self, request: &Value) -> Result<Value, String> {
        let joiner = text(request, "joiner")?;
        let bytes = STANDARD
            .decode(text(request, "response")?)
            .map_err(|e| e.to_string())?;
        let response = mimi_core::protocol_wire::KeyMaterialResponse::decode(&bytes, &[0x0001])
            .map_err(|e| format!("{e:?}"))?;
        let mimi_core::protocol_wire::KeyMaterialResponse::Success { key_package, .. } = response
        else {
            return Err(format!("no KeyPackage: {response:?}"));
        };
        let key_package_in = KeyPackageIn::tls_deserialize_exact(key_package.as_slice())
            .map_err(|e| format!("{e:?}"))?;
        let validated = key_package_in
            .validate(
                OpenMlsRustCrypto::default().crypto(),
                ProtocolVersion::Mls10,
            )
            .map_err(|e| format!("{e:?}"))?;
        self.fetched.insert(joiner, validated);
        Ok(json!({"ok": true}))
    }

    /// `user` joins from a Welcome its provider delivered (bare, or as an MLSMessage).
    fn join(&mut self, request: &Value) -> Result<Value, String> {
        let user = text(request, "user")?;
        let bytes = STANDARD
            .decode(text(request, "welcome")?)
            .map_err(|e| e.to_string())?;
        let welcome = match MlsMessageIn::tls_deserialize_exact(bytes.as_slice()) {
            Ok(message) => match message.extract() {
                MlsMessageBodyIn::Welcome(welcome) => welcome,
                _ => return Err("not a Welcome".into()),
            },
            Err(_) => {
                Welcome::tls_deserialize_exact(bytes.as_slice()).map_err(|e| format!("{e:?}"))?
            }
        };
        let joining = self.member(&user)?;
        let group = StagedWelcome::new_from_welcome(
            &joining.provider,
            &MlsGroupJoinConfig::builder()
                .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
                .build(),
            welcome,
            None,
        )
        .map_err(|e| format!("{e:?}"))?
        .into_group(&joining.provider)
        .map_err(|e| format!("{e:?}"))?;
        let epoch = group.epoch().as_u64();
        joining.group = Some(group);
        Ok(json!({"ok": true, "epoch": epoch}))
    }

    fn message(&mut self, request: &Value) -> Result<Value, String> {
        let by = text(request, "by")?;
        let body = text(request, "text")?;
        let member = self.member(&by)?;
        let group = member.group.as_mut().ok_or("not in the group")?;
        let message = group
            .create_message(&member.provider, &member.signer, body.as_bytes())
            .map_err(|e| format!("{e:?}"))?;
        Ok(
            json!({"ok": true, "bytes": STANDARD.encode(message.tls_serialize_detached().map_err(|e| format!("{e:?}"))?)}),
        )
    }
}

fn text(request: &Value, field: &str) -> Result<String, String> {
    request[field]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| format!("{field} missing"))
}

fn main() {
    let mut lab = Lab {
        members: HashMap::new(),
        listed: Vec::new(),
        fetched: HashMap::new(),
    };
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let answer = match serde_json::from_str::<Value>(&line) {
            Ok(request) => match request["op"].as_str() {
                Some("create") => lab.create(&request),
                Some("add") => lab.add(&request),
                Some("accepted") => lab.accepted(&request),
                Some("refused") => lab.refused(&request),
                Some("message") => lab.message(&request),
                Some("key_package") => lab.key_package(&request),
                Some("km_request") => lab.km_request(&request),
                Some("km_response") => lab.km_response(&request),
                Some("join") => lab.join(&request),
                other => Err(format!("unknown op {other:?}")),
            },
            Err(error) => Err(error.to_string()),
        }
        .unwrap_or_else(|error| json!({"ok": false, "error": error}));
        let _ = writeln!(stdout, "{answer}");
        let _ = stdout.flush();
    }
}
