# Conformance of interop (mimi-core and mimi-hubd)

Per section of the drafts below, what this repository implements and what it does not build yet. Hand-maintained from
the code; a row that says "not built yet" names the entry in [`DIVERGENCES.md`](../../DIVERGENCES.md) that explains it.
A deployment's own choices (which ciphersuites it accepts, who `identifierQuery` finds) are settings, described in
[`mimi-hubd/README.md`](../../mimi-hubd/README.md), not rows here.

**Status words.** *Implemented*: the code does it, with tests. *Partly*: the code does part of it; the row says which
part. *Not built yet*: the code does not do it. *Client*: the requirement falls on a client; the library supplies the
mechanism and a client calls it.

## Drafts

| Draft | Revision |
|---|---|
| `draft-ietf-mimi-protocol` | -07 |
| `draft-ietf-mimi-content` | -10 (reads and writes -09 peers, DIV-17) |
| `draft-ietf-mimi-room-policy` | -04 |
| `draft-ietf-mls-extensions` | -10 (AppDataUpdate) |
| `draft-ietf-mls-virtual-clients` | -01 |

## Transport and directory (protocol-07 §4.1, §5.1)

| ID | § | Requirement | Status | Where |
|---|---|---|---|---|
| T1 | 4.1 | Inter-provider requests over HTTPS | Implemented | `mimi-hubd/src/tls.rs`: the peer listener serves TLS only |
| T2 | 4.1 | Target provider in `Host` | Partly | Not compared with this hub's domain (DIV-16) |
| T3 | 4.1 | Source provider in `From` | Partly | Checked against the certificate when present, not required (DIV-16) |
| T4 | 4.1 | Mutually authenticated TLS | Implemented | Client certificate from the CA bundle, or a DNS-key request signature (`provider_auth.rs`); any CA may name any provider (DIV-16) |
| T5 | 5.1 | Publish `/.well-known/mimi-protocol-directory` | Implemented | `Provider::directory`; also on a plain listener of its own |

## Key material (protocol-07 §5.2)

| ID | § | Requirement | Status | Where |
|---|---|---|---|---|
| K1 | 5.2 | Each KeyPackage returned at most once | Implemented | `store.rs` claim is one atomic statement |
| K2 | 5.2 | Never serve expired key material | Implemented | Claim filters on expiry in the same statement |
| K3 | 5.2 | Hub associates KeyPackageRef with the target provider | Implemented | `associate_claimed_keypackage` |
| K4 | 5.2 | Provider associates KeyPackageRef with its local client | Implemented | `publish_key_package` |
| K5 | 5.2 | Refuse a KeyPackage or Welcome in a ciphersuite the provider does not accept, before decoding it | Implemented | `src/gate.rs`; the accepted list is the policy's `mls_ciphersuites` |

## Room state and update (protocol-07 §5.3, §7.5)

| ID | § | Requirement | Status | Where |
|---|---|---|---|---|
| R1 | 5.3, 7.5 | Participant-list changes as an AppDataUpdate (`mimiParticipantList`) | Implemented | `src/commit_wire.rs`, `src/participant_list.rs`; also read from the `0xF7A0` compatibility carrier (DIV-15) |
| R2 | 5.3, 7.5 | Removing an active user together with the MLS Remove | Client | The library's update codec; the client builds the Commit |
| R3 | 5.3 | Hub refuses a removed participant's messages, Commits and proposals (except Remove and SelfRemove) | Implemented | `Provider::authorize_sender` on `submitMessage` |
| W4 | 5.3 | `update` (HandshakeBundle) wire codec | Partly | One room-changing proposal per Commit, with or without Add and Remove (DIV-10); a tracked room's Commit is verified against its ratchet tree; the Commit is not stored or relayed |
| W11 | 5.3 | A room-policy change is an AppDataUpdate for a room-policy component | Implemented | `roles_list` and `base_room_policy` (DIV-15) |

## Messages and fan-out (protocol-07 §5.4, §5.5)

| ID | § | Requirement | Status | Where |
|---|---|---|---|---|
| M1 | 5.4 | An application message is an MLS PrivateMessage | Client | The hub relays it opaque |
| M2 | 5.4 | `sendingUri` is an active participant | Implemented | `Provider::authorize_sender` |
| M3 | 5.5 | Fan out to every provider with active participants | Implemented | Commits, held proposals and application messages, through the outbox (DIV-5) |
| M4 | 5.5 | Route a Welcome by the KeyPackageRef it carries | Implemented | By the provider recorded when the hub forwarded keyMaterial for that KeyPackage, else the added user's domain (DIV-5) |
| M5 | 5.5 | A duplicate `notify` is answered 201, byte-exact | Implemented | The `notify_seen` ledger |
| M6 | 5.4, 5.5 | Store and deliver a PrivateMessage once | Implemented | `submitMessage`, `message` |
| W9 | 5.5 | `notify` is accepted only from the room's hub | Implemented | `notify_source.rs` |

## GroupInfo and join (protocol-07 §5.6)

| ID | § | Requirement | Status | Where |
|---|---|---|---|---|
| G1 | 5.6 | Hub checks the joiner's authorization before returning GroupInfo | Not built yet | DIV-1 |
| G2 | 5.6 | GroupInfoResponse encrypted and signed by the hub | Not built yet | DIV-1 |

## Consent (protocol-07 §5.7)

| ID | § | Requirement | Status | Where |
|---|---|---|---|---|
| C1 | 5.7 | Accept and process `requestConsent` | Implemented | `process_request_consent`; answered 202 on the wire lane (W12) |
| C2 | 5.7 | Accept and process `updateConsent` (grant, revoke) | Implemented | `process_update_consent` |
| C3 | 5.2, 5.7 | KeyPackage access gated by consent | Implemented | `keypackage_access`, default deny |

## Discovery (protocol-07 §5.8)

| ID | § | Requirement | Status | Where |
|---|---|---|---|---|
| W6 | 5.8 | `identifierQuery` over the wire lane | Partly | One Handle or Nick query per request; other identifier types not built yet (DIV-4). Who it finds is the policy's `identifier_discovery` |

## Abuse reports and assets (protocol-07 §5.9, §5.10)

| ID | § | Requirement | Status | Where |
|---|---|---|---|---|
| A1 | 5.10.2 | Hub checks a `downloadUrl` host belongs to a peer provider | Not built yet | DIV-3 |
| A2 | 5.10.3 | OHTTP gateway for asset download | Not built yet | DIV-3 |
| — | 5.9 | `reportAbuse` with an attached AbusiveMessage | Not built yet | Metadata-only reports are accepted (DIV-8, DIV-9) |

## Wire framing (protocol-07 §5, TLS presentation language)

| ID | § | Requirement | Status | Where |
|---|---|---|---|---|
| W1 | 5.4 | `submitMessage` | Implemented | `src/protocol_wire.rs`, `/mimi/pl/submitMessage/{roomId}` |
| W2 | 5.7 | `requestConsent`, `updateConsent` | Implemented | `/mimi/pl/requestConsent`, `/mimi/pl/updateConsent` |
| W3 | 5.2 | `keyMaterial` | Implemented | `/mimi/pl/keyMaterial/{targetUser}` |
| W5 | 5.5 | `notify` (receiving) | Implemented | `/mimi/pl/notify/{roomId}` |
| W7 | 5.1 | The directory names the wire endpoints | Implemented | `Provider::directory` |
| W8 | 2 | TLS presentation language as the wire encoding | Implemented | The `/mimi/pl/*` routes |
| W10 | 7.5 | Participant-list indices are positions; added users appended | Implemented | `src/participant_list.rs` |
| W12 | 5.7, 10.6 | Consent answered 202 (422 for an operation the route does not take); wire bodies labelled `application/mimi-protocol` | Implemented | `mimi-hubd/src/http.rs` |

## Content (content-10)

| ID | § | Requirement | Status | Where |
|---|---|---|---|---|
| F1 | 4.1 | Per-message salt from a CSPRNG | Implemented | `src/content.rs` |
| F2 | 6.1 | Deterministic CBOR, no indefinite length | Implemented | `src/content.rs` |
| F3 | 6.2 | Extension keys int or text of at most 255 octets, valid UTF-8 | Implemented | `validate_extensions` |
| F4 | 6.3 | NestedParts at most 4 deep | Implemented | `validate_nesting` |
| F5 | 7.1 | Receive `application/mimi-content`, `text/plain`, `text/markdown;variant=GFM-MIMI` | Client | The codec reads all three |
| F6 | 4.5 | Decrypt external content | Client | `src/external.rs`; the caller supplies the AEAD |
| F7 | 7.1.1 | GFM-MIMI without raw HTML or autolinks | Client | `validate_gfm_mimi_nohtml` |
| F8 | 9.3 | Only the original sender edits or retracts a message | Client | `authorize_replacement`, which a receiving client calls |
| F9 | 4.5 | Encrypt external content | Client | `src/external.rs`; the caller supplies the AEAD |
| F10 | 4.1 | The 7-element container with a flat NestedPart | Implemented | `src/content.rs` |

## Room policy (room-policy-04)

| ID | § | Requirement | Status | Where |
|---|---|---|---|---|
| P1 | 3 | One role at a time; role 0 no-role, role 1 banned | Implemented | `src/room_policy.rs`; a ban into role 1 needs role 1 defined |
| P2 | 3, 8.6 | A role-list change is not in the same Commit as a participant-list change | Implemented | `check_changes` |
| P3 | 5 | Fixed membership, `max_clients`, `max_users` | Partly | Kept, not enforced on a Commit (DIV-15) |
| P4 | 8.1 | Who may make a role change (`authorized_role_changes`, `canBan`, ...) | Implemented for tracked rooms | Each change authorized for its proposer, `canRemoveSelf` for one's own leave; `canChangeOwnRole`, counts and Removes without a list change not built yet; untracked rooms not checked (DIV-15) |
| P5 | 8.3 | Hub enforces `canSendMessage` | Implemented | `authorize_sender`, by the sender's role |
| P6 | 9 | One stored policy is the authority at each check | Implemented | `room_policy` table |

## Virtual clients (mls-virtual-clients-01 §5-§6)

| ID | § | Requirement | Status | Where |
|---|---|---|---|---|
| VC1 | 5.2 | The five per-epoch virtual-client secrets | Implemented | `src/virtual_clients.rs` |
| VC2 | 5.6.1 | Small-Space PRP (FF1, AES-128, radix 2) | Implemented | `small_space_prp_encrypt` |
| VC3 | 5.6.2 | `reuse_guard`, and recovering the sender's leaf | Implemented | `compute_reuse_guard` |
| VC4 | 5.6.3 | `generation_id` | Implemented | `compute_generation_id` |
| VC5 | 6.2, 6.3 | Join the emulation group externally; removal advances the epoch | Implemented | The conformance tests, against an emulation group only |
