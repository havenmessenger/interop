# Changelog

This project uses 0.x semantic versions: a minor version changes the wire format or the public API, a patch changes
anything else. Each release names the drafts it implements and the divergences from them that remain open; the reasons
are in [DIVERGENCES.md](DIVERGENCES.md).

## Unreleased

- `mimi-hubd`: a submitted message's MLS framing is checked, from its outer header and with no key (draft-ietf-mimi-protocol-07
  §5.4): anything but a PrivateMessage carrying an application message is refused (`notAllowed`, or `not-permitted` on
  the client lane). In a room whose tree the hub keeps, a message for another group or for an epoch after the room's is
  refused, and one for an earlier epoch is answered `epochTooOld` with the room's epoch (on the client lane, the new
  problem type `epoch-too-old`, 409, whose body carries it as `current_epoch`). For any other room only the framing is
  checked (DIV-20). `MlsOuterHeader` gains the envelope's wire format and content type.
- `mimi-hubd`: the client lane passes the `epochTooOld` of a room's hub on another provider to its user as
  `epoch-too-old` with `current_epoch`, as for a room hosted here. Before, it answered `not-permitted`, and the user
  could not tell it was behind.
- `mimi-hubd`: a room hosted here that the hub keeps no ratchet tree for no longer takes changes the hub cannot
  authorize. Its first Commit, and any participant-list or room-policy change to it, is taken only with a bundle
  carrying a Full GroupInfo and the full ratchet tree, which seed the tree; otherwise it is refused (`notAllowed`, saying
  what is needed). A seed such a Commit needs is checked before anything changes, and the Commit's changes are
  authorized for its committer, the GroupInfo's signer, which must be the member that sent it. Before, such a room
  applied every change with no check of who made it. The policy's new `untracked_rooms` setting keeps that behaviour
  as `"accept"`; the default is `"refuse"`. DIV-10 has the rule.
- `mimi-hubd`: a room created by another provider's client could not be seeded: the group lists its creator from its
  creation, which no Commit carries, so the hub's list and the group's never matched and the Commit carrying the tree
  was refused. The list before a new room's first Commit is now its creator.
- `mimi-hubd`: `keyMaterial` on the provider path is taken only from a peer whose proof authenticates the requester's
  provider, or the provider hosting the room the request names (the room's hub, protocol-07 §5.2); otherwise `403
  not-permitted`. Before, any peer could name any requester, and a request passed the consent gate for any requester
  ever granted. The path's user and the body's `targetUser` must now be the same user (`400 malformed-request`
  otherwise): consent was read for the body's and the KeyPackage taken for the path's. The provider path's hourly
  limit of 5 for one target user is now counted per requesting provider (the domain the peer proved), not per the
  requester a request names, which is the peer's choice; a refused request is not counted. DIV-6 has what stays open: any peer can name any requester by naming
  a room on its own domain.
- `mimi-core`: `partial_group_info`, the `PartialGroupInfo` of draft-ietf-mls-ratchet-tree-options §4: read, written,
  split from a GroupInfo by its committer, and rebuilt into the GroupInfo it stands for from the GroupContext,
  confirmation tag, signer leaf and tree its receiver holds.
- `mimi-hubd`: a tracked room's Commit with a Partial GroupInfo is checked as one with a Full GroupInfo is. The hub
  rebuilds the GroupInfo from its group after the Commit (with the tree after it, when the Partial says the GroupInfo
  carries one) and refuses the Commit (`invalidProposal`) unless the committer signed it. Before, a Partial GroupInfo
  was taken unchecked. DIV-12 has where the rebuild departs from the draft's letter.
- `mimi-core`: a `Partial` `GroupInfoOption` payload is written and read raw, as protocol-07 §5.3 writes it, its end found
  by decoding the `PartialGroupInfo`; it no longer carries a `<V>` length prefix, and one that does not decode is
  refused. This changes the wire: a bundle written with the prefix does not decode. The `hb-03-partial-group-info`
  vector now carries the `PartialGroupInfo` of `hb-01`'s GroupInfo.
- `mimi-hubd`: the client lane serves `keyMaterial` (a client's signed `KeyMaterialRequest`, checked to be the user's
  own) and acts on rooms on another hub: `submitMessage`, `update` and `keyMaterial` for such a room are sent to the
  room's hub as this provider, as protocol-07 §3.4 and §5.2 have a member provider do. keyMaterial on the lane is
  limited per user and per user and target. On the provider path, a keyMaterial request whose `{targetUser}` is the URI
  of a user here (as this hub's own forwarding sends it) now finds the KeyPackages published for that user.
- `mimi-core`: `KeyMaterialRequest::sign` and `signature_verifies`, for its §5.2 signature over
  `KeyMaterialRequestTBS`.
- `mimi-hubd`: a last-resort KeyPackage (draft-ietf-mls-extensions §6.4, marked by its client) is handed out only when
  no one-time KeyPackage is left, and by default once, then deleted like any other, as protocol-07 §5.2 has it ("Keying
  material provided from one response MUST NOT be provided in any other response"). `MIMI_LAST_RESORT_REUSE=true` keeps it to be handed out again, with its
  `KeyPackageRef` still routing every Welcome sent for it (DIV-23). A user has one, the newest replacing the one before,
  and the per-user cap never evicts it. The client lane's `keyPackageCount` says how many one-time KeyPackages are left
  and whether a last-resort one is.
- `mimi-hubd`: on the provider path, one requester may make at most 5 `keyMaterial` requests an hour for one target
  user, as on the client lane; past that the hub answers 429 with the new problem type `key-material-rate-limited`.
- `mimi-hubd`: a user of this provider has one KeyPackage pool, whether published for or claimed by name or by URI;
  a store that kept some under the URI joins them to the name when it opens.
- `mimi-hubd`: `updateConsent` is recorded only from the provider of its target user and for a requester of this
  provider, and `requestConsent` only from the provider of its requester and for a target of this provider, as
  protocol-07 §5.7 has them. Before, any peer could send a grant naming one of this hub's users as the target, which
  the KeyPackage consent gate then honoured. Every answer is unchanged (201 / 202), so none says what was recorded.
- `mimi-hubd`: a Commit that would seed a room's tree may not change what the hub holds for the room. Its GroupInfo's
  GroupContext must carry the room's policy (roles_list and base room policy), its operational policy, and its
  participant list as the hub's list after the Commit; otherwise it is refused and nothing changes. Before, a seed took
  the group's components as the room's state and cleared those the group lacked, so a lane room's creator could drop
  the deployment's role checks and external-Commit refusal by creating its group without them. The client lane's
  `createRoom` now answers the room's `creator_role` and `components` for the client to start its group with. The
  neutral lane profile's member role may now leave (its own change to 0, which RemoveSelf alone does not grant).
- `browser-js` now builds the library for wasm32-unknown-unknown: it also turns on getrandom's `js` feature, which the
  virtual clients' reuse guard needs in a browser. CI checks that build.
- openmls moves to its main branch as of 2026-11-18, the commit `Cargo.toml` pins. With `extensions-draft` (`mimi-hubd`), commit staging
  now enforces every AppDataUpdate list rule of draft-ietf-mls-extensions-10 §4.7: one Remove per component, no Remove
  together with an Update, and no Remove of a component with no data; Update, Remove and SelfRemove proposals are
  listed in ascending leaf order; and the component operation label is "MLS Component" (§4.1), which only
  SafeEncrypt/SafeDecrypt use and nothing here calls. The VC-01 cross-check reruns at the new commit with the same
  values.
- A script, `scripts/render_status_page.py`, renders a deployment's status page when the hub is deployed: the
  revision it runs and the one before, the changelog entries and commits between them, the drafts and per-section
  status from `docs/mimi/CONFORMANCE.md`, the divergences, the problem types, the deployment's own settings files, and
  the test vectors with their SHA-256 for download, plus the same facts as JSON. It reads only the checkout, which
  must be at the named revision with no local changes, and writes a static page with no script. `--self-test` runs
  in CI.
- `docs/reasons.toml`: why each refusal is given. One row per problem type, per refusal a protocol answer carries
  (`notAllowed`, `notAuthorized`, `noConsent`, ...) and per MLS check a client in a room reports, each naming the
  specification and section it rests on with that section's sentence quoted, or saying the behaviour is this code's
  own and naming the divergence. The status page renders it and fails when a problem type has no row.
- An example, `mimi-hubd/examples/probe_bodies.rs`, makes the bodies a peer probe sends to a live hub, fresh each run:
  a `SubmitMessageRequest` from a named sender, a KeyPackage for a named user, and the notify `FanoutMessage` carrying
  a Welcome that adds that KeyPackage's holder. Each is an openmls object encoded with the types the hub decodes.
- A room takes every message its members may send, however many arrive within the delivery lifetime. An accepted
  application message is no longer also queued under the room's own URI, a queue nothing read: it filled to its cap of
  256 within the delivery lifetime and then refused every sender in the room, though each member read their own queue.
  Fan-out alone queues the message, for each other local member and each other provider with a participant. A message
  that is empty or larger than one queued item is still refused (`notAllowed`) and reaches no one. A message whose
  fan-out fails on a store error is answered as the hub's own failure (500 `internal-error`, on the wire and on the
  client lane; `SubmitMessageResponse` has no code for it), never as accepted.
- A client lane (`MIMI_LANE_BIND_ADDR`, off by default): a separate TLS listener on which a provider's client-facing
  service acts for one of this hub's users at a time, by an RFC 9421 signature tagged `mimi-client-lane`. The user
  publishes and withdraws their KeyPackages, reads and acknowledges their queued Welcomes and messages, creates rooms
  hosted here, sends messages and sends updates to them. What a created room starts with (its room policy, the
  creator's role, whether it allows external Commits) is the deployment's, from `MIMI_LANE_ROOM_POLICY`, by default a
  neutral profile that refuses external Commits; the client names none of it. On the lane a user speaks only for themself: a leave removes
  only them, an external Commit joins only them, and a GroupInfo that seeds a room's tree is signed by them. On the
  provider path a peer no longer speaks for a user of this hub in a room change, even when its proof names this hub's
  domain: a leave removing one, an external Commit joining one, or a seeding GroupInfo signed by one is refused. A local extension, not a MIMI route (DIV-19).
- One local member whose queue refuses an item (full: 256 messages or 32 Welcomes, or the item out of bounds) no
  longer stops fan-out to the others: that member is skipped and logged, and every other local member still gets
  the Commit, Welcome, held proposal, application message or followed room's message. A member's items (a held
  proposal and the ones beside it) are queued all or none, so no member holds part of a bundle. Only a queue's refusal
  skips a member; any other store error still fails the fan-out. The fan-out log line counts the members skipped.
- `submitMessage` (`/mimi/pl/submitMessage/{roomId}`) takes a message only from a peer submitting as a user of a
  domain its proof authenticates: never as a user of this provider, and not as a third provider's user. A refused
  message is answered `notAllowed` and is neither stored nor fanned out.
- The JSON lane's deposits, `/mimi/v1/submitMessage?recipient=` and `/mimi/v1/welcome/ingest?recipient=`, take an
  item only for a user of a domain the peer's proof authenticates (403 otherwise). A user of this provider's queues are
  filled only by this hub's own fan-out and its operator.
- On the provider path a peer acts only for users of the provider its proof names: it publishes KeyPackages only for
  them (`/mimi/v1/keyMaterial/ingest?user=`), and pulls only what is queued for them (`/mimi/v1/welcome` and
  `/mimi/v1/message`). A user of this provider, by bare name or by URI, takes KeyPackages from no peer, and what is
  queued for one is read by no peer. The operator's loopback listener gains `operator/keyMaterial`,
  `operator/welcome` and `operator/message` for this provider's users; `examples/seed_table.sh` publishes there.
- mimi-hubd can export traces and metrics over OTLP/HTTP to an OpenTelemetry collector: per peer provider, how many
  requests each way, with what status or failure and how long they took. Built with the `otlp` feature (off in a source
  build, on in the release binary and .deb) and on only when `MIMI_OTLP_ENDPOINT` names a collector, which must be
  `https` or loopback `http`. A record carries the route template, never a path value, user or room. Besides the
  outbound client, the exporter is the one connection the hub opens, and only to the operator's collector.
- Every refusal mimi-hubd answers with an HTTP error status carries an RFC 9457 problem body
  (`application/problem+json`) on each of its listeners: a type named by its anchor in `docs/problems.md` for each
  condition a peer can act on, and `http-error` for any other status. Error bodies were empty or text written for a
  log; the text is gone from the answers, and no problem body names a user, a client or a room.
- mimi-hubd keeps a room's ratchet tree once a Commit's bundle gives it one (a Full GroupInfo and a full ratchet tree),
  after checking who sent it; a tracked room's Commits are verified against the tree with openmls and refused when they
  do not apply, and its held proposals are queued in the group. The hub records which provider seeded each room and
  logs every Commit the tree refuses. The operator's listener gains `untrackRoom`. mimi-hubd depends on openmls with
  `extensions-draft`.
- For a tracked room, mimi-hubd authorizes each participant-list change for its proposer (room-policy-04 §8.1): the
  committer for a change carried by value, the leaving member for a held leave. One's own leave needs `canRemoveSelf`;
  any other change to one's own role is refused until `canChangeOwnRole` is built. A tracked room's policy and list are
  taken from its GroupContext when it is seeded, a Commit adding a first `roles_list` is refused (room-policy PR #52),
  and the operator's `roomPolicy`, `memberRole` and `addParticipant` answer 409 for it.
- mimi-core: `Capability::RemoveSelf` (`canRemoveSelf`, `0x0006`) and `RoomPolicy::authorize_self_removal`.
- mimi-hubd has an outbound client for requests to other providers: https only, to the peer's domain or
  a subdomain; the hub's certificate as the client certificate; every resolved address checked against the special
  ranges before connecting, and the connection made to that address. New settings `MIMI_OUTBOUND_ALLOW`,
  `MIMI_OUTBOUND_PROXY` and `MIMI_PEER_TRUST`. `MIMI_SERVER_CERT` needs the `clientAuth` extended key usage for it.
- mimi-hubd has an outbox for fan-out to other providers, delivered by a worker in order per room and provider, with
  retries and no expiry, and a peer directory lookup (`MIMI_PEERS` for a peer's base). The operator's listener gains
  `outbox` and `dropOutbox`. `MIMI_CLIENT_CERT` / `MIMI_CLIENT_KEY` set the outbound client certificate apart from the
  server's.
- mimi-hubd fans out what it accepts for a room it hosts to the other providers with a participant: Commits (to the
  participants before and after), the Welcome in a Commit's bundle (by the provider recorded for its KeyPackageRef, else
  the added user's), held leave proposals with their `moreProposals`, and application messages. Local members now get
  a room's Commits and held proposals in their queue too. mimi-core's `FanoutMessage` gains a constructor per kind.
- mimi-hubd forwards keyMaterial for another provider's user to that provider, for a room it hosts and from a
  participant who may add participants, and records each returned KeyPackage's provider for routing its Welcome.
  Any other such request is answered `noConsent`; a failing peer is `502`.
- mimi-hubd delivers what another hub fans out for a room it hosts to this provider's members of that room: a Welcome
  makes the users it names members here, and the Commits, proposals and application messages that follow are queued
  for them, each message once. A message for a room with no member here is answered `404` with the new problem
  `no-local-member`; `remote-room-not-delivered` (422) is retired.
- mimi-hubd signs every request it sends with the provider's DNS-published key when `MIMI_SIGNING_KEY` and
  `MIMI_SIGNING_SELECTOR` are set (RFC 9421, as draft-atwood-mimi-provider-auth §5 profiles it, with a nonce), and then
  presents a client certificate only when `MIMI_CLIENT_CERT` names one. Inbound, `From` is required on every peer
  request and must name a domain its proof authenticates; a signature's nonce is refused the second time within its
  window; the policy setting `require_nonce_on_key_material` refuses a signed keyMaterial request without one.
- A client can join a room by external Commit where the room allows it (protocol-07 §5.6): mimi-hubd keeps each
  tracked room's `mls_operational_policy` (mimi-core reads the whole component) and its last Full GroupInfo, serves
  `POST /groupInfo/{roomId}` (the answer encrypted to the requester and signed with the hub's own MLS key,
  `MIMI_HUB_MLS_KEY`), and accepts an external Commit from a joiner the room's roles admit (`canAddOwnClient`,
  `canOpenJoin`), never while proposals are held. A change to the operational policy needs
  `canChangeMlsOperationalPolicies`. The hub policy gains `external_commit_when_unset`. mimi-core reads an external
  Commit (`new_member_commit`, its `ExternalInit`) and gains the groupInfo wire types.
- For a tracked room, a change to the `roles_list` needs `canChangeRoleDefinitions` and a change to the
  `base_room_policy` `canChangeRoomMembershipStyle`, in the committer's role (room-policy-04 §8.6); until now any
  participant could make them.

## 0.1.0 - 2026-11-16

Implements draft-ietf-mimi-protocol-07, draft-ietf-mimi-content-10, draft-ietf-mimi-room-policy-04,
draft-ietf-mls-extensions-10 and draft-atwood-mimi-provider-auth-00, as 0.0.2 does. The minor version is for the API
change in mimi-core below.

### API change (mimi-core)
- Each accept-gate (`mimi_gate_keypackage`, `mimi_gate_welcome`, `mimi_gate_welcome_bare`, `mimi_gate_group_info`,
  `keypackage_ref`) takes the ciphersuites it accepts as a list, and so do the decoders that gate what they carry
  (`decode_consent_entry`, `KeyMaterialResponse::decode`, `HandshakeBundle::decode`). `default_mls_ciphersuites()` is
  every suite the crypto provider implements; a refusal names the accepted suites. `HAVEN_MLS_CIPHERSUITE_U16` is gone;
  `MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519` names 0x0001.

### The deployment's settings
- mimi-hubd reads a policy file named by `MIMI_POLICY` (`policy`): `mls_ciphersuites` (default: every implemented suite;
  the directory advertises exactly the list) and `identifier_discovery` (default `all`: every user the hub can answer
  for, one it has enrolled or holds an unexpired KeyPackage for; `enrolled` keeps it to enrolled users). A named file
  that cannot be read or is not a valid policy stops the start; the hub logs the policy it runs. A deployment that
  wants 0.0.2's behaviour sets `mls_ciphersuites = [0x0001]` and `identifier_discovery = "enrolled"`.
- `roomPolicy`, `memberRole` and `addParticipant` are the operator's: they are served only on a loopback listener of
  their own, `MIMI_ADMIN_BIND_ADDR` (`admin_bind_addr`), with no client certificate, and the peer listener answers 404
  for them. The hub does not start if that address is not loopback. Unset, there is no such listener.
  `examples/seed_table.sh` sets up its room through it, on the hub's host.

### Protocol
- `notify` refuses an application message, a Commit or a proposal for a room hosted on another hub with 422 and the
  RFC 9457 problem `remote-room-not-delivered`, instead of answering 201 for a message it does not deliver. A Welcome
  is still queued and answered 201. `docs/problems.md` names the problem types mimi-hubd answers with.
- A Commit's participant-list change is checked against the room's policy: every role it puts a user in must be one
  the policy defines. A ban into role 1 is refused unless the room's role list defines role 1 (room-policy #51); a list
  that names role 1 without defining it is still valid. Who made a role change is not checked yet (DIV-15).
- An update the room's policy refuses is answered `notAllowed` with the reason, no longer `invalidProposal` with an
  empty list: a role the policy does not define, a role list or base policy that does not validate, a base policy before
  any roles, or a role list beside a participant-list change. Malformed proposals stay `invalidProposal`. The recorded
  answer of vector `up-x6-base-room-policy-before-roles` is now `notAllowed`.
- The hub reads and keeps `room_metadata` (`0x0023`, protocol-07 §10) instead of refusing it: a room's name,
  descriptions, avatar, subject and mood are stored as the last accepted update sent them, within bounds.
- The directory's `unsupported` block no longer lists other ciphersuites, and says the GroupInfo join is not built yet.

### Operating the hub
- Every answer from mimi-hubd carries `Server: mimi-hubd/<version>`.
- Releases are signed: `SHA256SUMS` and a detached signature by the Haven Releases key on each release, signed tags,
  and the public key in `RELEASE-KEY.asc`. The README says how to verify one.

### Documentation
- `SECURITY-INVARIANTS.md` states the hub's own security properties and the code that holds each.
  `docs/mimi/CONFORMANCE.md` is this repository's own table, by draft section.
- DIVERGENCES lists only what is not built yet and where the drafts are open. DIV-2 is closed (a setting). The base
  policy's membership limits (`fixed_membership` growth, `max_clients`, `max_users`) are kept but not enforced on a
  Commit (DIV-15). `0xF7A0` is described as a compatibility carrier to be removed once clients send an AppDataUpdate.

### Tooling
- A joint vector set from the IETF 127 MIMI table, recorded against mimid and this hub
  (`tests/vectors/joint-ietf127-*.json`), with replay tests.

### Open divergences
DIV-1 (GroupInfo and external-commit join not built yet), DIV-3 (no assets or OHTTP), DIV-4 (identifierQuery answers a
single Handle or Nick query), DIV-5 (no relay to other providers), DIV-6 (client identity not bound to the channel),
DIV-8 (metadata-only abuse reports), DIV-9 (no franking), DIV-10 (no wire route for the operator's routes), DIV-11
(update fields read as opaque), DIV-12 (a Partial GroupInfo payload carries a length prefix), DIV-13 (an exhausted
client is answered partialSuccess), DIV-15 (two room-policy components are read; who made a role change is not checked),
DIV-16 (any client CA may name any provider domain), DIV-17 (content-10 against content-09 peers). See DIVERGENCES.md
for each.

## 0.0.2 - 2026-11-15

Implements draft-ietf-mimi-protocol-07, draft-ietf-mimi-content-10, draft-ietf-mimi-room-policy-04,
draft-ietf-mls-extensions-10 (AppDataUpdate, the app data dictionary, app components and safe AAD) and
draft-atwood-mimi-provider-auth-00 (DNS-published keys).

### Protocol
- The hub follows protocol-07: wire answers carry the protocol media type; `update` takes an `UpdateRequest` and answers
  with an `UpdateRoomResponse`; a Commit may carry a participant-list change, a room-policy change, or one of each, with
  Add and Remove proposals beside it, and a member may leave through proposals the next Commit includes by reference.
- A Commit's epoch is checked, and a Commit refused for its changes says which rule refused it.
- Participant-list updates apply in the room's own order (protocol-07 §7.5).
- Room policy is read from `roles_list` and `base_room_policy` AppDataUpdates (room-policy-04).
- `identifierQuery` answers with an `IdentifierResponse`: a handle search takes the whole handle URI
  (`mimi://<domain>/u/<name>` or `im:<name>@<domain>`), a nick search the bare name, and every miss is the same
  `notFound` with HTTP 200.
- `keyMaterial` serves a KeyPackage that meets the request's ciphersuites and capabilities; KeyPackages are published
  only for this hub's own users or by the provider that holds them.
- A notify is accepted only from the hub of its room; a fanned-out Welcome is queued for the local user it names.
- content-10 is read and written; `content_check` decodes another implementation's content documents and compares the
  re-encoding.

### Identity and URIs
- URIs are compared in their canonical form (RFC 3986 §6.2.2), and a path written as an IRI is mapped to its URI
  (RFC 3987 §3.1), so a name written raw and the same name percent-encoded are one user. A found user is answered with
  the name percent-encoded. An existing store is rewritten to this form once, at its next start.
- An authority outside ASCII is refused.

### Provider authentication
- A peer is authenticated by a client certificate that chains to the configured CA, or, with no certificate, by an
  RFC 9421 signature from a key its provider publishes in DNS (draft-atwood-mimi-provider-auth §5). One gate decides
  this for every route but the directory; a request with neither is answered 403. Peer keys are read from a file
  (`MIMI_PEER_KEYS`) the operator keeps current from DNS; this release does not query DNS itself.
- The fingerprint of each client CA is printed at startup.

### Operating the hub
- `mimi-hubd enroll` lets the operator enroll a handle for `identifierQuery` from the hub's host.
- An optional listener serves the directory and nothing else; an optional activity line logs each peer request's
  method, route template and status.
- The startup line names the version and the git commit it was built from.

### Tooling
- Protocol-07 test vectors another implementation can replay; `seed_fixtures` seeds a hub for a visiting
  implementation.
- Dependencies: openmls on a main revision (GREASE KeyPackages pass the gate), rusqlite 0.41, rustls 0.23.46,
  rustls-webpki 0.103.16 (RUSTSEC-2026-0382).

### Open divergences
DIV-1 (no external commits, by design), DIV-2 (one ciphersuite), DIV-3 (no assets or OHTTP), DIV-4 (identifierQuery
by opt-in only), DIV-5 (no relay to other providers), DIV-6 (client identity not bound to the channel), DIV-8
(metadata-only abuse reports), DIV-9 (no franking), DIV-10 (role checks on a Commit's sender), DIV-11 (update fields
read as opaque), DIV-12 (a Partial GroupInfo payload carries a length prefix), DIV-13 (an exhausted client is answered
partialSuccess), DIV-15 (two room-policy components are read; role 1 is named "banned"), DIV-16 (any client CA may name
any provider domain), DIV-17 (content-10 against content-09 peers). See DIVERGENCES.md for each.

## 0.0.1 - 2026-07-16

First release: the mimi-core library (protocol-06 wire codecs, consent, participant lists, room policy, content
codec) and the mimi-hubd reference hub over mutually authenticated TLS, with binaries, `.deb` packages and a container
image.
