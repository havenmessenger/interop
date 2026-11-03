# Divergences from the drafts

`mimi-hubd`'s v1 implements a subset of `draft-ietf-mimi-protocol`, `draft-ietf-mimi-content`,
and `draft-ietf-mimi-room-policy`. The authoritative source is the hub's own `directory`
endpoint `unsupported` block (`mimi-hubd/src/lib.rs`); this file explains the reasoning.

DIV-1 through DIV-4 are scoping decisions: deliberate, documented choices about what v1 does
not do. DIV-5 through DIV-15 are gaps in what v1 attempts: endpoints or fields the code accepts
and processes without yet enforcing everything the draft requires, or behaviour that differs
from the draft on a point where the draft is silent or the pinned MLS library falls short. A
strict implementation of the affected endpoints will not interoperate with this hub on those
points until they close.

## DIV-1 - GroupInfo / external-commit join

Not supported. Cross-provider group membership is add-driven only: an existing member adds
the new participant via Commit + Welcome. The `§5.6` claim-group-key flow (self-join via
`join_by_external_commit` against an exported `GroupInfo`) is out.

External commits are the part of MLS the original security proofs did not cover. The
External-Operations TreeKEM analysis (ETK, eprint 2025/229) shows an adversary who
compromises a party's long-term secret can, at any time, resync that party's group
representation via external join, a strictly larger attack surface than standard membership
operations. Haven does not implement it, in either the native or the mimi lane
(`INV-MLS-001a`).

## DIV-2 - Non-`0x0001` ciphersuites

Rejected at ingest, before the object reaches openmls. Haven generates and accepts
`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (`0x0001`) only, on both sides of the wire
(`INV-MLS-002`). A foreign KeyPackage or Welcome carrying a different suite is refused by
the gate rather than passed through.

## DIV-3 - Assets and OHTTP transport

Not supported. v1 is messaging-only: text content over the wire and JSON lanes, no binary
asset transfer, no OHTTP relay path (`§5.10`).

## DIV-4 - `identifierQuery` has no existence oracle, and only ever answers a single Handle query

A query for a non-enrolled user returns HTTP 404 with a zero-byte body, identical on both the
JSON and TLS-PL wire lanes. The response carries no signal that would let a caller
distinguish "not found" from any other failure mode, so repeated queries cannot be used to
enumerate who has an account. This is symmetric across BOTH outcomes: a match also returns a
bare status with no decodable body (HTTP 200 on the JSON lane, HTTP 200 on TLS-PL) - not just
the not-found case - because a body that only appears on success would itself be an oracle.

This also means the hub cannot honor the draft's implied AND-across-elements semantics for a
multi-element `IdentifierRequest`: v1 has no data model for `email`/`phone`/`oidcStdClaim`/
`vcardField`/etc. lookups, only usernames (wire type `Handle`). A request is answered only when
it carries exactly one query element of type `Handle`; a request with zero elements, more than
one element, or any non-`Handle` element is treated as unanswerable and always returns
not-found, rather than silently evaluating just the first element regardless of its type or
what else was asked.

## DIV-5 - `submitMessage`'s sender authorization and fan-out - MOSTLY CLOSED

`submit_message_wire` now calls `authorize_sender` (active-participant + not-removed +
room-policy check) before accepting anything, and `fanout_targets` after: every other LOCAL
participant of the room the path segment names now receives the message, not just the one
routing key. The residual: forwarding to a participant on a FOREIGN provider is still not
implemented (this reference hub has no cross-provider relay client), so a room spanning
multiple providers only delivers to the local share of its membership over the wire lane. The
JSON compat lane's `submit_message` is intentionally left as the pre-existing unauthenticated
demo/admin path (`?recipient=` accepts any opaque string, no room semantics) - it predates and
is independent of the wire protocol surface.

Protocol-07 §5.5 adds that the exemption for a client's own message does not cover a Welcome: the
hub sends a Welcome to every provider associated with a `KeyPackageRef` in its `secrets` array,
including the provider of the client that submitted it. This hub relays no Welcome to another
provider, which is the residual above, so that rule is not exercised here.

## DIV-6 - client-asserted identity is not bound to an authenticated channel

This reference hub authenticates the TRANSPORT PEER via mTLS (an allowlisted certificate), never
the individual end-user identity inside a request body. The three wire routes that carry a claimed
identity have different answers, not one shared gap:

- **`submitMessage`**: `sendingUri` is unverified by this hub, and that is not a gap. RFC 9420's own
  delivery-service trust model does not expect the DS to verify a message's signature or hold group
  state - that is the receiving member's responsibility, checked against the sender's leaf
  credential inside the actual MLS group. This hub relaying an unverified `sendingUri` claim matches
  the spec's own DS posture rather than diverging from it.
- **`keyMaterial`**: unlike `submitMessage`, the draft's own `KeyMaterialRequest` (§5.2) carries a
  self-signed identity claim (`requesterSignatureKey`/`requesterCredential`/
  `keyMaterialRequestSignature`) - a real mechanism, not an invented one. This hub checks the
  credential's embedded identity against the claimed `requestingUser` and logs the outcome, but
  never refuses a request over a mismatch, and does not verify the signature itself (the exact
  signed-content scope isn't confirmed against primary source, and this check is diagnostic only -
  nothing gates on it). **This is a deliberate testing-phase choice, not a settled production
  security posture.** A self-signed credential has no external trust root without a persistent
  identity registry, and this hub's `KeyPackage` store is a one-time-claim object for the add flow,
  not one - there is nothing durable here to pin a claimed identity's genuine key against.
  Requiring a match before serving would functionally refuse any identity this hub has not already
  interacted with, defeating the point of testing interop with new peers. A production/GA
  federation policy (rate-limiting repeated unverified claims, or a real persistent identity-key
  registry) should be revisited before general availability.
- **`consent`**: `ConsentEntry` (§5.7) carries no signature field at all in the draft - no
  self-signed mechanism exists here for this hub to check even if it wanted to. This may be a
  genuine gap in the draft itself rather than an implementation gap; worth raising with the WG
  rather than inventing a Haven-only signing convention unilaterally.

## DIV-7 - the directory document - CLOSED

§5.1 defines a directory whose top-level keys are the endpoint URLs. This hub's `directory()`
now publishes those flat, draft-shaped keys (absolute HTTPS URLs) for the six endpoints it
actually wire-routes, alongside the pre-existing `endpoints` (JSON compat lane) and
`wireEndpoints` (TLS-PL lane, relative paths) nesting, kept as additive non-standard keys for
existing consumers. A client that looks for a root-level `keyMaterial` key per the draft now
finds one.

## DIV-8 - `reportAbuse` is bounded to metadata-only reports; asset download is not implemented

`reportAbuse` (§5.9) has a v1 wire handler (`POST /mimi/pl/reportAbuse/{roomId}`) that accepts and
stores `reportingUser`/`allegedAbuserUri`/`reasonCode`/`note` in the configured provider store. A
report attaching one or more `AbusiveMessage` entries is refused (decode error, not silently
dropped): validating an `AbusiveMessage` requires recalculating its `Frank` against this hub's own
key material, which this codebase does not build (DIV-9). This hub takes no automated action on an
accepted report - it is a stored record only, matching the draft's own text ("the response code
only indicates if the abuse report was accepted, not if any specific automated or human action was
taken").

Asset download (§5.10) has no v1 handler, wire or JSON.

## DIV-9 - `SubmitMessageResponse` omits the `frank` field, and `reportAbuse` cannot validate a franked message

§5.4.1 `server_frank` framing is not yet built. The wire form's `optional Frank frank` presence tag
is encoded as absent, so adding a real value later is additive. Closing this divergence needs
computing `server_frank` from a client-supplied `frank_aad` and this hub's own `hub_key` (an
HMAC-style commitment scheme, per §5.4.1's description and its comparison to the Facebook franking
design), plus the receiver-side verification the draft describes. The implementation does not
compute or verify `server_frank`; `SubmitMessageResponse` therefore omits `frank`, and `reportAbuse`
rejects attached `AbusiveMessage` values rather than accepting them unverified.

## DIV-10 - CLOSED for a Commit carrying a single custom proposal; `roomPolicy`/`memberRole`/`addParticipant`/`authorizeSender` still have no wire route of their own

**This entry has been rewritten twice already this session as the real picture came into focus -
each rewrite is kept below rather than silently replaced, per this file's own discipline of
recording what changed and why.** The short version: the wire-parsing step some earlier language
here called blocked on group-state machinery was not blocked on that at all; it is done, and it is
now wired end to end for both Haven custom proposal types.

`POST /mimi/pl/update/{roomId}` (§5.3) takes an `UpdateRequest`, a `HandshakeBundle` whose
`PublicMessage`-wrapped MLS Commit carries exactly one custom proposal. `mimi_core::commit_wire::decode_single_custom_proposal_commit` reads
the proposal's type and payload - independent of openmls's own (crate-private) `Commit` type,
hand-coded the same way every other MIMI-specific structure in this codebase is - without verifying
the Commit's signature or holding any group state, matching RFC 9420's own delivery-service trust
model (the DS is not expected to do either; that is the receiving member's job). Commits on this
hub's groups already travel as `PublicMessage`, so the proposal bytes are visible on the wire
without needing that machinery in the first place.

- A `mimiParticipantList` proposal's payload is applied to this room's `room_participants`/
  `member_role` tables. Indices in the payload count the room's participants vector in the order
  participants joined, as protocol-07 §7.5 has it: they refer to the vector as it stood before the
  update, removing one entry does not shift the others, and added participants are appended. The
  update is applied by `mimi_core::participant_list::apply_update`, and the room is written from
  its result. An update is refused as `invalidProposal` when an index is out of range, appears
  twice in one list, or appears in both lists, and when a user in `addedParticipants` is already
  listed. The list an update is checked against is the one before it, so removing a user and
  adding the same user in one update is refused too; that is this hub's reading of §7.5, which
  gives no example. §7.5 also has the indices hold across more than one `ParticipantListUpdate` in
  a Commit; this hub accepts a single custom proposal per Commit (below), so that case is refused
  rather than applied.
- A `mimiRoomPolicy` proposal's payload is the JSON-serialized `RoomPolicy` this hub already stores
  for the JSON-compat `roomPolicy` route - a whole-object replace, validated the same way
  (`RoomPolicy::validate`) before it is stored.
- A Commit that mixes the custom proposal with a standard MLS proposal (Add, Remove, ...) in the
  same list is refused, not decoded: skipping past a standard proposal's own body (an `Add`, for
  instance, embeds a full KeyPackage) needs that proposal's own decoder, which is out of scope. A
  sender that wants this hub to read the change sends it as its own Commit.
- **Framing.** The request body is the draft's `UpdateRequest { HandshakeBundle }` and the answer
  is an `UpdateRoomResponse` in a 200: `success` with the hub's acceptance time in milliseconds;
  `notAllowed` for a room this hub does not host, a bundle whose Welcome or GroupInfo is under
  another ciphersuite, or a store limit (the participant cap), with the same bytes for each, so a
  refusal does not say which of them applied; `invalidProposal` (with an empty `invalidProposals` list)
  for a body that is not an `UpdateRequest`, a bundle of proposals, an unrecognized proposal
  type, or an update that does not fit the room. The hub checks that the room URI is under its own
  domain, not that the room exists, and answers `invalidProposal` or `success` for a room it
  hosts, so a peer on the allowlist can learn a room's participant count from those answers.
  `wrongEpoch` is never answered, because the hub
  holds no group state and so no epoch. A SQLite failure is a 500 with no body. The Welcome,
  `GroupInfoOption` and `RatchetTreeOption` of a Commit bundle are read and suite-gated, and are
  neither stored nor relayed: `success` means the participant-list or room-policy change was
  applied, not that the Commit was distributed (§5.3's "will be distributed"). A body that is only
  the Commit, without the bundle around it, is refused.
- The four room-admin RPCs (`roomPolicy`/`memberRole`/`addParticipant`/`authorizeSender`) remain
  JSON-compat-lane only - `update` is the wire-lane mechanism for the two operations it actually
  carries (roster and policy changes); it is not a wire-framing of those four RPCs themselves.

Verified against a captured real `openmls` Commit, freshly re-encoded ones each test run, an
end-to-end participant-list apply, an end-to-end room-policy apply, and rejection cases for an
unrecognized proposal type and an undecodable body.

## DIV-11 - CLOSED for `consent_extensions`; `update`'s fields stay opaque

`ConsentEntry.consent_extensions` (§5.7) is decoded into the real `draft-ietf-mls-extensions` §4.6
`AppDataDictionary` shape: a run of `ComponentData { uint16 component_id; opaque data<V>; }`
entries, sorted and unique by `component_id` (the draft's own MUST), wrapped in one outer
length-prefixed window. `id_request_extensions`/`id_response_extensions` (§5.8) and
`abuse_extensions` (§5.9, the same `AppDataDictionary` type) stay opaque length-prefixed blobs - the
decoder consumes these fields without interpreting or retaining their contents, since nothing here
produces or consumes those specific fields.
`update`'s `RatchetTreeOption` field (§5.3) also stays opaque, for the same reason as the rest
of `update`'s codec: no live accept-path exists yet. A `Full` `GroupInfoOption` is read raw and
suite-gated; a `Partial` one stays an opaque length-prefixed blob (DIV-12).

## DIV-12 - a `Partial` `GroupInfoOption` payload carries a length prefix

§5.3 writes the `GroupInfoOption` payload raw: a `GroupInfo` for `full`, a `PartialGroupInfo`
for `partial`, each ending where its own structure ends, with `ratchetTreeOption` following.
A `Full` payload is written and read that way here: its end is found by decoding it as an
openmls `VerifiableGroupInfo`, and it is suite-gated at decode.

A `Partial` payload has no decoder in this crate or in openmls, because `PartialGroupInfo`
belongs to a sibling draft this code does not implement, so there is nothing that could find
where one ends. It is written with a `<V>` length prefix, the only way to keep
`ratchetTreeOption` (the trailing field) findable, and it is not suite-gated. A peer that
sends a raw `Partial` payload will not decode against this codec until `PartialGroupInfo` is
implemented. The codec is not wired to any route, so no live exchange depends on it.

## DIV-13 - an exhausted client is answered with `partialSuccess`

When a user has no key material left, the `keyMaterial` response carries user status
`partialSuccess` with one client entry whose status is `keyMaterialExhausted`. §5.2 defines
`partialSuccess` as key material for at least one client, so a response with no successful
client does not fit it, and the draft gives no user code for "known user, nothing left to
issue": `noCompatibleMaterial` is defined as no client able to supply material compatible with
the request's required capabilities, which is a different condition. `partialSuccess` is used
because the user is known and a client was enumerated; the choice is a judgment call on a
point the draft leaves open, and is not treated as settled. The decoder accepts the response
as sent. It refuses the combinations §5.2 rules out: `success` with a client that is not
`success`, `success` or `partialSuccess` with no client, and a client list under any user
status other than `success`, `partialSuccess` and `noCompatibleMaterial`. Every other
combination of user and client statuses is read and written back unchanged.

## DIV-14 - KeyPackages that carry a GREASE value are refused

RFC 9420 §13.5 has clients include GREASE values to keep peers tolerant of unknown values. The
openmls release this crate pins (0.9.2; the 0.8.1, 0.8.2 and 0.8.3 releases behave the same way) rejects
a KeyPackage that carries a GREASE extension value with `UnsupportedExtension`, because it
classifies the same value as a GREASE extension type in the client's capabilities and as an
unknown extension type in the KeyPackage's own extensions (openmls#2162, fixed on openmls
`main` and not yet in a release). The gate therefore refuses such a KeyPackage, and the
`keyMaterial` and consent exchanges cannot take key material from a client that sends one.

A test pins the refusal (`gate::grease_tests`) and fails when the pinned release stops
refusing it; it is then inverted and this entry removed. The fix needs an openmls release, or
a source dependency, which this crate's manifest-purity guard does not allow.

## DIV-15 - room-policy changes are read from a private proposal type; room-policy components are not read

`update` reads a participant-list change from either of two carriers: an AppDataUpdate
(mls-extensions-10 §4.7, proposal type `0x0008` as its §7.2.1 suggests) addressed to
component `0x0022` (`participant_list`, protocol-07 §10.3), or the custom proposal of the
private type `0xF7A0` (`mimiParticipantList`). Both carry the draft's `ParticipantListUpdate`
encoding and are applied the same way. The openmls release this crate pins (0.9.2) is built
without its `extensions-draft` feature and cannot read an AppDataUpdate, so `commit_wire` reads
the proposals window itself and rewrites an AppDataUpdate to the `0xF7A0` form for reading only; the
bytes of the Commit are never changed.

Protocol-07 §5.3 sends a room-policy change as an AppDataUpdate for the room policy components of
room-policy-04 (`mls_operational_policy`, `roles_list`, `base_room_policy` and ten more, with
values `0x0024` to `0x0030` suggested and not yet registered). This hub reads none of them. It
reads a room-policy change only from the custom proposal of the private type `0xF7A1`
(`mimiRoomPolicy`), whose payload is the JSON form of this crate's `RoomPolicy`. An AppDataUpdate
for any other component, including `room_metadata` (`0x0023`, protocol-07 §10.4), a removal, and an
AppSync proposal are refused as an unrecognized proposal type, so a sender is told the change was not
applied and never that it was.

Protocol-06 described the carrier two ways (AppSync in §2 to §5.3 and AppDataUpdate in §9 and
§10.3); protocol-07 says AppDataUpdate throughout and no longer mentions AppSync.

## DIV-16 - a certificate names the provider domains it carries, and any CA in the client bundle may issue any name

Protocol-07 §4.1 has the TLS certificates presented in the handshake authenticate the source and
target provider domains (RFC 6125). This hub's mTLS listener accepts a client certificate only if it
chains to a CA in `MIMI_CLIENT_CA`; the request handlers then see the end-entity certificate, and
`/notify/{roomId}` (§5.5) is accepted only when that certificate is valid for the room's hub, the
domain in the authority of the room URI. A certificate is valid for a domain when a `dNSName`
subject alternative name matches it, exactly or by a leftmost wildcard label; the common name is not
read. The same question gates the JSON-lane `/mimi/v1/notify`, which takes a `room` query for it.

- **What this does not bind.** The check says which names a certificate carries. It does not say
  which names the CA that signed it may issue. Every CA in the client bundle can issue a certificate
  for any provider domain, so trusting a CA means trusting it to name any provider, and a peer with a
  certificate from such a CA passes the `/notify` check for any room. Binding a CA to its names would
  take a name constraint per CA (an X.509 name-constraints extension on the CA certificate, or a
  configured list of allowed domains for each CA in the bundle, enforced when the chain is built).
  This hub has neither; a deployment that trusts an outside CA is trusting it with every domain.
- **`From`.** §4.1 says a request MUST identify its source provider in a `From` header (`mimi@<provider domain>`).
  This hub does not require the header, since the draft's own note questions it, and it refuses a
  request whose header names a domain the peer's certificate does not carry, is not of that form, or
  arrives on a connection that presented no certificate (403). The `Host` header, which names the
  target provider, is not compared with this hub's domain.
- **`submitMessage`, `update` and the rest.** Only `/notify` is bound to the room's hub. A peer that
  passes mTLS is not otherwise tied to the provider domain in its certificate on the other routes,
  as DIV-6 says for the identities inside a request body.

---

Divergences are revisited as the drafts move and as the accept-path work (DIV-6, DIV-9, DIV-10)
lands. DIV-1 through DIV-4 do not block interoperating with another provider on the supported
surface. DIV-5, DIV-7, and DIV-11 are closed or mostly closed (see above); DIV-6, DIV-8, DIV-9,
DIV-10, DIV-12, DIV-13, DIV-14, DIV-15, and DIV-16 still do, for the endpoints they touch, until closed.
