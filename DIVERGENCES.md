# Divergences from the drafts

`mimi-hub`'s v1 implements a subset of `draft-ietf-mimi-protocol`, `draft-ietf-mimi-content`,
and `draft-ietf-mimi-room-policy`. The authoritative source is the hub's own `directory`
endpoint `unsupported` block (`mimi-hub/src/lib.rs`); this file explains the reasoning.

DIV-1 through DIV-4 are scoping decisions: deliberate, documented choices about what v1 does
not do. DIV-5 through DIV-11 are gaps in what v1 attempts: endpoints or fields the code accepts
and processes without yet enforcing everything the draft requires. A strict implementation of
the affected endpoints will not interoperate with this hub until those close.

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

`POST /mimi/pl/update/{roomId}` (§4.3.2) takes a real, `PublicMessage`-wrapped MLS Commit carrying
exactly one custom proposal. `mimi_core::commit_wire::decode_single_custom_proposal_commit` reads
the proposal's type and payload - independent of openmls's own (crate-private) `Commit` type,
hand-coded the same way every other MIMI-specific structure in this codebase is - without verifying
the Commit's signature or holding any group state, matching RFC 9420's own delivery-service trust
model (the DS is not expected to do either; that is the receiving member's job). Commits on this
hub's groups already travel as `PublicMessage`, so the proposal bytes are visible on the wire
without needing that machinery in the first place.

- A `mimiParticipantList` proposal's payload is applied to this room's `room_participants`/
  `member_role` tables. **Caveat**: indices in the payload resolve against this hub's own
  canonical participant ordering (alphabetical by URI, the same order `list_participants` already
  returns everywhere else this hub needs one) - a peer that computed those indices against a
  different ordering convention will not apply correctly. This reference hub does not attempt to
  reconcile a foreign ordering convention.
- A `mimiRoomPolicy` proposal's payload is the JSON-serialized `RoomPolicy` this hub already stores
  for the JSON-compat `roomPolicy` route - a whole-object replace, validated the same way
  (`RoomPolicy::validate`) before it is stored.
- A Commit that mixes the custom proposal with a standard MLS proposal (Add, Remove, ...) in the
  same list is refused, not decoded: skipping past a standard proposal's own body (an `Add`, for
  instance, embeds a full KeyPackage) needs that proposal's own decoder, which is out of scope. A
  sender that wants this hub to read the change sends it as its own Commit.
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
`update`'s `RatchetTreeOption`/`GroupInfoOption` fields (§5.3) also stay opaque, for the same
reason as the rest of `update`'s codec: no live accept-path exists yet.

---

Divergences are revisited as the drafts move and as the accept-path work (DIV-6, DIV-9, DIV-10)
lands. DIV-1 through DIV-4 do not block interoperating with another provider on the supported
surface. DIV-5, DIV-7, and DIV-11 are closed or mostly closed (see above); DIV-6, DIV-8, DIV-9, and
DIV-10 still do, for the endpoints they touch, until closed.
