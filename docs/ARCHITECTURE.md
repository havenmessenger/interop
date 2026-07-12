# Architecture - Haven Interop

## Purpose
A spec-conformant implementation of the MIMI (More Instant Messaging Interoperability) and
MLS (RFC 9420) protocol logic - the layer that lets another service interoperate with Haven.
Native Rust, no UI, no platform bindings; a clean protocol library.

## Scope
- MIMI content/codec, consent, participant lists, room policy, URI handling.
- MLS group/commit machinery as used for cross-provider interoperability.
- `protocol_wire` rejects the QUIC varint's 8-byte/62-bit length-of-length form itself, so a
  declared length this crate ever accumulates is at most 30 bits; a build-time assertion
  (`usize::BITS >= 32`) enforces that this stays wrap-safe rather than leaving it an unstated
  assumption.

## Boundary (open vs. closed)
**Open (here):** the protocol/interoperability library (`mimi-core`, the repo root) and a
reference hub daemon (`mimi-hub/`) that runs it.
**Closed (by design):** Haven's own production deployment of a hub is closed by design, along
with the rest of Haven's operational infrastructure. Across federation the Haven *client* is the
cryptographic endpoint; hubs and relays carry ciphertext only and hold no decryption capability.

## Conformance
This crate tracks the relevant IETF drafts/RFCs. Known divergences from the drafts are in
[`DIVERGENCES.md`](../DIVERGENCES.md).

## Module map
- `gate` - the security-critical foreign-input ingest logic: the ciphersuite accept-gate
  (`INV-MLS-002`), the `identifierQuery` no-existence-oracle (`DIV-4`), the one-time KeyPackage
  store contract, and notify dedup.
- `content` - the MIMI content codec (content-09 §4-6): deterministic CBOR, the part type
  system, and the validation MUSTs (nesting depth, no-HTML, reply-loop).
- `consent` - the cross-provider anti-spam/privacy gate (protocol-06 §5.7): consent request,
  grant, and revoke, checked before a requester can reach a target.
- `participant_list` - participant-list changes as an AppSync proposal (protocol §5.3, §7.5).
- `room_policy` - the role model and authorization logic (room-policy-03); roles live in the
  participant list, this module enforces what each role may do.
- `protocol_wire` - the protocol-06 §5 TLS presentation-language wire framing, alongside the
  JSON `/mimi/v1/*` compatibility lane a foreign implementation does not speak.
- `uri` - MIMI identifier URIs (protocol-06 §4): `mimi://authority/{u|r|d}/path` addressing,
  where the authority is the destination provider.
- `virtual_clients` - draft-ietf-mls-virtual-clients-01 §5-6: the emulation-group secret
  derivation, Small-Space PRP, reuse guard, and generation-ID mechanism.
- `spec_capability_proof` (test-only, `external-ops` feature, off by default) - proves
  openmls's own external-commit and external-proposal mechanisms are real and testable, for a
  full-fidelity consumer. Not Haven's own acceptance mechanism; see `gate`'s own scope note.

`mimi-hub/` (the reference hub daemon) consumes these modules and adds the HTTP transport, mTLS
termination, and durable storage. All library modules are dependency-free of FRB and the app;
each module's tests are self-contained.

## Enforcement direction
Several wire types decode into public fields with validation as a separate, skippable call - a
`ConsentEntry` that decoded successfully but was never passed to `validate_consent_entry` looks
identical, at the type level, to one that was checked. The crate is moving toward decoders that
either return a validated value or an error, with no path to an unvalidated-but-constructed
instance. Two further seams the same discipline targets: one canonical principal type for
`mimi://` identifiers (today `protocol_wire::IdentifierUri` is a second, unvalidated wrapper that
can diverge from `uri::MimiUri`'s parsed-and-canonicalized form), and binding the authenticated
participant-list payload to the MLS Add/Remove it accompanies, so role authorization, membership
limits, and the roster mutation land as one step instead of three independently-ordered calls.
Changes toward this shape land incrementally; today's decoders stay available and correct
throughout.

## Wire-format conformance

`mimi-hub`'s v1 started as a JSON-only compatibility lane. As of the routes in
`mimi-hub/src/http.rs`, the directory endpoint plus 14 `/mimi/v1/*` JSON routes are live, and 6 of
them (`keyMaterial`, `submitMessage`, `notify`, `identifierQuery`, `requestConsent`,
`updateConsent`) also have a `/mimi/pl/*` route speaking `draft-ietf-mimi-protocol`'s TLS
presentation-language (TLS-PL) framing directly. Both lanes read and write the same underlying
store. The remaining JSON-only routes (room policy, member role, participant, sender
authorization) are local hub-administration RPCs without a spec wire equivalent.

One known nuance: on the JSON lane, the consent endpoints (`requestConsent`/`updateConsent`)
return HTTP 422 rather than the documented always-201 response when the request body fails to
deserialize; the TLS-PL wire lane returns the spec-correct always-201. This is a JSON-transport
artifact of the framework's body extractor, not a protocol divergence.
