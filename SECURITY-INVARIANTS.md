# Security Invariants

<!-- AUTO-GENERATED - DO NOT EDIT BY HAND. Generated from and kept in sync with this crate's
     design invariants. -->

This file resolves the `// WHY: INV-*` references cited in this repo's source. Only
invariants cited in this repo are included. Each entry states a design invariant, the
reason it holds, and the change-control it is under (pre-commit checks and code review).

## `INV-CSP-003` - Inbound email HTML is sanitized before any DOM render

**Severity:** critical · **Change control:** security review required

Email bodies are untrusted input. Every inbound HTML body passes through the sanitizer
before it reaches a renderer; unsanitized user-supplied HTML is never handed to a DOM.

## `INV-MIMI-001` - The MIMI provider runs isolated: no production user secrets, opted-in users only, ciphertext-only transit

**Severity:** high · **Change control:** security review required

The MIMI provider holds no production user secrets beyond the narrow seam it needs
within its own provider, and can reach only users who opted into federation.
Cross-provider traffic crosses intermediate infrastructure as ciphertext; TLS terminates
only at the provider itself.

## `INV-MIMI-002` - In MIMI federation the client is the cryptographic endpoint; no server-side component can decrypt messages

**Severity:** high · **Change control:** security review required

MLS keys live in the client. The hub and any relay on the path carry ciphertext they
cannot decrypt. No provider- or relay-side component holds message-decryption
capability.

## `INV-MIMI-003` - The MIMI lane and the native messaging lane are separate; cross-provider MLS cannot alter the native wire format

**Severity:** high · **Change control:** security review required

Cross-provider (MIMI) messaging runs on its own lane with its own endpoints.
Haven-to-Haven messaging keeps its existing wire format, unchanged by MIMI work, and a
change on the MIMI side is not reachable from the native send or receive path. The two
lanes evolve independently, which is what lets the MIMI lane track moving IETF drafts
without putting the native protocol at risk.

## `INV-MLS-001a` - External commits (RFC 9420 external-commit join) are disabled in every lane, permanently

**Severity:** high · **Change control:** security review required

Members join a group only by processing a Welcome addressed to their validated
KeyPackage, and membership changes are member-signed commits. No code path constructs or
accepts an RFC 9420 external commit, in either the native or the MIMI lane. This follows
the External-Operations TreeKEM analysis (eprint 2025/229): external joins let an
adversary holding a compromised long-term secret re-enter a group at any time, a strictly
larger surface than member-driven adds. The refusal is structural and negative-tested.

## `INV-MLS-001b` - External proposals are refused in the native lane; the MIMI lane accepts only a pre-configured hub's Remove proposals, each requiring an explicit member commit

**Severity:** high · **Change control:** security review required

RFC 9420 external proposals (Sender::External) are refused in native messaging. The MIMI
lane accepts exactly one narrow case: a Remove proposal from the group's single
allowlisted hub credential - and even then the proposal is inert until an existing member
explicitly includes it in a commit. Nothing is auto-committed. Both the refusals and the
narrow acceptance path are negative-tested.

## `INV-MLS-002` - The MLS ciphersuite is pinned two-sided to 0x0001: generation uses only it, and inbound objects under any other suite are rejected before openmls

**Severity:** high · **Change control:** security review required

Haven generates MLS objects only under suite 0x0001
(MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519) and rejects any inbound MLS object
carrying a different suite before it reaches openmls. A suite change is a wire-format
event: it goes through one policy seam rather than scattered constants, and is gated by
known-answer tests. This is also the crypto-agility seam - adding a post-quantum suite is
a change to configuration and vectors, not a rewrite.
