# Haven Interop

Making secure-messaging protocols interoperable - part of
[Haven](https://havenmessenger.com).

We implement **MIMI** (the IETF's *More
Instant Messaging Interoperability* drafts) and **MLS** (Messaging Layer Security, RFC 9420)
as working code another service can run against, and contribute what implementing surfaces
back to the working groups.

This repository is a MIMI/MLS interoperability library and reference hub: use it to
interoperate with Haven, or adopt it as the interop layer for your own service. It is not
Haven-specific - the protocol logic follows the IETF drafts, and Haven is one deployment of it.

> **Status:** a reference implementation of the MIMI content codec and room-policy roles, with
> the IETF content test vectors byte-verified against the official examples, and a hub
> demonstrating the core mechanisms (directory, key material, message relay, consent). It
> implements protocol-07. Known
> gaps against the full protocol-07 surface are listed in [`DIVERGENCES.md`](DIVERGENCES.md).
> Feedback welcome.

## Why use this
- **Protocol code against the IETF drafts.** MIMI protocol-07 (the JSON lane and the
  TLS presentation-language wire lane), mimi-content-10 (and what it reads from content-09
  peers, DIV-17), and room-policy-04, over MLS (RFC 9420) via openmls. `update` reads two of
  room-policy-04's components and refuses the other eleven (DIV-15).
- **A runnable, installable hub.** `mimi-hubd` is an mTLS daemon you can stand up from its
  quickstart and point an implementation at; its README shows the output of the commands
  it lists. It also installs like a normal system service - a systemd unit, a `.deb`, prebuilt
  Linux binaries, and a Docker image are all built from the same source (see mimi-hubd/README.md's
  "Installing as a service").
- **Conformance receipts.** The tests include hand-computed byte KATs and
  the official IETF mimi-content test vectors. Cross-implementation vectors against
  openmls-main are published with a full report
  ([`docs/vc-01-vector-report.md`](docs/vc-01-vector-report.md)), including a §5.6.1
  divergence this work found and narrowed.
- **Divergences documented.** Every departure from the drafts is recorded in
  [`DIVERGENCES.md`](DIVERGENCES.md).
- **Fed back to the working group.** Interactions this implementation surfaces are raised on
  the IETF mls/mimi lists as they are found.
- **Security invariants indexed.** [`SECURITY-INVARIANTS.md`](SECURITY-INVARIANTS.md) maps
  each cross-cutting invariant to where the code enforces it.
- **Standalone.** Apache-2.0, no submodules, no services needed to build and run the tests.

## See it run
- [mimi.havenmessenger.com](https://mimi.havenmessenger.com) - Haven's running hub, built from
  this repository. The directory is public; the protocol endpoints need a client certificate. No
  other provider has connected to it yet. To test against it, open an issue.
- [`mimi-hubd/README.md`](mimi-hubd/README.md) - quickstart for the reference hub daemon: mTLS
  server, a live directory endpoint, and both the JSON and TLS-PL wire lanes.
- [`docs/vc-01-vector-report.md`](docs/vc-01-vector-report.md) - a cross-implementation test
  against openmls-main, including the small-space PRP (§5.6.1) divergence found and how it was
  narrowed down.

## Why this is open
- This is the runnable reference for interoperating with Haven, and an interop layer any
  service can adopt to speak MIMI/MLS with any other service.
- The MIMI drafts are pre-standard and still moving; implementing them has already surfaced
  draft-level questions and divergences, which are documented here and raised with the
  working group.
- Anyone can check that what Haven ships matches the drafts as written.

## What lives here (and what does not)
**Here (open):** the interop library + `mimi-hubd` reference hub you can stand up yourself.
**Not here:** the production service that operates this protocol is out of scope
for this repository. (The relays/servers are untrusted by design; the cryptographic endpoint is
the client.)

## Related repositories
- [`havenmessenger/crypto`](https://github.com/havenmessenger/crypto) - the cryptographic core.
  Its own [`examples/`](https://github.com/havenmessenger/crypto/tree/main/examples) has a
  runnable usage sample.
- This repo - the interoperability layer.

Haven's client application is not yet public; the runnable examples in this repo and in
`havenmessenger/crypto` show the same public APIs the client calls.

## Try it: MLS Virtual Clients (draft-ietf-mls-virtual-clients-01)
`src/virtual_clients.rs` implements the Virtual Clients mechanism (§5-§6): multiple
devices ("emulator clients") jointly acting as one virtual client under a single MLS leaf. This is
running code against openmls; see the module's own doc comment for the full
scope statement (what's implemented vs. not, and why an external commit into the
emulation group doesn't touch Haven's rule against external commits).

```sh
cargo test --lib virtual_clients        # unit tests and openmls conformance tests
cargo run --example virtual_clients_demo  # a narrated walkthrough: two devices derive identical
                                           # secrets, a third onboards via external commit, one is
                                           # removed and the epoch advances
```

## License
[Apache-2.0](LICENSE). Haven's product code (client, crypto core) is AGPL-3.0; only this
interop layer is permissive.

## Security
See [`SECURITY.md`](SECURITY.md) - please use coordinated disclosure. The invariants this code
enforces (and where each is checked) are tracked in
[`SECURITY-INVARIANTS.md`](SECURITY-INVARIANTS.md).
