# Security properties of mimi-hubd

What the reference hub guarantees, and where the code holds each one. What it does not do yet is in
[`DIVERGENCES.md`](DIVERGENCES.md); how to report a problem is in [`SECURITY.md`](SECURITY.md).

## It relays ciphertext and holds no key that opens an application message

Application messages reach the hub as MLS `PrivateMessage`s and leave it unchanged: the store keeps them as opaque bytes
under a routing key (`mimi-hubd/src/store.rs`, the `messages` and `welcomes` tables) and bounds only their size and
number. The hub is not a member of any group and holds no group secret. The only MLS content it reads is what MLS sends in
the clear for a delivery service: a Commit's proposals in a `PublicMessage` (participant-list and room-policy changes,
`src/commit_wire.rs`) and the outer fields of a handshake message. A Commit wrapped in a `PrivateMessage` is refused.

## It makes no request to another hub

The hub only answers requests. It has no HTTP client, opens no outbound connection, and reads the keys of peers that sign
requests from a file a job on the host keeps current (`MIMI_PEER_KEYS`). So nothing a peer sends can make the hub connect
anywhere, its own listeners included. Delivery to other hubs is not built yet (DIV-5); when it is, each outbound request
is https with the hub's client certificate and refuses a loopback, link-local or unspecified destination before
connecting.

## Every peer request is from an authenticated provider

The peer listener requires a client certificate from the configured CA bundle, or a request signed with a key the
provider publishes in DNS (`mimi-hubd/src/provider_auth.rs`, `signature.rs`: a signature older than 300 s or more than
60 s ahead is refused). Only the directory document is served without either. Which provider a certificate names, and
what any CA in the bundle can name, is in DIV-16.

## The operator's routes listen on loopback only

`roomPolicy`, `memberRole` and `addParticipant` change a room's policy, roles and participants. They are not served to
peers: only on the listener `MIMI_ADMIN_BIND_ADDR` names, and the hub does not start if that address is not 127.0.0.0/8
or `::1` (`mimi-hubd/src/admin.rs`). Unset, there is no such listener.

## It accepts only the ciphersuites its policy names

A KeyPackage, Welcome or GroupInfo from another provider is refused before any decoder or openmls touches it when its
ciphersuite is not in the accepted list: the suite is read from its fixed wire position first (`src/gate.rs`). The list
is `mls_ciphersuites` in the policy file, by default every suite the crypto provider implements; the directory advertises
exactly it. A policy file that cannot be read or is not valid stops the start.

## Hostile input fails closed

Every decoder bounds what it reads before it allocates: run lengths and element counts (`src/protocol_wire.rs`, 1024
elements and 1 MiB per run, 16 query elements), CBOR nesting (`src/content.rs`, depth 4 in content, recursion 64), and a
decoder that can panic on malformed input runs behind `catch_unwind` so a bad object is a refusal, not a crash.

## Its store has bounds

Per recipient, 32 pending Welcomes and 256 pending messages, each at most 64 KiB, for 24 hours. Per user, the newest 64
KeyPackages, each kept 30 days. At most 1024 rooms, 256 participants a room, 65,536 consent records and 65,536 abuse
reports. Proposals held for a member's leave: 4 KiB each, 64 KiB and one more than the room's participants a room, for 15
minutes. A routing key is at most 256 bytes and a URI at most 512. The constants are in `mimi-hubd/src/store.rs` and
`mimi-hubd/src/lib.rs`.

## `identifierQuery` says found or not found, and nothing else

A user the hub answers for (the policy's `identifier_discovery`) is `success`; every other answer is the same `notFound`,
byte for byte, whether the user is outside the setting, does not exist, or the request could not be read (DIV-4).
