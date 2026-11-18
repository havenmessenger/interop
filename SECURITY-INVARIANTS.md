# Security properties of mimi-hubd

What the reference hub guarantees, and where the code holds each one. What it does not do yet is in
[`DIVERGENCES.md`](DIVERGENCES.md); how to report a problem is in [`SECURITY.md`](SECURITY.md).

## It relays ciphertext and holds no key that opens an application message

Application messages reach the hub as MLS `PrivateMessage`s and leave it unchanged: the store keeps them as opaque bytes
under a routing key (`mimi-hubd/src/store.rs`, the `messages` and `welcomes` tables) and bounds only their size and
number. The hub is not a member of any group and holds no group secret. The only MLS content it reads is what MLS sends in
the clear for a delivery service: a Commit's proposals in a `PublicMessage` (participant-list and room-policy changes,
`src/commit_wire.rs`) and the outer fields of a handshake message. A Commit wrapped in a `PrivateMessage` is refused. For
a room whose ratchet tree it keeps, the hub holds that room's public group state (the tree and GroupContext, as
openmls's `PublicGroup`; `mimi-hubd/src/room_tree.rs`, `group_store.rs`): public keys and hashes, no epoch secret.

## A tracked room's Commits are verified against its tree

Once a room's tree is seeded (DIV-10 says from what, and what the seed is trusted for), every Commit for it is verified
before anything changes: its sender must be a member whose signature verifies, it must be for the room's group and epoch,
and it must apply to the tree. One that does not is refused, changes nothing, and is logged with the room and the sender's
provider; the hub never drops a room's checks because a Commit failed them. Only the operator can drop a room's tree
(`untrackRoom`, loopback only).

Each participant-list change to a tracked room is authorized for the member who proposed it, by the role the room's
list gives that member and the room's policy (`mimi-hubd/src/role_checks.rs`, room-policy-04 §8.1); a change it does
not authorize is refused and changes nothing. The policy and list are the group's from its GroupContext, so the
operator's routes cannot change them for a tracked room. What is not checked yet is in DIV-15.

## Its requests to other hubs go only where they are meant to

The hub reads the keys of peers that sign requests from a file a job on the host keeps current (`MIMI_PEER_KEYS`), and
has one outbound client (`mimi-hubd/src/outbound.rs`); the outbox worker (`outbox.rs`) and the directory lookup
(`peer_directory.rs`) send through it, and nothing else reaches another provider. (The one other connection the hub can
open is to the operator's own OpenTelemetry collector, below.) Every request that
client makes is `https` to a host that is the peer's domain or a subdomain of it, endpoint URLs from a peer's directory
included, is signed with the provider's DNS-published key when one is configured (`request_signing.rs`), presents a
client certificate when one is configured (`MIMI_CLIENT_CERT`; the server's, for a hub that does not sign), and checks
the peer's server certificate for that host. The
host is resolved once; if any address it resolves to is loopback, unspecified, link-local, private, shared,
unique-local, multicast, documentation or reserved, the request is refused and nothing connects, unless the operator's
`MIMI_OUTBOUND_ALLOW` names that range. The connection goes to the checked address itself, and through a `CONNECT`
proxy the tunnel names that address, so no second lookup can lead anywhere else. Redirects are not followed.

## What it tells an OpenTelemetry collector, and only the operator's

A build with the `otlp` feature, the published binary among them, exports traces and metrics only when
`MIMI_OTLP_ENDPOINT` names a collector (`telemetry.rs`, `otlp.rs`). That address is the operator's setting, not a peer's,
so it does not go through the outbound gate; instead it must be `https`, or `http` to a loopback address only. A record
holds the method, the route template this crate's router matched, the status or a failure's class, the provider domain
the request was authenticated as or sent to, a refusal's problem type, and for a queued delivery its attempt number, and
nothing else: no path value, query, header, certificate, body, user or room. Export runs on threads of its own, so a
collector that is slow or down drops records and never slows or fails a request.

## Every peer request is from an authenticated provider

The peer listener requires a client certificate from the configured CA bundle, or a request signed with a key the
provider publishes in DNS (`mimi-hubd/src/provider_auth.rs`, `signature.rs`: a signature older than 300 s or more than
60 s ahead is refused). Only the directory document is served without either. Every other request names its provider
in `From`, and the proof must authenticate that domain. A signature's nonce is remembered for its window, and a second
use by the same key is refused; the policy can require a nonce on keyMaterial (`require_nonce_on_key_material`).
Which provider a certificate names, and what any CA in the bundle can name, is in DIV-16.

## An external join is checked against the room's tree, its policy and the joiner's role

A client can join a room by external Commit only where the hub keeps the room's ratchet tree, so the Commit is verified
against it like any other; only when the user its new leaf names belongs to the provider whose proof came with the
request (on the client lane: is the requesting user); only where the room's operational policy allows it (or, with no such policy, the hub's
`external_commit_when_unset`); only for a joiner the room's roles admit (`canAddOwnClient` for a listed user's new
client, `canOpenJoin` on role 0 for an unlisted one, `mimi-hubd/src/external_join.rs`); never while proposals are held
for the epoch; and changing nothing but the joiner's own entry in the list. A GroupInfo is kept and served
(`group_info_endpoint.rs`) only for such a room, encrypted to the requester's key and signed with the hub's own MLS key
(`MIMI_HUB_MLS_KEY`), which signs nothing else. A change to the room's operational policy needs
`canChangeMlsOperationalPolicies`, to its roles `canChangeRoleDefinitions`, and to its base policy
`canChangeRoomMembershipStyle`, in the proposer's role (DIV-15).

## A client-lane request acts for one user of this hub, and only for them

The client lane (`MIMI_LANE_BIND_ADDR`, off when unset) is a listener of its own; a peer request is not served there,
nor a lane request on the peer listener. A lane request verifies only with a key in `MIMI_LANE_KEYS`, under the tag
`haven-client-lane` and nothing else, with a new nonce, at most 30 s old, signed after the process started
(`mimi-hubd/src/client_lane.rs`); its `mimi-client-user` must be a user URI on this hub's domain. Every route acts for
that user and takes no user from the body (`client_http.rs`). In a room change the user speaks only for themself
(`requester.rs`): a leave removes only them, an external Commit joins only them, a GroupInfo that seeds a room's tree
is signed by them. A KeyPackage the user publishes names them, exactly, in its basic credential. Each user has a
bounded number of requests a minute.

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
