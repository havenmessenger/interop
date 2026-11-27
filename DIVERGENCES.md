# Divergences from the drafts

`mimihubd`'s v1 implements a subset of `draft-ietf-mimi-protocol`, `draft-ietf-mimi-content`,
and `draft-ietf-mimi-room-policy`. The authoritative source is the hub's own `directory`
endpoint `unsupported` block (`mimihubd/src/lib.rs`); this file explains the reasoning.

This file lists only what is not built yet, and the points where the drafts are open and this hub
takes a reading the working group may settle otherwise. What a deployment chooses (which
ciphersuites it accepts, who `identifierQuery` finds) is a setting, described in
`mimihubd/README.md`, not a divergence. DIV-1, DIV-3 and DIV-4 are parts not built yet. DIV-5
through DIV-15 are gaps in what v1 attempts: endpoints or fields the code accepts
and processes without yet enforcing everything the draft requires, or behaviour that differs
from the draft on a point where the draft is silent or the pinned MLS library falls short. A
strict implementation of the affected endpoints will not interoperate with this hub on those
points until they close.

## DIV-1 - GroupInfo and external-commit join: built for rooms whose tree the hub keeps

A client can join a room by external Commit (protocol-07 §5.6), as the drafts describe and as mimid does it
(`mimihubd/src/external_join.rs`, `group_info_endpoint.rs`):

- **Whether the room allows it**: its `mls_operational_policy` component's `external_commit_allowed` (DIV-18). A room
  with no such component follows MLS, where an external join is possible; a deployment can refuse those rooms instead
  (`external_commit_when_unset = "deny"` in the hub policy).
- **Who may join**: a listed participant whose role holds `canAddOwnClient` (a new client of its user), or an unlisted
  user when role 0 holds `canOpenJoin`, whose external Commit then adds that user, and only that user, to the
  participant list. A room with no roles has no role checks (room-policy PR #52: "A room that has no `roles_list` has no role-based restrictions."). Preauthorized users are not read and
  joining codes are refused: not built yet.
- **`POST /groupInfo/{roomId}`**: the request's `SignWithLabel` must verify, its BasicCredential must name a user of
  the provider the request's proof authenticates, and the user must be one who may join. The answer is the room's last
  Full GroupInfo, its tree as a `full` RatchetTreeOption and the proposals held for the epoch with the time each was
  accepted, `EncryptWithLabel`ed to the request's key with the room ID as context, and signed by the hub's own MLS key
  (`MIMI_HUB_MLS_KEY`) as `hub_sender`, credential `mimi://<hub domain>`. Every refusal is `notAuthorized`, the code
  §5.6 has; a room this hub does not host is `404`, as mimid answers `noSuchRoom`. A hub with no MLS key answers every
  request `notAuthorized`. Mark's proposed `externalJoinNotAllowed` code is not used until a draft defines it.
- **The GroupInfo kept** is the Full one the room's last accepted Commit (or the bundle that seeded it) carried, and
  only while the room allows external Commits. After a Commit with a Partial GroupInfo or none, none is kept until the
  next Full one: a Partial one is rebuilt to check the Commit (DIV-12), not kept.
- **An external Commit on `update`** is verified against the room's tree like any other (openmls `PublicGroup`), and is
  refused (`notAllowed`, with the reason) when the user its new leaf names is not of the provider whose proof came with
  the request (the leaf is signed by the joiner's own key, so nothing else ties that user to a provider), when the
  room does not allow it, when its joiner may not join, when it changes
  anything but its joiner's own entry in the list, when proposals are held for the epoch, or when the hub keeps no tree
  for the room (an untracked room refuses every external Commit, since nothing could verify it).
- **No `externalProposals` staple**: §5.5 lets the hub re-issue, as its own external proposals, the held proposals an
  external Commit invalidates. That needs the hub listed in each group's `external_senders`, which groups do not do, so
  this hub refuses an external Commit while proposals are held instead, as mimid does, and its `externalProposals` is
  always empty.

## DIV-2 - CLOSED: the accepted ciphersuites are a setting

The accept-gates refuse a KeyPackage, Welcome or GroupInfo in a ciphersuite outside the accepted
list before the bytes reach openmls. The list is the deployment's (`mls_ciphersuites` in the
policy file, `mimihubd/README.md`); by default it is every suite the crypto provider implements,
and the directory lists the same suites.

## DIV-3 - Assets and OHTTP transport

Not supported. v1 is messaging-only: text content over the wire and JSON lanes, no binary
asset transfer, no OHTTP relay path (`§5.10`).

## DIV-4 - `identifierQuery` answers a single Handle or Nick query only: other identifier types not built yet

Who a query can find is the deployment's setting (`identifier_discovery`, `mimihubd/README.md`). On the TLS-PL wire
lane the answer is an `IdentifierResponse`, as §5.8 has it, always HTTP 200 (notFound means the request was acceptable
and nothing matched, so the code in the body says the outcome): a user the hub answers for is `success` with the
user's URI on this provider; every other answer is the same `notFound` body, byte for byte, whether the user is
outside the setting, does not exist, or the request could not be decoded or evaluated. The JSON lane answers with the
bare status (200 or 404, no body).

The hub cannot honor the draft's implied AND-across-elements semantics for a
multi-element `IdentifierRequest`: v1 has no data model for `email`/`phone`/`oidcStdClaim`/
`vcardField`/etc. lookups, only usernames. A request is answered only when it carries exactly
one query element of type `Handle` or `Nick`; a request with zero elements, more than one
element, or any other element type is treated as unanswerable and always returns not-found,
rather than silently evaluating just the first element regardless of its type or what else was
asked.

As §5.8 has it, a `Nick` search is the bare user name (`alice`), and a `Handle` search is the
entire handle URI. The handle URI forms this hub takes for one of its users are
`mimi://<this hub's domain>/u/<name>`, compared in canonical form (RFC 3986 §6.2.2: case in the
scheme and host, percent-encoded unreserved characters; a name written as an IRI is mapped to its
URI, RFC 3987 §3.1, so `zoë` and `zo%C3%AB` are one name), and `im:<name>@<this hub's domain>`,
the form of the draft's own example. A found user is answered as a URI, the name percent-encoded
from its UTF-8. A handle on another provider, a room or device URI, a bare name searched as a
handle, or a name that does not decode to UTF-8 is not-found.

## DIV-5 - fan-out to other providers, and what is not delivered yet

For a room it hosts, the hub fans out what it accepts (protocol-07 §5.5; `mimihubd/src/fanout.rs`): each local
participant gets the message in its queue, and each other provider with a participant gets one FanoutMessage in the
outbox, which a worker posts to that provider's `notify`.

- **A Commit** goes to the participants before and after it, so a member it removes is told (§5.5 SHOULD), with an
  empty `externalProposals`: the hub takes no external Commit, so it has nothing to staple.
- **A Welcome** in the Commit's bundle goes with the bundle's `RatchetTreeOption`, to the provider the hub recorded
  for each `KeyPackageRef` in its secrets when it claimed that KeyPackage, and, for a ref it has no record of, to the
  providers of the users the Commit adds (mimid routes every Welcome that way). The submitter's provider is not left
  out (§5.5). A new member of this provider gets it in its own queue.
- **Held leave proposals** go when they are held, the first with the rest as `moreProposals`, as the bundle carried
  them (§5.5 MUST).
- **An application message** goes to every participant but its sender, with no `frank`: this hub franks nothing.
- The sender's provider is not skipped for its own message: §5.5 does not require the hub to send it back, and asks
  the client and its provider to be ready for one.
- Fan-out runs after the change is stored and never undoes it: a failure to queue is logged, and the message stays
  accepted.

The outbox follows §5.5 as mimid's does, where the draft leaves it open: one FIFO queue per room and destination
provider, of which only the head is attempted, its bytes fixed so a retry is a byte-identical duplicate; `201`
delivers it; a `4xx` other than `408` and `429` drops it and logs it; anything else retries after a backoff of 1 s
doubling to 5 min, or the `Retry-After` asked for, up to a day. Nothing expires while a provider is down; the operator
sees each queue (`GET /mimi/v1/outbox`), with its head's last outcome, and can drop one (`dropOutbox`). A request the
outbound client refuses (a peer whose name resolves into a refused range, or a directory naming another host) is
retried like any failure, so that room's queue to that provider does not move until the operator changes the
configuration or drops the queue; its last outcome is the refusal's reason. A provider's endpoints come from its
directory at `https://<domain>/.well-known/mimi-protocol-directory`, or under the base the operator's `MIMI_PEERS`
gives it. Every request goes through the hub's one outbound client (`mimihubd/src/outbound.rs`; SECURITY-INVARIANTS
says what it refuses). Two of its rules are this hub's, not the draft's. A URL it sends to must name the peer's own
domain or a subdomain of it as its host, so a directory that points an endpoint at another host is refused, where
protocol-07 §5.1 takes a directory's URLs as given. And the peer's server certificate is checked for the host
connected to, by the same `dNSName` test DIV-16 applies inbound; for an endpoint on a subdomain that is the subdomain,
not the provider domain §4.1 names.

**keyMaterial for a user of another provider** (`mimihubd/src/key_material_proxy.rs`), chosen by the request's
`targetUser`: the hub forwards it only for a room it hosts and only from a participant whose role may add
participants (`canAddParticipant`; any participant of a room with no roles), as mimid does. Any other such request is
answered `noConsent`, which is what §5.2 has for a refusal, and nothing is forwarded. The request goes as received to
the target provider's directory `keyMaterial` URL; a `200` answer must decode as a `KeyMaterialResponse`, and the
`KeyPackageRef` of each KeyPackage in it is recorded against that provider for 30 days, so the Welcome that adds it is
routed there. The answer is returned as received. A peer that fails or answers anything else is `502`. The hub does not
check the request's signature before forwarding: the target provider does (DIV-6).

**A room on another hub**, as this provider's users see it (`mimihubd/src/follower.rs`): a Welcome its hub sends is
queued for each user here whose published KeyPackage it names and makes that user a member of the room here; what
the hub sends after that (Commits, proposals, application messages) is queued, as its MLSMessage without the
FanoutMessage's tail, for every member here, in arrival order. A message for a room with no member here is refused
with `404` and the problem `no-local-member` (DIV-16). A FanoutMessage already delivered for the room is answered
`201` and not delivered again, whether the hub resends the same body (§5.5) or the same message with another
timestamp.

Not built yet:

- **A member's removal, on this side.** A user stays a member of a room on another hub, and keeps getting what its
  hub sends, after a Commit removes them: this provider holds neither the room's participant list nor its tree, so it
  cannot tell which user a list index or a leaf is. mimid's follower does the same, until an explicit leave.
- **Our own users' requests to another hub**: this provider does not relay its users' `update` or `submitMessage` to
  the hub of a room hosted elsewhere.
- **Several FanoutMessages in one `notify` body**: §5.5 allows them; this hub sends one per request and reads one.

`submitMessage` checks the sender first (`authorize_sender`: an active, unremoved participant whose role may send).
The JSON compatibility lane's `submit_message` is the older unauthenticated path (`?recipient=` takes any opaque
string, with no room semantics) and does not fan out.

## DIV-6 - client-asserted identity is not bound to an authenticated channel

This reference hub authenticates the transport peer via mTLS (an allowlisted certificate), never
the individual end-user identity inside a request body. The three wire routes that carry a claimed
identity have different answers, not one shared gap:

- **`submitMessage`**: `sendingUri` is unverified by this hub, and that is not a gap. RFC 9420's own
  delivery-service trust model does not expect the DS to verify a message's signature or hold group
  state - that is the receiving member's responsibility, checked against the sender's leaf
  credential inside the actual MLS group. This hub relaying an unverified `sendingUri` claim matches
  the spec's own DS posture rather than diverging from it.
- **`keyMaterial`**: the requester is bound to the peer. The provider path takes a `KeyMaterialRequest` only from a
  peer whose proof authenticates the provider of its `requestingUser` (never this provider: a peer does not speak for
  this provider's users), or the provider hosting the room the request names, the room's hub, through which §5.2 sends
  every request ("MUST be sent via the hub provider of whatever room they will be used in"); otherwise `403
  not-permitted`. The path's user and the body's `targetUser` must be the same user, since the KeyPackage is taken for
  the one and consent is read for the other; otherwise `400 malformed-request`. What stays open is the room clause, at
  its full width: any authenticated peer can name any requester by naming a room on its own domain, since the target's
  provider cannot tell whether that room exists. It follows from §5.2, which has the target's provider hear the request
  from the room's hub, and from a BasicCredential, which binds the request's signature key to no one; there is no fix
  inside protocol-07. A consent scoped to a room narrows it, and that is the granting user's choice. What the binding
  does close is a peer naming a requester of another provider for a room on that provider or on a third one. The
  provider-path rate limit is therefore counted on what is proven, the peer's domain, as well as on the requester
  (DIV-23). Unlike `submitMessage`, the draft's own `KeyMaterialRequest` (§5.2) carries a self-signed identity claim (`requesterSignatureKey`/`requesterCredential`/
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
  registry) should be revisited before general availability. A request for another provider's user is forwarded as
  received (DIV-5): this hub does not check its signature and cannot sign one, so the target provider checks it, and
  a KeyPackage is claimed from another provider only for a requester whose client signs the request.
- **`consent`**: `ConsentEntry` (§5.7) carries no signature field at all in the draft - no
  self-signed mechanism exists here for this hub to check even if it wanted to. This may be a
  genuine gap in the draft itself rather than an implementation gap; worth raising with the WG
  rather than inventing a private signing convention unilaterally.

## DIV-7 - the directory document - CLOSED

§5.1 defines a directory whose top-level keys are the endpoint URLs. This hub's `directory()`
now publishes those flat, draft-shaped keys (absolute HTTPS URLs) for the six endpoints it
wire-routes, alongside the pre-existing `endpoints` (JSON compat lane) and
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

## DIV-10 - CLOSED for room updates by Commit; four operations have no wire route of their own

`update` (§5.3) applies a Commit carrying participant-list changes, room-policy changes, or both (one change per
policy component; a roles_list never beside a participant-list change), with or without `Add` and `Remove` proposals, and a member's leave through proposals the next Commit includes by reference.
`roomPolicy`, `memberRole`, `addParticipant` and `authorizeSender` have no wire route of their own: on the wire they
are what an `update` does.

`POST /mimi/pl/update/{roomId}` (§5.3) takes an `UpdateRequest`, a `HandshakeBundle` whose
`PublicMessage`-wrapped MLS Commit carries participant-list changes, room-policy changes, or both (and, since
the rewrite below, any `Add` and `Remove` proposals beside them). `mimi_core::commit_wire::decode_commit_proposals` reads
each change's type and payload and the Adds and Removes - independent of openmls's own (crate-private) `Commit` type,
hand-coded the same way every other MIMI-specific structure in this codebase is. For a room whose ratchet tree the hub
keeps (the tracked rooms, below) the Commit is also verified against the tree with openmls before anything changes. A
room hosted here that the hub keeps no tree for takes no change the hub cannot authorize, by default (below). Commits on this hub's groups travel as `PublicMessage`, so the proposal bytes are visible
on the wire.

- **Tracked rooms: the hub keeps the room's ratchet tree once a bundle gives it one.** A room is tracked from the first
  accepted Commit whose bundle carries a Full GroupInfo and a full ratchet tree (ratchet-tree-options `full`). From then
  on the hub moves the tree on from every Commit it accepts, so any `RatchetTreeOption` will do (a `distributionService`
  hub, from the room's second Commit). Seeding is trust on first use: a member that already holds the room's next epoch can seed a tree of its own
  making. It is narrowed by what the hub checks first: the GroupInfo is for the epoch after the Commit, signed by a
  member of the tree it comes with; that member's provider is the peer that sent the bundle; and every participant the
  hub lists for the room is a member of the tree. The hub records the group's id and which provider seeded the room,
  and logs it. A room's creator is in its group's participant list from the group's creation, which no Commit carries,
  so for a room the hub has seen no Commit or participant for (one another provider's client made here), the list
  before its first Commit is the creator alone, the GroupInfo's signer.
- **A room the hub hosts but keeps no tree for takes no change it cannot authorize** (`untracked_rooms = "refuse"` in
  the hub's policy, the default). Protocol-07 §5.3 lets the client choose what the bundle carries and gives the hub no
  way to ask, but the hub is the one that enforces the room's policy (§9), and without the tree it cannot tell who
  proposed a change. So the room's first Commit is taken only when its bundle seeds the tree, and a room with Commits
  but no tree (one from before the hub kept trees, or after `untrackRoom`) takes a participant-list or room-policy change
  by value only when its bundle seeds the tree: without the GroupContext the hub cannot tell whether the group has a
  `roles_list`, so every such change is one that needs it. Anything else is refused `notAllowed`, saying a Full
  GroupInfo and the full tree are needed, and logged with the room. A seed this needs is checked before anything
  changes, and a bundle that fails a check refuses the Commit. The seeding Commit's changes are authorized for its
  committer like a tracked room's (DIV-15): the GroupInfo's signer, which must be the leaf that sent the Commit, against
  the room's policy before the Commit (the hub's; for a room it holds none for, the group's, and then a room-policy
  change in that Commit is refused) and its list before it. A Commit that commits only held leaves (bound to the
  requester when held, below) or changes only room metadata is taken as before. `untracked_rooms = "accept"` is the
  other choice: **the hub applies changes it cannot authorize**, trusting the members to have checked them (RFC 9420's
  delivery service is not required to), until a bundle gives it the tree.
- **A tracked room's Commit the tree cannot take is refused, not relayed.** Its sender must be a member whose signature
  verifies, it must be for the room's group and epoch (`wrongEpoch` naming the room's otherwise), its proposals must
  apply to the tree, and a GroupInfo beside it (a Partial one rebuilt first, DIV-12) must describe the group after it. A refused Commit changes nothing
  and is logged with the room and the sender's provider. Relaying it and dropping the room's tracking instead would let
  one bad Commit switch the tree's checks off. The cost is that a tree the hub models wrong would stall the room; the
  operator's `untrackRoom` (on the loopback listener) drops the tree, and the room's next full bundle seeds it again.
  Proposals held for a member's leave are verified against the tree and queued in the group too, so the Commit that
  names them stages. The membership tag of a `PublicMessage` is not checked: it needs the epoch's secret, which a
  delivery service does not hold.

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
  a Commit; this hub accepts one change per Commit (below), so that case is refused
  rather than applied.
- A room-policy change is an AppDataUpdate for `roles_list` or `base_room_policy` (DIV-15); the policy it
  produces is validated (`RoomPolicy::validate`) before it is stored, the same as one set through the
  JSON-compat `roomPolicy` route.
- **Which changes one Commit may carry together** (`mimi_core::commit_wire::check_changes`). At most one change of each
  kind. A participant-list change and a `base_room_policy` change may share a Commit (room-policy-04 §5 sets no rule
  against it), as may `roles_list` and `base_room_policy`. A `roles_list` change beside a participant-list change is
  refused (room-policy-04 §3). `preauth_list` is not a change this hub reads. Still stricter than -07 §7.5: one
  participant-list update per Commit. Everything is decoded and checked before anything is written; the participant
  change is written first and the policy second, so only a store failure between the two writes could split them.
- **A Commit with `Add` and `Remove` beside the change is read.** A Commit may carry its changes in any order with any
  number of `Add` and `Remove` proposals (-07 §3.2: "Alice adds Bob to the Room"). Each `Add`
  is read by openmls's own KeyPackage decoder, which says where it ends, and its KeyPackage goes through the same gate as
  any other (the suite, the signature); one the gate refuses refuses the whole Commit, answered `notAllowed`. A `Remove` is
  a leaf index. When the Commit has either, §7.5 is checked against what it says, against the list the room holds now:
  every user the change adds has an `Add` for one of its clients; no `Add` is for a user who is neither listed nor added
  by the change; and a change that removes users has a `Remove` beside it. Otherwise the Commit is `invalidProposal` and
  nothing changes. Two limits stay: for an untracked room the hub holds no ratchet tree, so a `Remove` is a number and never a user (a `Remove`
  with no user removed from the list is read as one device leaving, and an `Add` for a listed user as a second device), and
  the credential-to-user binding is open, so for a `BasicCredential` the identity bytes are read as the user URI, and a
  credential of another type names no user (DIV-24). A Commit with the change alone is read as it always was, so a participant can be listed
  before any client is added. A Commit that carries a `GroupContextExtensions`, `Update`, `PreSharedKey`, `ReInit`,
  `ExternalInit`, `SelfRemove`, changes it may not carry together, or no change is still refused, whichever order it is
  in.
- **A member leaving (-07 §3.5).** A leaving client cannot remove its own devices, so it sends its proposals to the hub:
  an `update` whose bundle is proposals (`proposalOrCommit` and `moreProposals`) is a leave. The hub takes one
  participant-list change that only removes participants, with `Remove`s, all member-sent `PublicMessage`s, and holds
  them, each named by its `ProposalRef` (RFC 9420 §5.2, SHA-256 under 0x0001) and kept as sent. The change may arrive as
  the AppDataUpdate for `0x0022` or as `0xF7A0`. The next Commit at that epoch must include every held proposal by
  reference (RFC 9420 §12.4: a proposal from another member is included by reference). A reference to nothing held for
  the Commit's epoch, a reference named twice, or a held proposal left out is `invalidProposal`, with those
  `ProposalRef`s in `invalidProposals`; nothing changes. A held `Remove` joins the Commit's `Remove`s and the held change
  becomes one of its changes, and §7.5 is checked as above, so a committer's own participant-list change beside a held one
  is a second participant-list update and is refused.
  - **For an untracked room signatures are not verified, and what that costs is bounded by who may ask.** The hub holds
    no group state for it, so it verifies neither a proposal's signature nor its membership tag, as for a Commit (a
    tracked room's proposals are verified against its tree, above). A held proposal that the next
    Commit must include would otherwise let any peer have the hub require someone's removal from the participant list.
    So every user the change removes must be one whose provider the peer's mTLS certificate authenticates (no
    certificate, or another provider's user, is `notAllowed`): a provider can have the hub require the removal of its own
    users only. The hub does not check that the change removes the sender's own user rather than another user of the
    same provider, which that provider vouches for in any case. A `Remove` is a leaf index, and the hub holds no ratchet
    tree to tell whose leaf it is, so `Remove`s are not bound to a provider: -07 §3.5 has the leaving client propose the
    removal of every device of its user, itself included, and the hub takes them as sent. The room's bounds on what it
    holds and their expiry (below) bound what a leave can make the next Commit carry. Members verify each proposal
    before committing it, so one they cannot verify, or will not commit, holds the room's Commits at that epoch until it
    expires.
  - **Epoch, expiry and bounds.** The hub learns a room's epoch from the Commits it accepts: one past the latest, kept in
    the store with the room, so it survives a restart. A leave of another epoch is `wrongEpoch` naming the current one,
    so proposals sent again after their Commit are refused. A room the hub has not yet seen a Commit for (one founded
    before the hub learned its epoch) takes a leave at the leave's own epoch, which binds only a Commit at that epoch. A
    held proposal expires after 15 minutes, and an expired one is neither required nor resolvable. One message is at most
    4 KiB, and a room holds at most its participant bound plus one proposals and 64 KiB of them; past any of these the
    leave is `notAllowed` saying which, and nothing is held. The checks run in this order: what the messages are, that
    the peer presented a certificate, the epoch, whose provider the removed users are, then the bounds. So a leave
    replayed after its Commit is `wrongEpoch` whatever its indices name in the room now, any peer the transport trusts
    can learn the room's current epoch from that answer (an epoch every member's handshake messages carry), and only the
    provider of a participant a leave removes learns what the room holds. A Commit is checked the same way: one sent at
    another epoch than the room's (a replay of one already accepted, for instance) is `wrongEpoch` and changes nothing;
    the epoch it is sent in is also the one its references are read at.
  - Refused as a leave (`invalidProposal`, nothing held): a change that adds a participant or changes a role, a
    room-policy change, two changes, proposals of more than one epoch, or `Remove`s with no change (a Commit of
    `Remove`s alone is one this hub does not read, so holding those would hold the room). Held proposals are not fanned
    out: the hub sends no `/notify` (see Framing), so the committer learns of them from its own provider.
  - **Open: the peer of a Commit is not bound.** `update` takes a Commit from any peer the transport trusts, whatever
    room it names, as before, so a peer can send a Commit for a room it has no participant in; the leave is bound to the
    removed users' provider, the Commit is not. Binding the peer to a provider of the room on every `update` is the fix.
- **openmls and this path.** For a tracked room the hub processes each Commit with openmls's `PublicGroup` (with
  `extensions-draft`, so AppDataUpdates apply to the GroupContext), at the revision this crate pins. Group-processing
  fixes in later openmls revisions (external AppDataUpdate proposals, the order of AppDataUpdate before
  GroupContextExtensions, an `app_data_dictionary` kept in place on update) reach the hub only when the pin moves.
- **Framing.** The request body is the draft's `UpdateRequest { HandshakeBundle }` and the answer
  is an `UpdateRoomResponse` in a 200: `success` with the hub's acceptance time in milliseconds;
  `notAllowed` for a room this hub does not host, a bundle whose Welcome or GroupInfo is under
  another ciphersuite, or a store limit (the participant cap), with the same bytes for each, so a
  refusal does not say which of them applied; `notAllowed` with the reason in its description when
  the room's policy refuses the change (protocol-07 §5.3: "some type of policy or authorization prevented" it): a
  role the policy does not define, a role list or base policy that does not validate, a base policy before any roles,
  or a role list beside a participant-list change (room-policy-04 §3); `invalidProposal` for a body that is not an
  `UpdateRequest`, a bundle of proposals that is not a leave, an unrecognized proposal type, a proposal that does not
  decode, or an update that does not fit the room, with an empty `invalidProposals` list except where a
  Commit's references are at fault (above), which it names. The list stays empty for a proposal the Commit carries by
  value: `invalidProposals` lists `ProposalRef`s, and RFC 9420 §5.2 computes a `ProposalRef` only for a proposal sent
  as its own message, so an inline proposal has none to name. Protocol-07 §5.3 does not say what to answer then. `success` for a bundle of proposals
  means they are held for the next Commit. The hub checks that the room URI is under its own
  domain, not that the room exists, and answers `invalidProposal` or `success` for a room it
  hosts, so a peer on the allowlist can learn a room's participant count from those answers.
  `wrongEpoch` is answered to a leave, or a Commit, of another epoch than the one the hub learned
  from the room's latest accepted Commit (above). A leave past a bound is `notAllowed` saying which bound; it reaches
  that answer only from the provider of a participant it removes. A SQLite failure is a 500 with no body. The Welcome,
  `GroupInfoOption` and `RatchetTreeOption` of a Commit bundle are read and suite-gated; a Full GroupInfo and full tree
  seed an untracked room, and a Full GroupInfo is checked against a tracked room's group. None of them is relayed: `success` means the participant-list or room-policy change was
  applied, not that the Commit was distributed (§5.3's "will be distributed"). A body that is only
  the Commit, without the bundle around it, is refused.
- The four room-admin RPCs (`roomPolicy`/`memberRole`/`addParticipant`/`authorizeSender`) remain
  JSON-compat-lane only - `update` is the wire-lane mechanism for the two operations it
  carries (roster and policy changes); it is not a wire-framing of those four RPCs themselves.

Verified against a captured real `openmls` Commit, freshly re-encoded ones each test run, an
end-to-end participant-list apply, an end-to-end room-policy apply, and rejection cases for an
unrecognized proposal type and an undecodable body. The leave is verified end to end (held, then
included by reference), against openmls's own `ProposalRef` for a proposal it committed by reference,
one client leaving for two devices of its user, a room the hub saw no Commit for, the learned epoch
across a reopened store, and against each bound: another provider's user, no certificate, a wrong
epoch and a replay after the Commit, the count, size and byte bounds, and expiry.

## DIV-11 - CLOSED for `consent_extensions`; `update`'s fields stay opaque

`ConsentEntry.consent_extensions` (§5.7) is decoded into the real `draft-ietf-mls-extensions` §4.6
`AppDataDictionary` shape: a run of `ComponentData { uint16 component_id; opaque data<V>; }`
entries, sorted and unique by `component_id` (the draft's own MUST), wrapped in one outer
length-prefixed window. `id_request_extensions`/`id_response_extensions` (§5.8) and
`abuse_extensions` (§5.9, the same `AppDataDictionary` type) stay opaque length-prefixed blobs - the
decoder consumes these fields without interpreting or retaining their contents, since nothing here
produces or consumes those specific fields.
`update`'s `RatchetTreeOption` field (§5.3) also stays opaque, for the same reason as the rest
of `update`'s codec: no live accept-path exists yet. The wire vectors fill it with a real option
(see DIV-12), not filler bytes, so a decoder that reads it is not thrown by them. A `Full` `GroupInfoOption` is read raw and
suite-gated; a `Partial` one is read raw too (DIV-12).

## DIV-18 - the operational policy component: kept, two flags enforced

`mls_operational_policy` (`0x0024`, room-policy-04 §7.1, `OperationalParameters`) is read whole
(`mimi-core/src/operational_parameters.rs`) and kept per room whose tree the hub keeps: from the GroupContext when the
room is seeded, and from an AppDataUpdate in a Commit. Where -04 leaves a type undefined it is read as MLS defines the
name: `WireFormats` as a `WireFormat` (`uint16`), `ContentType` as MLS's (`uint8`), `ComponentID` as mls-extensions-10
has it (`uint16`), `MediaType` as its §6.2.2 struct, and `unit64` as `uint64`. `PendingProposalPolicy`'s `extension` arm
names no enum value, so only `unspecified`, `immediate_commit` and `random_delay` are read.

Enforced: `external_commit_allowed` (DIV-1). `external_proposal_allowed` can only narrow what the hub takes, since it
accepts no external proposal from a peer; it is kept and not otherwise acted on. Every other field is
kept and not enforced. A change to the component needs the proposer's role to hold `canChangeMlsOperationalPolicies`
(`0x0600`), which -04 lists as reserved: this hub reads it as the draft's own capability for the change, pending the
draft's answer, and a room with no roles has no role checks (room-policy PR #52: "A room that has no `roles_list` has no role-based restrictions.").

## DIV-12 - a `Partial` GroupInfo is rebuilt at the hub, its tree tried at each place in the list

§5.3 writes the `GroupInfoOption` payload raw: a `GroupInfo` for `full`, a `PartialGroupInfo`
for `partial`, each ending where its own structure ends, with `ratchetTreeOption` following. Both are written and read
that way here. A `Full` payload's end is found by decoding it as an openmls `VerifiableGroupInfo`, and it is
suite-gated at decode; a `Partial` payload's by decoding it with `mimi_core::partial_group_info`
(draft-ietf-mls-ratchet-tree-options §4), and it is not suite-gated, since it carries no ciphersuite.

A tracked room's Commit with a `Partial` GroupInfo is checked as one with a `Full` GroupInfo is: the hub rebuilds the
GroupInfo from its group after the Commit and checks its signature, signer and GroupContext. Two departures from the
draft's letter:

- The draft has a GroupInfo sent as a Partial put its `ratchet_tree` extension last. Implementations differ: openmls
  writes it first, before `external_pub`; mls-rs writes it after `external_pub`, and with its GREASE feature puts a
  GREASE extension after it, so the tree is neither first nor last. A Partial is the signed list with the tree taken
  out and the rest in order, so the hub puts its own tree after the Commit back at each place in that list (last, then
  first, then the places between), and the committer's signature decides which, if any, was signed. Each place
  is one GroupInfo built and one signature checked, made one at a time and stopped at the first that verifies, so a
  GroupInfo with the tree at either end costs what it did before. Past 16 extensions only the two ends are tried
  (`MAX_TREE_PLACES_EXTENSIONS`), so one Commit costs at most 17 checks. The work comes after the Commit itself has
  staged: only a member of the room, with a Commit for the current epoch, reaches it.
- `ratchet_tree_presence` says whether the GroupInfo before the Commit carried the tree, too (`removed`, `added`). The
  hub does not keep whether the last GroupInfo did, so it reads only whether this one does.

The protocol-07 wire vectors (`tests/vectors/protocol07-vectors.json`) are written so another implementation can decode
them: every `HandshakeBundle` carries a one-byte `RatchetTreeOption` naming `distributionService`
(draft-ietf-mls-ratchet-tree-options §3), and every `UpdateRequest` carries a `Full` GroupInfoOption with the committing
group's GroupInfo, except `hb-03-partial-group-info`, which carries the `PartialGroupInfo` of `hb-01`'s GroupInfo.

## DIV-13 - an exhausted client is answered with `partialSuccess`

When a user has no key material left (no unexpired one-time KeyPackage, and no last-resort one, which by default is
handed out once, DIV-23), the
`keyMaterial` response carries user status `partialSuccess` with one client entry whose status is
`keyMaterialExhausted`. §5.2 defines
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

The point is open as mimi-protocol issue 184, which names this choice and the reading of another
implementation, `noCompatibleMaterial` with the clients listed, and proposes either a user code of its
own or a wider `noCompatibleMaterial`. This crate reads that other form: a test holds
`noCompatibleMaterial` with every client `keyMaterialExhausted` (one client, or several) and checks it
is read and written back unchanged. The hub still sends `partialSuccess`, until the issue is settled.

## DIV-15 - three room-policy components are read; the other ten are refused

`update` reads a participant-list change from either of two carriers: an AppDataUpdate
(mls-extensions-10 §4.7, proposal type `0x0008` as its §7.2.1 suggests) addressed to
component `0x0022` (`participant_list`, protocol-07 §10.3), or the custom proposal of the
private type `0xF7A0` (`mimiParticipantList`). Both carry the draft's `ParticipantListUpdate`
encoding and are applied the same way. `0xF7A0` is a compatibility carrier for clients that do not
yet send the change as an AppDataUpdate, and is to be removed once they do. The openmls release this crate pins (0.9.2) is built
without its `extensions-draft` feature and cannot read an AppDataUpdate, so `commit_wire` reads
the proposals window itself and rewrites an AppDataUpdate to the `0xF7A0` form for reading only; the
bytes of the Commit are never changed. A fanned-out Commit or proposal reaching `/notify` is refused before it is read
(see below).

Protocol-07 §5.3 sends a room-policy change as an AppDataUpdate for the room policy components of
room-policy-04, with values `0x0024` to `0x0030` suggested and not yet registered. This hub reads two:

- `roles_list` (`0x0025`, §3): the `update` is a `RoleData`, and it replaces the room's roles.
- `base_room_policy` (`0x0027`, §5): the `update` is a `BaseRoomPolicy`, and it replaces the room's base policy.

They are read the way the participant-list update is, as the private types `0xF7A3` and `0xF7A4`
while the message is being read. The private JSON carrier `0xF7A1` that earlier versions read is
gone. A base policy applies to roles, so a base update for a room that has no roles is refused until a
role list has been sent; room-policy-04 has no such rule. Room-policy PR
[#52](https://github.com/ietf-wg-mimi/mimi-room-policy/pull/52), still open, makes it the opposite rule: "An update to
the `base_room_policy` component is valid in a room that has no `roles_list`", and such a room "has no role-based
restrictions". If it merges, this hub takes a base policy before any role list and applies no role rule until a role
list arrives; the reason that follows would no longer hold. This hub keeps base and roles as one policy and, once a room
has a policy, enforces `canSendMessage` by role, so a base policy with no roles would leave nobody able to send. A role
list sent first sets the roles and leaves the base policy at the draft's defaults. A role list whose index 1 is not
named `banned` is refused: room-policy-04 says the banned role "always has role_index = 1 and role_name = banned" and
that it "does not have to exist", and this hub reads that as fixing the name of whatever role holds index 1.

What the hub keeps of them: of a role, its index, its name, its `authorized_role_changes`, and the capabilities
`canAddParticipant` (`0x0000`), `canRemoveParticipant` (`0x0001`), `canAddOwnClient` (`0x0002`), `canOpenJoin`
(`0x0004`), `canRemoveSelf` (`0x0006`), `canBan` (`0x000a`), `canKick` (`0x000c`), `canChangeUserRole` (`0x000f`),
`canSendMessage` (`0x0100`), `canChangeRoomMembershipStyle` (`0x0502`), `canChangeRoleDefinitions` (`0x0503`) and
`canChangeMlsOperationalPolicies` (`0x0600`, DIV-18). On every Commit, each role a
participant-list change puts a user in must be one the room's policy defines (or 0, out of the room), so a ban into
role 1 is refused while the list does not define role 1. A room with no policy is not checked at all.

**Who may change the room's policy**, on a tracked room: a change to the `roles_list` needs the proposer's role to hold
`canChangeRoleDefinitions` (`0x0503`), to the `base_room_policy` `canChangeRoomMembershipStyle` (`0x0502`), and to the
operational policy `canChangeMlsOperationalPolicies` (`0x0600`, DIV-18) (room-policy-04 §8.6). These changes arrive by
value, so the proposer is the committer. A room with no roles has no role checks, and its first `roles_list` by Commit
is refused (room-policy PR #52: "A Commit that adds a `roles_list` to a group that has none is invalid.", below). On an untracked room the proposer is not known: by default such a change is taken only in the Commit that gives the hub the tree, and authorized there (DIV-10); on `untracked_rooms = "accept"` none of this is checked.

**Who made a change is checked for a tracked room only** (one whose ratchet tree the hub keeps, DIV-10). There the
sender's leaf maps to a member, and room-policy-04 §8.1 authorizes each change for its proposer: the committer for a
change the Commit carries by value, and the proposal's own sender for a change held by reference (a leave). The
proposer must be listed, and its role is the one the room's list gives it, as the list and policy stand before the
Commit. A change to another user needs the capability its transition needs (`canAddParticipant` from 0,
`canRemoveParticipant` to 0, `canBan` to 1, `canChangeUserRole` otherwise) and an entry in the proposer's own
`authorized_role_changes`. Those capabilities exclude the holder itself, so a proposer's own leaving needs
`canRemoveSelf` and an entry from its role to 0. Any other change to the proposer's own role is `canChangeOwnRole`,
which works through the Preauthorized users component this hub does not read yet: such a change is refused until that
is built. In a tracked room a Remove with no participant-list change is checked against the tree: it removes the
proposer's own client (`canRemoveOwnClient`) or is a kick (`canKick`), and no client's new leaf names another user
(`mimihubd/src/list_leaves.rs`). Not checked yet: the participant-count constraints, and `canAddOwnClient` outside an
external Commit. An untracked room's Commit sender is a leaf index the hub cannot map to
a member: by default its changes that need a proposer are taken only in the Commit that gives the hub the tree, whose
committer is the GroupInfo's signer (DIV-10); on `untracked_rooms = "accept"` none of this is checked.

A tracked room's policy and list are its group's. When the room is seeded, the GroupContext's `roles_list`,
`base_room_policy` and `participant_list` replace what the hub stored (a GroupContext with no `roles_list` leaves the
room with no policy), every participant it lists must be in the tree, and every client in the tree must be a client of
a participant it lists. Room-policy PR
[#52](https://github.com/ietf-wg-mimi/mimi-room-policy/pull/52), still open, sets a `roles_list` when the MLS group is
created, in its change "Set the roles_list at group creation" (its title and description name only its other change,
the `base_room_policy` one in DIV-15): a Commit that adds a `roles_list` to a group that has none is invalid, and a room with no `roles_list` has no
role-based restrictions. Room-policy-04 as written does not say whether a first `roles_list` may arrive by Commit;
this reading is the PR's, not -04's. The hub follows it for tracked rooms and refuses such a Commit; an untracked room
takes its first role list by Commit only on `untracked_rooms = "accept"`. The operator's `roomPolicy`, `memberRole` and `addParticipant` answer 409 for
a tracked room.
`canSendMessage` is enforced where the hub sees the sender, on `submitMessage`, by the sender's role (§8.3). The other capability values (uploads, calls, room attributes
and the rest of the registry, which is open to additions) are read for their shape and not carried, so a
role that lists them is accepted. The description and the four participant-count constraints are
read and not kept. Of a base policy: `fixed_membership`, `parent_dependant`, `max_clients`,
`max_users` and `discoverable`; the rest is read and not kept. **Kept is not enforced for the membership limits:** a
Commit that grows a `fixed_membership` room, or takes a room past `max_clients` or `max_users`, is not refused; the
hub checks only that a fixed-membership room's roles hold no `canAddParticipant` (room-policy-04 §5). A value is refused when it does not end
where its length says, when a length or a count passes a bound (256 roles, 512 capabilities, 1 KiB of
text), when a flag is neither 0 nor 1, when a role index repeats, when a minimum participant count is
above its maximum, when a parent-dependent room names no parent or any other names one, or when the
resulting policy does not validate (the reserved roles 0 and 1, a transition that names an undefined
role, a fixed-membership room whose role may add participants).

`room_metadata` (`0x0023`, protocol-07 §10.4) is read and kept: a `RoomMetaData` that decodes within bounds (16 KiB
in all, 1 KiB a text, 4 KiB a description, 16 descriptions, UTF-8 without NUL, an `https` avatar or none) and names
this room is stored as sent, replacing the last one, alone or beside the changes above. It is display data and the hub
enforces nothing from it; who may change it is not checked, since no capability for it is kept. The `room_metadata` a
GroupContext carries when the room is seeded is held to the same rule: a seed whose `RoomMetaData` does not decode
within those bounds, or names another room, is refused like a seed with a bad `roles_list`. A seed that passes keeps
it as the room's metadata, as sent, and a GroupContext with none leaves the room with none.

`mls_operational_policy` (`0x0024`) is read and kept (DIV-18). The other ten components are refused as an unrecognized
proposal type, as are a removal of any component and an AppSync proposal, so a sender is told
the change was not applied and never that it was: `preauth_list`
(`0x0026`), `status_notification_policy` (`0x0028`), `join_link_policy` (`0x0029`), `join_links`
(`0x002a`), `link_preview_policy` (`0x002b`), `asset_policy` (`0x002c`), `logging_policy` (`0x002d`),
`chat_history_policy` (`0x002e`), `bot_policy` (`0x002f`) and `message_expiration_policy` (`0x0030`).
They govern what clients and the operator do and are not state this hub enforces.

Where room-policy-04 leaves a rule open, this is what the hub does. The issues are in
`ietf-wg-mimi/mimi-room-policy`.

- [#33](https://github.com/ietf-wg-mimi/mimi-room-policy/issues/33), rules for a valid role list: a repeated
  `role_index`, a transition that names a role outside the list, and a minimum above its maximum are refused.
  A list may name role 1, the banned role, without defining it: it "does not have to exist"
  ([#51](https://github.com/ietf-wg-mimi/mimi-room-policy/pull/51)). Banning into it needs it defined ("to use the
  canBan and canUnban capabilities, a role with role_index = 1 needs to exist"), so a ban into an undefined role 1,
  or any change into a role the list does not define, is refused while the list itself is accepted. A capability listed twice counts once. Two `authorized_role_changes`
  entries with the same `from_role_index` are both honoured: a change is authorized when any entry permits it.
- [#31](https://github.com/ietf-wg-mimi/mimi-room-policy/issues/31), when role constraints are checked: the four
  participant-count constraints are read and not kept, so the hub enforces them at no point in a commit.
- [#37](https://github.com/ietf-wg-mimi/mimi-room-policy/issues/37),
  [#40](https://github.com/ietf-wg-mimi/mimi-room-policy/issues/40) and
  [#41](https://github.com/ietf-wg-mimi/mimi-room-policy/issues/41), fixed-membership and parent-dependent
  rooms: a fixed-membership room refuses a role that holds `canAddParticipant`, as §5 says, and accepts a role
  that holds a removal capability. `parent_dependant` is kept as a flag; the parent is not followed, no subset
  rule is checked, and the hub does not limit a participant set to one fixed-membership room.
- [#28](https://github.com/ietf-wg-mimi/mimi-room-policy/issues/28),
  [#29](https://github.com/ietf-wg-mimi/mimi-room-policy/issues/29),
  [#32](https://github.com/ietf-wg-mimi/mimi-room-policy/issues/32),
  [#35](https://github.com/ietf-wg-mimi/mimi-room-policy/issues/35),
  [#36](https://github.com/ietf-wg-mimi/mimi-room-policy/issues/36),
  [#38](https://github.com/ietf-wg-mimi/mimi-room-policy/issues/38) and
  [#46](https://github.com/ietf-wg-mimi/mimi-room-policy/issues/46) concern `preauth_list`, the operational
  policy and the logging policy, which the hub does not read.

A roles update that drops a role some member still holds leaves that member with an index the policy
does not define; the hub treats an undefined role as unable to do anything, so the member cannot send
until a role list that defines the index is sent. The hub does not check the sender of an update against
the room's roles (see the room-admin principal in the README), as for the participant list.

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

What a `/notify` delivers: a Welcome is queued for each local user whose published KeyPackage it names (this provider
records each KeyPackage's `KeyPackageRef` when it is published, so the recipient comes from its own map and never from
the peer), and makes that user a member of the room here. Anything else (an application message, a Commit, a
proposal) is queued for the room's members here (DIV-5). For a room with no member here it is refused with `404` and
the RFC 9457 problem `no-local-member` ([docs/problems.md](docs/problems.md#no-local-member)) rather than answered 201
and delivered to nobody, and the sender should drop the delivery rather than retry it. The refusal is decided before
the dedup ledger records the body, so a resend of a refused message is refused again; §5.5's "MUST return 201" for a
duplicate covers a duplicate of what was accepted. The JSON compatibility lane `/mimi/v1/notify` still records any body it is sent and
answers 201; it delivers nothing.

- **What this does not bind.** The check says which names a certificate carries. It does not say
  which names the CA that signed it may issue. Every CA in the client bundle can issue a certificate
  for any provider domain, so trusting a CA means trusting it to name any provider, and a peer with a
  certificate from such a CA passes the `/notify` check for any room. Binding a CA to its names would
  take a name constraint per CA (an X.509 name-constraints extension on the CA certificate, or a
  configured list of allowed domains for each CA in the bundle, enforced when the chain is built).
  This hub has neither; a deployment that trusts an outside CA is trusting it with every domain.
- **`From`.** §4.1 says a request MUST identify its source provider in a `From` header (`mimi@<provider domain>`),
  and the draft's own note asks whether `From` is the right field. This hub requires it on every peer request but the
  directory, whatever the proof: a signature covers it (draft-atwood-mimi-provider-auth §5), and a certificate must
  carry the domain it names. A request with no `From`, one not of that form, or one naming a domain its proof does not
  authenticate is refused (403). That follows the direction Mark gave for provider-auth -01 (what the proof binds to
  cannot be optional); if the WG moves the source provider to another field, the check moves with it. The `Host`
  header, which names the target provider, is not compared with this hub's domain.
- **Signatures and nonces.** The hub signs every request it sends with its provider's DNS-published key when one is
  configured (`MIMI_SIGNING_KEY`, `MIMI_SIGNING_SELECTOR`), as mimid does: `@method`, `@target-uri`, `content-digest`
  (sent on every request) and `from`, with `created`, a random `nonce`, `keyid` and `tag="mimi"`. A client certificate
  is then presented only when `MIMI_CLIENT_CERT` names one. Of a signature it receives, it remembers the nonce for the
  signature's window and refuses a second use by the same key (provider-auth §13.2, as Mark described it for -01: a
  replayed keyMaterial request takes another KeyPackage). The ledger is in memory, as mimid's is, so a restart forgets
  at most one window. A signed keyMaterial request with no nonce is accepted by default, since -00 has no nonce; the
  policy setting `require_nonce_on_key_material` refuses it.
- **The operator's routes.** `roomPolicy`, `memberRole` and `addParticipant` set a room's policy, roles and
  participants. They are not MIMI routes, and no peer reaches them: they are served only on a listener bound to a
  loopback address (`MIMI_ADMIN_BIND_ADDR`; the hub does not start with any other address), with no client
  certificate, so the caller is whoever can reach that address on the hub's host, the same person who can run
  `mimihubd enroll` or open the hub's store. Unset, there is no such listener. That listener is safe without a
  credential only while nothing a peer sends can make the hub connect to it: every request the hub sends is https and
  goes only to an address its outbound client checked, which refuses loopback unless the operator allowlists it, and
  this plain-HTTP listener does not answer TLS.
- **`authorizeSender`.** It changes nothing. It checks that the caller completed the handshake and that the room is one
  this hub hosts, and nothing about who the caller is; any certificate in the client CA bundle can ask it, which is
  part of what trusting a CA means. The hub prints the fingerprint of each CA in the bundle at startup, so the list can
  be read and compared.
- **`submitMessage`, `update` and the rest.** Only `/notify` is bound to the room's hub. A peer that
  passes mTLS is not otherwise tied to the provider domain in its certificate on the other routes,
  as DIV-6 says for the identities inside a request body.

## DIV-17 - content-10: what `mimi-core` reads and writes against content-09 peers

The content codec follows draft-ietf-mimi-content-10. Its examples are the instance documents already held for -09: the
draft's text caught up with them (the reaction's heart is U+2764 and its in-reply-to ID is the one in the table), so there
is no new vector to add and every one still reads and writes byte for byte.

- **URLs.** `url` in an external part is written as an untagged text string (-10 `url: tstr`). A -09 peer's CDDL said
  `uri`, which is tag 32 over text; the reader takes both and writes the untagged form, so a -09 peer that re-reads our
  document gets a text string where its own CDDL names a URI. Any other tag, or tag 32 over a non-text value, is refused.
- **Extension values.** There is no 4095-byte limit on a `mimiExtensions` value (it is gone from the CDDL); the codec never
  enforced one, and a test now reads a 5000-byte value.
- **`senderUri` and `roomUri` extensions.** `validate_extension_uris` refuses a document whose extension 1 or 2 does not
  match the URI the enclosing protocol gave. It takes both URIs as arguments: the caller (the MLS layer) owns them, so
  the codec's `from_content08_cbor` does not call it.
- **Indefinite-length CBOR.** `from_content08_cbor` first walks the document by its heads and refuses any indefinite-length
  string, array or map, or break byte, before a general decoder sees it.
- **`contentHash`.** `external_content_hash_matches` hashes the bytes as stored (the ciphertext when `encAlg` is not zero)
  under the part's `hashAlg`; only SHA-256 (1) is computed here, and any other value is an error, never a match.
- **Thread order.** `sort_thread` prefers the hub accepted timestamp where the receiver has it, else the sender's, and
  breaks a tie by the lowest message ID.
- **Not built.** The three `MsgUri` fields of `MessageDerivedValues` (`senderClientUrl`, `senderUserUrl`, `roomUrl`) have no
  type in this crate, so there is nothing to change for them.

---

Divergences are revisited as the drafts move and as the accept-path work (DIV-6, DIV-9, DIV-10)
lands. DIV-1 through DIV-4 do not block interoperating with another provider on the supported
surface. DIV-5, DIV-7, and DIV-11 are closed or mostly closed (see above); DIV-6, DIV-8, DIV-9,
DIV-10, DIV-13, DIV-15, and DIV-16 still do, for the endpoints they touch, until closed.

## DIV-19 - the client lane is a local extension

MIMI specifies provider-to-provider traffic and leaves how a provider's own clients reach it to the provider. This hub
serves one such path, the client lane (`mimihubd/README.md`, "The client lane"), on its own listener, for a provider
whose client-facing service authenticates its users and signs each request for one of them. Nothing on it is a MIMI
route or changes one: rooms, Commits, proposals and application messages it carries go through the same checks as on
the provider path, with the user as the requester. A peer cannot reach it, and the operator's routes stay on their own
loopback listener.

A Welcome the lane hands its user names the room it joins (`inboxFetch`'s `room`), as the hub queued it: the room it fanned the Welcome out for, or the room a hub's `notify` named. A Welcome alone does not say which room it is for, and protocol-07 leaves how a provider hands one to its own client open. A Welcome relayed through the JSON compatibility lane (`POST /mimi/v1/welcome/ingest?recipient=`) names no room, so it is queued without one and its item carries no `room`; that route is not for the lane's clients, and a lane client that needs the room to know what it joins can refuse such a Welcome. Welcomes queued before the hub kept rooms read back the same way.

For a room on another hub, the lane sends the user's message, update or keyMaterial request to that hub as this
provider (protocol-07 §3.4, §5.2). The hosting hub judges it as it judges any peer's request, against the room it
holds; it can tell that the request comes from a user of this provider, not which one. This hub vouches for that: a
relayed message names the lane user as its sender, and a keyMaterial request must name the lane user as requester, under
the lane user's credential, with a signature that verifies. A relayed Commit or leave carries the MLS signatures that
bind it to its sender's leaf, which the hosting hub and the room's members check; this hub holds neither the room's list
nor its tree (DIV-5), so it does not check what a relayed update changes.

The lane's consent routes (`consent`, `requestConsent`, `consentRequests`, `consentReceived`, `optOut`) let a user of
this provider make the decisions §8 leaves to the target user, and only that user makes them: a decision gating a user's
KeyPackages is recorded only from that user's lane, never from a peer (`updateConsent` is taken only for a requester of
this provider). A decision's scope is §8's `ConsentScope`, one requesting user and optionally one room. What the draft
leaves to the provider is a policy setting: deciding for every user of a provider (`consent_provider_grants`, off; a
provider grant is read against the requester URI's domain, which any peer naming a room on its own domain can choose
(DIV-6), so on it admits any authenticated peer, and it is for a deployment where every peer is trusted), telling the
requester of a revoke (`consent_revoke_notifies`, off: "typically not communicated"), keeping decisions when a user opts
out (`consent_kept_at_opt_out`, off), and how long a request stays pending (`consent_request_days`, 30).

How the lane hands a user what the hub holds for them is the provider's choice too, and the lane offers two (`mimihubd/README.md`, "Delivering to your server: push or pull"). Per-user inboxes, the default, are read with `inboxFetch` and `inboxAck`. The provider event stream is one sequence of Welcomes, room messages and consent changes for every user of the provider, each with a `seq`. The provider's server reads it by pull (`events/wait`, `events/fetch`, `events/ack`, signed for the provider rather than a user) or has the hub push it to the server's URL. Push and pull carry the same events in the same order and share one cursor, and the hub's tests play one scenario through both and require the same events from each. Neither is a MIMI route: protocol-07 has a hub notify another provider's hub, and leaves how a provider's own server receives what is for its users to that provider.

A known gap in the hub's framing check. In a room whose ratchet tree the hub keeps, `submitMessage` refuses a message
whose MLS framing names another group, or an epoch the room has not reached. A room whose tree the hub does not keep
has no group to compare with, so its messages are not checked: a lane room is such a room from `createRoom` until its
creator's first Commit seeds the tree. In that window a participant could submit bytes framed for another group, and a
member who routes by group id would read them as that group's. Recording the group a room is created for would close
it; the hub does not do that yet.

## DIV-21 - several participant-list updates in one Commit: the order their additions are appended in

protocol-07 §7.5 says every `ParticipantListUpdate` in a Commit indexes the list as it stood before the Commit ("This
holds even when a commit contains more than one ParticipantListUpdate. Removing one entry does not shift the indices of
the other removals."), and that a Commit whose updates touch one user twice is not valid. It does not say in which order
two updates' added participants are appended. This hub, and `mimi_core::participant_list::merge_updates`, which a client
of this repository uses too, append them in the order the Commit's AppDataUpdate proposals for the participant list
come in, the order draft-ietf-mls-extensions §4.7 hands a component's updates to the application. A client that appends
them in another order computes another list, and so a GroupContext that differs from the Commit's.

## DIV-22 - the neutral lane profile's admins cannot leave; a deployment's profile may let them

room-policy-04 §8.1.2 authorizes `canRemoveSelf` by the holder's role's `authorized_role_changes` "entry where
from_role_index matches its current role", whose targets contain zero, and `canRemoveParticipant` by the entry whose
from_role_index matches the removed user's role. Both read the same entry, so a role that may leave from role 2 may also
remove other holders of role 2 when it holds `canRemoveParticipant`. The neutral profile (`client_lane_rooms.rs`) lets a
member leave (role 3 has an entry 3 → 0 and no `canRemoveParticipant`) and does not give the admin role an entry 2 → 0,
so under it an admin cannot remove another admin and cannot leave either: an admin leaves by first being changed to a
member by another admin (the entry 2 → 3), and the room's last admin cannot. A deployment whose admins should leave
writes the entry 2 → 0 in its own profile (`MIMI_LANE_ROOM_POLICY`), and with it its admins may also remove one another,
as §8.1.2 reads; the neutral profile keeps the narrower rule as its default.

## DIV-23 - with `MIMI_LAST_RESORT_REUSE=true`, a last-resort KeyPackage is handed out more than once

protocol-07 §5.2 says of the key material a `keyMaterial` request claims: "The keying material is designed for use in a
single room and may not be reused", and, normatively, "Keying material provided from one response MUST NOT be provided in
any other response." By default this hub follows it: a last-resort KeyPackage is handed out once and deleted, like any
other. A deployment may set `MIMI_LAST_RESORT_REUSE=true` (off by default), and then the hub hands a user's last-resort
KeyPackage out more than once, so two `keyMaterial` responses, for two rooms or two requesters, carry the same
KeyPackage. That breaks §5.2's MUST NOT, which makes no exception for a last-resort KeyPackage; the setting is a
deployment's choice of RFC 9420 §16.8's MAY over it.

What reuse rests on. RFC 9420 §16.8: "KeyPackages are intended to be used only once", and "An application MAY allow
for reuse of a 'last resort' KeyPackage in order to prevent denial-of-service attacks. Since a KeyPackage is needed to
add a client to a new group, an attacker could prevent a client from being added to new groups by exhausting all
available KeyPackages." draft-ietf-mls-extensions-10 §6.4 gives the marker RFC 9420 lacks, the
`last_resort_key_package` component, "to specifically mark KeyPackages as KeyPackages of last resort that MAY be used
more than once in scenarios where all other KeyPackages have already been used". The hub reuses only a KeyPackage its
client marked so: it reads the mark when the KeyPackage is published (openmls `KeyPackage::last_resort`, which
recognizes the component and the obsolete `last_resort` extension `0x000a`), and every other KeyPackage is handed out
once and deleted, whatever the setting. The trade-off is reachability: with reuse off, a user whose one-time
KeyPackages are spent, and whose last-resort one has been handed out, cannot be added to a room until its client
publishes more.

What the hub does with a last-resort KeyPackage, either way:

- **Served last.** A claim takes the oldest unexpired one-time KeyPackage that meets it, and the last-resort one only
  when none does. It answers `success` with it, like any other; a requester that wants to know reads the mark in the
  KeyPackage itself, as extensions-10 §6.4 has a client processing the Add do.
- **One per user.** Publishing a new last-resort KeyPackage replaces the old one. A user's one-time and last-resort
  KeyPackages share the per-user cap of 64; the cap evicts the oldest one-time KeyPackages and never the last-resort
  one. An expired last-resort KeyPackage is not served.
- **The client can see it.** The client lane's `keyPackageCount` says how many one-time KeyPackages are left and
  whether a last-resort one is, so a client knows when to publish more.

With reuse on, a claimed last-resort KeyPackage stays stored to be handed out again, and its `KeyPackageRef` stays
mapped to its user, so every Welcome sent for it reaches the user (protocol-07 §5.2's association of the ref with the
target client is kept, not deleted after the first Welcome). With it off, the KeyPackage is deleted when it is claimed,
and the ref still routes the one Welcome sent for it.

Limits of reuse. It is what RFC 9420 §16.8 warns "can lead to replay attacks": every group that adds the user through
the last-resort KeyPackage encrypts its Welcome to the same init key, and the client holds that private key until it
replaces the KeyPackage. The hub narrows how often that happens; it does not remove it. §16.8 also has the publication
system "rate-limit KeyPackage requests, especially if not authenticated". Every `keyMaterial` request from a peer or a
client is authenticated (the peer's proof on the provider path, the user's signature on the client lane) and passes the
consent gate. The client lane takes at most 5 requests an hour from one user for one target user, and 30 a minute from
one user (429 `client-rate-limited`). The provider path takes at most 5 an hour per requesting provider and target user,
the provider being the domain the peer proved (429 `key-material-rate-limited`). The requester a request names is not
counted: a peer can name any requester by naming a room on its own domain (DIV-6), so a count on it would let one peer
spend the budget of another provider's users. A refused request is not counted. The operator's loopback route that serves a KeyPackage (DIV-16, "The operator's
routes") is the operator's, and is neither gated nor limited.

## DIV-24 - a member's user is read from the credential types this hub supports; any other names no user

RFC 9420 leaves which identifiers a credential presents for a member to the application ("The application using MLS
is responsible for specifying which identifiers it finds acceptable for each member in a group", §5.3.1), and MIMI has
not settled how a credential names a user. The hub needs the user of each member's leaf: to check a Commit's
participant-list change against the clients it adds and removes (protocol-07 §7.5), to bind a published KeyPackage to
the user it is published for, and to know which provider a client belongs to. It reads two credential types:

- **Basic**: the identity bytes are the user's URI.
- **`did_webvh`** (draft-atwood-mls-didwebvh-credential): the credential's log is verified, offline, by the
  reference implementation's `mls-didwebvh` crate, and must authorize the leaf's signature key (§Binding to the
  LeafNode). The user is the one entry of the head DID document's `alsoKnownAs` whose scheme is `mimi`, in any case;
  none, or more than one, names no user. This reading is the reference implementation's (its `mimi_user_uri`), kept
  exactly so a hub and the members using it bind the same leaf to the same user; the draft itself makes the log's SCID
  the credential's identity and says nothing of a MIMI URI. The DID's own domain is not compared with the URI's
  provider: the draft lets a portable DID move ("The DID string can change if the controller moves the DID, but the
  SCID cannot"), and "a moved DID lists its previous DID in `alsoKnownAs`", which the log verification checks.

  The draft's code points contradict each other until IANA assigns them. Its IANA table asks for "TBD1 (suggested value
  0x0008)" for the credential type, and the next paragraph says "Until IANA assigns a value, implementations use the
  suggested value 0xF013"; 0xF013 is also the suggested value of the `did_webvh_heads` component. The hub reads the
  credential type 0x0008 and the component 0xF013, the `mls-didwebvh` crate's defaults and the values the reference
  implementation uses, so that the implementations that run agree.

  Not built yet: the draft's Group Consistency Rules (the `did_webvh_heads` record, Expected Heads, Authorization).
  Until they are, the hub orders a room of `did_webvh` members by its participant list alone, as it does for Basic
  ones; the members' own clients check the rules.

A credential of any other type names no user, whatever its content: it is never read as if it were one of these. Where the hub must know the user (a published KeyPackage, a client a
Commit adds, an external Commit's joiner, a renewed leaf), it is refused; a published KeyPackage is answered
`credential-not-supported`. A renewed leaf's new credential must be "valid as a successor" to the old one "according to the
application's policy" (RFC 9420 §5.3.1); for a Basic credential the hub's policy is exactly the same identity bytes, and for a `did_webvh` credential the same
SCID with the old log a prefix of the new (the draft's §Successor Credentials) and the same `mimi:` URI. All of this is read in one module, `mimihubd/src/credential.rs`, so
a further credential type is added there.
