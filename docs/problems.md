# Problem types

mimihubd answers some refusals with an [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) problem body
(`Content-Type: application/problem+json`). Each problem type below is named by its URI: this page, with the type as
its anchor. A problem body names the condition only. It never names a user, a client or a room.

Every refusal mimihubd answers with an HTTP error status (4xx or 5xx) carries one, on each of its listeners. Answers
that are a protocol structure in a 2xx (`update`'s `notAllowed`, `groupInfo`'s `notAuthorized`, `keyMaterial`'s
`noConsent`) are not HTTP errors and keep their protocol form. As mimi-protocol PR #211 asks, a client acts on the
`type` and shows neither `title` nor `detail` to a user.

Why each refusal is given, and the sentence of the specification it rests on, is in [`reasons.toml`](reasons.toml):
one row per problem type, per refusal a protocol answer carries, and per MLS check a client in a room reports.

## no-local-member

| field | value |
|---|---|
| `type` | `https://github.com/havenmessenger/interop/blob/main/docs/problems.md#no-local-member` |
| `title` | Not delivered: no member of the room here |
| `status` | 404 |

The answer to a `notify` (protocol-07 §5.5) that carries a Commit, proposals or an application message for a room
hosted on another hub when no user of this provider is a member of that room. A user becomes a member when the room's
hub sends this provider a Welcome naming one of the user's KeyPackages. The message is not recorded, so the same
`notify` sent again gets the same answer; the sender should drop the delivery rather than retry it.

Answered 201 instead:
- a `notify` that carries a Welcome: it is queued for each user of this provider it names, who then is a member;
- a message for a room with a member here: it is queued for each member;
- a duplicate of a `notify` already accepted from the same hub, as §5.5 requires, or the same message in another body.

## malformed-request

| field | value |
|---|---|
| `type` | `https://github.com/havenmessenger/interop/blob/main/docs/problems.md#malformed-request` |
| `title` | The request could not be read |
| `status` | 400 |

Any endpoint, for a body, path or query it cannot read: a wire body that does not decode as the endpoint's request, a JSON body that is not JSON, a query parameter missing, a path segment that is not a room URI, or a room this hub does not host where the endpoint needs one it does. Also what axum answers with 400 for a request it rejects before a handler runs. Fix the request; sending it again unchanged gets the same answer.

## material-not-accepted

| field | value |
|---|---|
| `type` | `https://github.com/havenmessenger/interop/blob/main/docs/problems.md#material-not-accepted` |
| `title` | The KeyPackage or Welcome is not accepted |
| `status` | 400 |

`keyMaterial/ingest` and `welcome/ingest`: the KeyPackage or Welcome does not decode, is under a ciphersuite this hub does not accept, or fails the gate's other checks. Nothing is stored. Do not retry the same bytes.

## message-not-queued

| field | value |
|---|---|
| `type` | `https://github.com/havenmessenger/interop/blob/main/docs/problems.md#message-not-queued` |
| `title` | The message was not queued |
| `status` | 400 |

The JSON lane's `submitMessage`: the store's bounds refuse the message (empty, too large, a recipient it does not keep a queue for, or a full queue). A full queue may drain; anything else is the same on retry.

## client-not-authenticated

| field | value |
|---|---|
| `type` | `https://github.com/havenmessenger/interop/blob/main/docs/problems.md#client-not-authenticated` |
| `title` | The client lane request is not authenticated |
| `status` | 401 |

The client lane's gate: no lane signature, one that does not verify with a key in the lane's key file, a missing or
reused nonce, a signature older than 30 seconds or made before the hub started, or a `mimi-client-user` that is not a
user of this provider. The hub logs which; the body does not say. Only the provider's own client-facing service can
retry, with a fresh signature.

## client-rate-limited

| field | value |
|---|---|
| `type` | `https://github.com/havenmessenger/interop/blob/main/docs/problems.md#client-rate-limited` |
| `title` | Too many client lane requests for this user |
| `status` | 429 |

The client lane takes a bounded number of requests per user per minute, a backstop to the client-facing service's own
limits. Retry after a minute.

## delivery-mode

| field | value |
|---|---|
| `type` | `https://github.com/havenmessenger/interop/blob/main/docs/problems.md#delivery-mode` |
| `title` | This hub delivers the other way |
| `status` | 409 |

The hub's operator chose how the client lane delivers: per-user inboxes (`inboxFetch`, `inboxAck`) or the provider event
stream (`events/wait`, `events/fetch`, `events/ack`, or push). The call belongs to the mode the hub is not in. The
lane's `info` call says which mode it is in.

## ack-past-end

| field | value |
|---|---|
| `type` | `https://github.com/havenmessenger/interop/blob/main/docs/problems.md#ack-past-end` |
| `title` | The acknowledgement is past the last event |
| `status` | 400 |

An `events/ack` named a `seq` later than the last event the hub has written. Nothing was acknowledged: an
acknowledgement can only cover events that exist, so it can never skip one written later.

## group-mismatch

| field | value |
|---|---|
| `type` | `https://github.com/havenmessenger/interop/blob/main/docs/problems.md#group-mismatch` |
| `title` | The message is framed for another group |
| `status` | 400 |

A `submitMessage` for a room whose tree the hub keeps carried an MLS message whose cleartext framing names a group other
than the room's, or an epoch the room has not reached. Members route a message to a chat by its group id and read a
later epoch as a missed Commit, so such a message is delivered to no one. A message from an earlier epoch is taken.

## not-an-application-message

| field | value |
|---|---|
| `type` | `https://github.com/havenmessenger/interop/blob/main/docs/problems.md#not-an-application-message` |
| `title` | Not an application message |
| `status` | 400 |

A `submitMessage` carried something other than an application message as RFC 9420 §6 has one: an MLSMessage carrying a
PrivateMessage whose content type is `application`. A PublicMessage, a Commit, a proposal, or bytes that are no MLS
message are refused and delivered to no one. A Commit or a proposal goes to `update`.

## key-material-rate-limited

| field | value |
|---|---|
| `type` | `https://github.com/havenmessenger/interop/blob/main/docs/problems.md#key-material-rate-limited` |
| `title` | Too many keyMaterial requests for this target |
| `status` | 429 |

A `keyMaterial` request on the provider path (protocol-07 §5.2) from a requesting provider that has already asked for
the same target user's KeyPackages the most times the hub takes in an hour (5, as for one user on the client lane).
The requesting provider is the domain the peer's proof authenticated. The requester a request names is not counted:
it is only a name the peer chose, and counting it would let one peer spend the budget of another provider's users. A target's KeyPackages are spent by
being claimed, and a reused last-resort one (DIVERGENCES DIV-23) is the same each time, so the hub bounds how often
they can be claimed. Retry after an hour.

## not-authenticated

| field | value |
|---|---|
| `type` | `https://github.com/havenmessenger/interop/blob/main/docs/problems.md#not-authenticated` |
| `title` | The requesting provider is not authenticated |
| `status` | 403 |

The provider-auth gate (no certificate and no valid signature, a signature that does not verify, a refused nonce) and the `From` check (a header naming a provider the request's proof does not authenticate). The hub logs which; the body does not say. Retry only with a valid proof of the provider the request is from.

## not-permitted

| field | value |
|---|---|
| `type` | `https://github.com/havenmessenger/interop/blob/main/docs/problems.md#not-permitted` |
| `title` | The requesting provider may not do this |
| `status` | 403 |

`keyMaterial/ingest` publishing KeyPackages for a user of another provider: only that provider may. Do not retry.

## not-the-rooms-hub

| field | value |
|---|---|
| `type` | `https://github.com/havenmessenger/interop/blob/main/docs/problems.md#not-the-rooms-hub` |
| `title` | Not from the room's hub |
| `status` | 403 |

`notify` (protocol-07 §5.5) from a provider that is not the hub of the room the path names. Do not retry: only the room's hub sends a notify for it.

## sender-not-allowed

| field | value |
|---|---|
| `type` | `https://github.com/havenmessenger/interop/blob/main/docs/problems.md#sender-not-allowed` |
| `title` | The sender may not send in this room |
| `status` | 403 |

`authorizeSender`: the sender may not send in the room. The answer changes only when the room's list or policy does.

## not-found

| field | value |
|---|---|
| `type` | `https://github.com/havenmessenger/interop/blob/main/docs/problems.md#not-found` |
| `title` | Not found |
| `status` | 404 |

Nothing answers the request: a route this listener does not serve, no KeyPackage or queued message or Welcome for the user named, an identifier that is not found (`identifierQuery`), or an operator's `untrackRoom` for a room with no tree. One body for all of them, byte for byte, so it says nothing about which (DIV-4). Nothing to retry unless what was asked for has since been published.

## room-not-hosted

| field | value |
|---|---|
| `type` | `https://github.com/havenmessenger/interop/blob/main/docs/problems.md#room-not-hosted` |
| `title` | The room is not hosted here |
| `status` | 404 |

`groupInfo` (protocol-07 §5.6) for a room this hub does not host; mimid answers this case `noSuchRoom`. Ask the room's own hub.

## method-not-allowed

| field | value |
|---|---|
| `type` | `https://github.com/havenmessenger/interop/blob/main/docs/problems.md#method-not-allowed` |
| `title` | Method not allowed |
| `status` | 405 |

A route asked with a method it does not take. The `Allow` header is kept. Use a method the `Allow` header names.

## room-is-tracked

| field | value |
|---|---|
| `type` | `https://github.com/havenmessenger/interop/blob/main/docs/problems.md#room-is-tracked` |
| `title` | The room is changed by Commit |
| `status` | 409 |

The operator's `roomPolicy`, `memberRole` and `addParticipant` for a room whose ratchet tree the hub keeps: its list and policy are its group's, changed by Commit (DIV-10). Change the room by Commit, or untrack it first.

## body-too-large

| field | value |
|---|---|
| `type` | `https://github.com/havenmessenger/interop/blob/main/docs/problems.md#body-too-large` |
| `title` | The request is too large |
| `status` | 413 |

A body larger than the endpoint takes. Do not retry the same body.

## wrong-operation

| field | value |
|---|---|
| `type` | `https://github.com/havenmessenger/interop/blob/main/docs/problems.md#wrong-operation` |
| `title` | Wrong consent operation |
| `status` | 422 |

`requestConsent` with an entry whose operation is not `request` or `cancel`, or `updateConsent` with one that is not `grant` or `revoke` (protocol-07 §5.7). Send it to the other endpoint.

## internal-error

| field | value |
|---|---|
| `type` | `https://github.com/havenmessenger/interop/blob/main/docs/problems.md#internal-error` |
| `title` | The hub failed |
| `status` | 500 |

The hub's own failure, such as its store. Retry later.

## upstream-failed

| field | value |
|---|---|
| `type` | `https://github.com/havenmessenger/interop/blob/main/docs/problems.md#upstream-failed` |
| `title` | Another provider did not answer |
| `status` | 502 |

`keyMaterial` for a user of another provider: the hub forwards it, and that provider could not be reached or answered with something this hub cannot read. Also when this hub has no outbound client to forward with. Retry later.

## http-error

| field | value |
|---|---|
| `type` | `https://github.com/havenmessenger/interop/blob/main/docs/problems.md#http-error` |
| `title` | The request was refused |
| `status` | the answer's own |

Any other error status, when no type above applies: for example 415 for a JSON endpoint asked without
`Content-Type: application/json`. The HTTP status says why.

## remote-room-not-delivered

| field | value |
|---|---|
| `type` | `https://github.com/havenmessenger/interop/blob/main/docs/problems.md#remote-room-not-delivered` |
| `title` | Not delivered: the room is hosted on another hub |
| `status` | 422 |

**Retired.** This hub delivers messages for rooms on other hubs to their members here, and answers `no-local-member`
when there are none. The text below is what this answer meant while it was used.

The answer to a `notify` (protocol-07 §5.5) that carries an application message or a Commit for a room hosted on
another hub. This hub does not yet deliver those to its users, so it refuses them rather than answering 201 for a
message it would not deliver. The sender should drop the delivery, not retry it: the answer will be the same until
this hub delivers messages from rooms on other hubs.

Two answers stay 201:
- a `notify` that carries a Welcome: the Welcome is queued for its client;
- a duplicate of a `notify` already received from the same hub, as §5.5 requires.

mimihubd answers this from the release after 0.0.2. Before it, such a `notify` is answered 201 and the message is not
delivered (see DIV-5 in [DIVERGENCES.md](../DIVERGENCES.md)).
