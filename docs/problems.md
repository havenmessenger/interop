# Problem types

mimi-hubd answers some refusals with an [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) problem body
(`Content-Type: application/problem+json`). Each problem type below is named by its URI: this page, with the type as
its anchor. A problem body names the condition only. It never names a user, a client or a room.

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

mimi-hubd answers this from the release after 0.0.2. Before it, such a `notify` is answered 201 and the message is not
delivered (see DIV-5 in [DIVERGENCES.md](../DIVERGENCES.md)).
