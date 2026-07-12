# mimi-hub

A reference MIMI hub daemon: mTLS-terminated HTTP server, durable SQLite-backed state, and the
v1 request-handling semantics (add-driven membership, text-only content, MLS ciphersuite 0x0001
only) over [`mimi-core`](..)'s gate, consent, and room-policy logic.

## Wire format: read this before you rely on interop

This hub speaks two lanes side by side.

**`/mimi/v1/*`** is JSON. It implements the *semantics* of the v1 endpoints (the gate, the consent
flow, the room-policy RBAC, the ciphersuite restriction) faithfully, but its request/response bodies
are not the TLS presentation-language framing `draft-ietf-mimi-protocol` defines.

**`/mimi/pl/*`** is the draft's actual wire framing (TLS presentation language, RFC 8446 §3), routed
for six endpoints: `submitMessage` (§5.4), `requestConsent`/`updateConsent` (§5.7), `keyMaterial`
(§5.2), `notify` inbound-receive (§5.5), and `identifierQuery` (§5.8). Every wire route decodes the
same bytes a strict protocol-06 client would send and calls the identical business logic the JSON
lane calls, so state written through one lane is readable through the other (proven below for
`keyMaterial`). The path segment on the request/consent/keyMaterial routes (`:recipient`,
`:target_domain`, `:requester_domain`, `:target_user`) plays the same opaque routing-key role the
JSON lane's query parameters play; it is not the draft's room-participant-list fanout, which this
reference hub does not implement for message delivery. The directory (`/.well-known/mimi-protocol-
directory`) advertises all six under `wireEndpoints`, with real path templates.

`update` (§5.3) has a wire codec (`HandshakeBundle`, tested against real MLS Commit and Proposal
messages) but no live route: this reference hub has no processing path for a real MLS Commit or
Proposal at all (`roomPolicy`/`memberRole`/`addParticipant` implement the policy *outcome* of that
flow through separate JSON RPCs, never parsing one), so wiring `update` would mean building that
processing, not just framing its bytes. `groupInfo` (§5.6) is out of scope for the same shape of
reason: it is the external-commit join endpoint DIV-1 disallows in Haven's own product build, and
framing it without the accept-path behind it would wire-format half of a security-relevant endpoint.
`reportAbuse` (§5.9) and asset download (§5.10) have no v1 handler of any kind to frame. The four v1
room-admin endpoints (`roomPolicy`/`memberRole`/`addParticipant`/`authorizeSender`) are not
protocol-06 endpoints at all - they are this hub's own RBAC surface, not part of the draft's wire
vocabulary - so there is nothing to frame them against.

Real output, proving the wire lane against a live hub with real MLS objects.

`submitMessage`, round-tripped against the JSON lane's store:

```
$ curl -s --cacert ca-cert.pem --cert client-cert.pem --key client-key.pem \
    -X POST --data-binary @submit_message.bin \
    https://localhost:8443/mimi/pl/submitMessage/xxx@haven -w '\nHTTP_STATUS=%{http_code}\n'
HTTP_STATUS=200
# response body: 01 00 00000000 6a4d6bba  (protocol=mls10, code=accepted, accepted_timestamp)

$ curl -s --cacert ca-cert.pem --cert client-cert.pem --key client-key.pem \
    "https://localhost:8443/mimi/v1/message?user=xxx@haven" -o fetched.bin
# fetched.bin is byte-identical to the MLS envelope inside submit_message.bin: the wire and
# JSON lanes read from the same store.
```

`keyMaterial`, published over the *JSON* lane and served back over the *wire* lane, proving the two
lanes share one store in both directions, not just one:

```
$ curl -s --cacert ca-cert.pem --cert client-cert.pem --key client-key.pem \
    -X POST --data-binary @bob_kp.bin \
    "https://localhost:8443/mimi/v1/keyMaterial/ingest?user=bob" -w 'HTTP_STATUS=%{http_code}\n'
HTTP_STATUS=204

$ curl -s --cacert ca-cert.pem --cert client-cert.pem --key client-key.pem \
    -X POST --data-binary @km_req.bin \
    https://localhost:8443/mimi/pl/keyMaterial/bob -o km_resp.bin -w 'HTTP_STATUS=%{http_code}\n'
HTTP_STATUS=200
# the served KeyPackage bytes inside km_resp.bin are byte-identical to bob_kp.bin (290-byte
# response: userStatus=success, one ClientKeyMaterial entry, the KeyPackage as published)
```

`notify` (a real application message wrapped as `FanoutMessage`) and `identifierQuery` (a real
wire-encoded query against a non-enrolled user, proving DIV-4's no-body-oracle property holds on
the wire lane the same way it holds on the JSON lane):

```
$ curl -s --cacert ca-cert.pem --cert client-cert.pem --key client-key.pem \
    -X POST --data-binary @notify.bin \
    https://localhost:8443/mimi/pl/notify -w '\nHTTP_STATUS=%{http_code}\n'
HTTP_STATUS=201

$ curl -s --cacert ca-cert.pem --cert client-cert.pem --key client-key.pem \
    -X POST --data-binary @idq.bin \
    https://localhost:8443/mimi/pl/identifierQuery -o idq_resp.bin -w 'HTTP_STATUS=%{http_code}\n'
HTTP_STATUS=404
$ wc -c idq_resp.bin
0 idq_resp.bin
```

## Quickstart

You need `cargo` and `openssl` (or any tool that can issue a CA and a leaf certificate signed by
it). This daemon requires mTLS: it will not start without a server certificate, a server key, and
a client CA to validate incoming peer certificates against.

```bash
mkdir -p /tmp/mimi-hub-demo
CERTDIR=/tmp/mimi-hub-demo

# A throwaway CA.
openssl req -x509 -newkey rsa:2048 -nodes -keyout $CERTDIR/ca-key.pem -out $CERTDIR/ca-cert.pem \
  -days 365 -subj "/CN=mimi-hub-demo-ca"

# A server certificate for localhost, signed by that CA.
openssl req -newkey rsa:2048 -nodes -keyout $CERTDIR/server-key.pem -out $CERTDIR/server-req.pem \
  -subj "/CN=localhost"
openssl x509 -req -in $CERTDIR/server-req.pem -CA $CERTDIR/ca-cert.pem -CAkey $CERTDIR/ca-key.pem \
  -CAcreateserial -out $CERTDIR/server-cert.pem -days 365 \
  -extfile <(echo "subjectAltName=DNS:localhost")

# A client certificate, also signed by that CA - this is what a peer presents to be trusted.
openssl req -newkey rsa:2048 -nodes -keyout $CERTDIR/client-key.pem -out $CERTDIR/client-req.pem \
  -subj "/CN=demo-client"
openssl x509 -req -in $CERTDIR/client-req.pem -CA $CERTDIR/ca-cert.pem -CAkey $CERTDIR/ca-key.pem \
  -CAcreateserial -out $CERTDIR/client-cert.pem -days 365

# Run the hub from the repo root (cargo needs the workspace Cargo.toml; the cert paths above are
# already absolute, so this does not need to run from $CERTDIR).
MIMI_PROVIDER_DOMAIN=example.com \
MIMI_BIND_ADDR=127.0.0.1:8443 \
MIMI_DB_PATH=/tmp/mimi-hub-demo/hub.db \
MIMI_SERVER_CERT=/tmp/mimi-hub-demo/server-cert.pem \
MIMI_SERVER_KEY=/tmp/mimi-hub-demo/server-key.pem \
MIMI_CLIENT_CA=/tmp/mimi-hub-demo/ca-cert.pem \
cargo run -p mimi-hub
```

In a second terminal, query the directory with a client certificate signed by the same CA:

```bash
curl -s --cacert /tmp/mimi-hub-demo/ca-cert.pem --cert /tmp/mimi-hub-demo/client-cert.pem \
  --key /tmp/mimi-hub-demo/client-key.pem \
  https://localhost:8443/.well-known/mimi-protocol-directory
```

Real output from this exact sequence:

```json
{
    "endpoints": {
        "identifierQuery": "/mimi/v1/identifierQuery",
        "keyMaterial": "/mimi/v1/keyMaterial",
        "message": "/mimi/v1/message",
        "notify": "/mimi/v1/notify",
        "requestConsent": "/mimi/v1/requestConsent",
        "submitMessage": "/mimi/v1/submitMessage",
        "updateConsent": "/mimi/v1/updateConsent",
        "welcome": "/mimi/v1/welcome"
    },
    "mls_ciphersuites": [1],
    "protocol_drafts": {"content": "09", "protocol": "06", "room-policy": "03"},
    "provider": "example.com",
    "unsupported": {
        "assets_ohttp": "DIV-3: v1 is messaging-only",
        "groupInfo_external_commit_join": "DIV-1: add-driven join only (ETK security)",
        "non_0x0001_ciphersuites": "DIV-2: rejected at ingest",
        "update_wire_endpoint": "codec built, no live accept-path (no Provider method processes a real MLS Commit/Proposal yet); JSON room-admin RPCs cover the policy outcome"
    },
    "wireEndpoints": {
        "identifierQuery": "/mimi/pl/identifierQuery",
        "keyMaterial": "/mimi/pl/keyMaterial/{targetUser}",
        "notify": "/mimi/pl/notify",
        "requestConsent": "/mimi/pl/requestConsent/{targetDomain}",
        "submitMessage": "/mimi/pl/submitMessage/{recipient}",
        "updateConsent": "/mimi/pl/updateConsent/{requesterDomain}"
    }
}
```

A request without a client certificate is rejected at the TLS handshake (curl exits 56, connection
reset), proving mTLS is actually enforced rather than merely configured.

## Configuration reference

All configuration is environment variables; there are no config files.

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `MIMI_PROVIDER_DOMAIN` | yes | none, hard error if unset | This hub's own domain, used in the directory response and in `From`-authority checks. |
| `MIMI_SERVER_CERT` | yes | none | PEM path, this hub's TLS server certificate (+ chain). |
| `MIMI_SERVER_KEY` | yes | none | PEM path, this hub's TLS server private key. |
| `MIMI_CLIENT_CA` | yes | none | PEM path, the CA that signs client certificates for peers this hub trusts. This is the whole peer-trust model: any peer presenting a cert this CA signed is allowed to call the hub's endpoints. |
| `MIMI_BIND_ADDR` | no | `0.0.0.0:8443` | Listen address. |
| `MIMI_DB_PATH` | no | `/var/lib/mimi/provider.db` | SQLite file path for durable state. |

The daemon never falls back to plain HTTP: a missing certificate, key, or CA path is a hard error
at startup, not a degraded-but-running mode.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/.well-known/mimi-protocol-directory` | Advertises supported ciphersuite, draft revisions, and endpoint URLs. |
| GET | `/mimi/v1/keyMaterial?user=` | Serve one local user's one-time KeyPackage. |
| POST | `/mimi/v1/keyMaterial/ingest` | Gate + optionally publish a KeyPackage (local or foreign). |
| POST | `/mimi/v1/notify` | Idempotent fanout receipt. |
| POST | `/mimi/v1/welcome/ingest` | Gate + optionally relay a Welcome. |
| GET | `/mimi/v1/welcome?user=` | Deliver-once pull of a queued Welcome. |
| POST | `/mimi/v1/submitMessage?recipient=` | Deposit an opaque application message for a recipient. |
| GET | `/mimi/v1/message?user=` | Deliver-once pull of a queued message. |
| POST | `/mimi/v1/identifierQuery` | Opt-in-only identifier lookup. |
| POST | `/mimi/v1/requestConsent` | Consent request (§5.7 C1), always 201. |
| POST | `/mimi/v1/updateConsent` | Consent grant/revoke (§5.7 C2), always 201. |
| POST | `/mimi/v1/roomPolicy?room=` | Set a room's RBAC policy. |
| POST | `/mimi/v1/memberRole?room=&member=&role=` | Assign a member's role in a room. |
| POST | `/mimi/v1/addParticipant?room=&member=` | Register a room participant. |
| POST | `/mimi/v1/authorizeSender?room=&sender=` | Check whether a sender may send in a room. |

## What this hub does not do (v1 scope)

- **§5.6 GroupInfo / external-commit join.** Membership is add-driven only.
- **Non-0x0001 ciphersuites.** Rejected at the gate before they reach any MLS processing.
- **Assets / OHTTP (§5.10).** v1 is messaging-only.
- **A per-caller room-admin principal.** The mutating room-policy endpoints trust any mTLS peer in
  the allowlist to administer any room this hub hosts; they do not yet bind an authenticated
  principal and check a per-room admin role before mutating. See the `SECURITY SCOPE` comment in
  `src/http.rs` for the exact boundary.

The directory endpoint discloses the ciphersuite and join-model restrictions programmatically, so
a client can detect them without reading source.

## Security

See the parent repo's [`SECURITY.md`](../SECURITY.md) for the vulnerability-reporting process and
the scope statement covering this daemon.
