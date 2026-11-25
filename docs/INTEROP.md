# Test against Haven's hub

Haven runs mimihubd at `mimi.havenmessenger.com`. Its directory is public:
<https://mimi.havenmessenger.com/.well-known/mimi-protocol-directory>. The revision the hub runs, and that directory as
last read, are on the site's [Live status](https://mimihubd.havenmessenger.com/status.html) page.

## Connecting

Every endpoint but the directory needs proof of which provider is calling (`mimihubd/README.md`, "Peer
authentication"). Either of these:

- Sign each request with an Ed25519 key your provider publishes in DNS, as draft-atwood-mimi-provider-auth §5 has it:
  a TXT record `v=MIMI1; k=ed25519; p=<base64 public key>` at `<selector>._mimi.<your domain>`, and a `From` header
  naming your domain. Haven's host reads your key through a DNSSEC-validating resolver, so your zone has to be signed.
- Present a TLS client certificate issued by a CA this hub trusts, with your provider domain as a DNS subjectAltName.

A request with neither is answered 403. The hub accepts MLS ciphersuite 0x0001 only, and the drafts it serves are
listed in its directory.

## Asking to be added

Open a [peering request](https://github.com/havenmessenger/interop/issues/new?template=peering-request.yml) with your
provider domain and either your key's selector or your CA certificate (PEM; a CA certificate is public). If your
directory is not at `https://<your domain>/.well-known/mimi-protocol-directory`, give its base. Ask there for test
users on our side, too.

We add a provider by hand, after checking the request with you. A CA in this hub's client bundle may issue a
certificate for any provider name ([DIV-16](../DIVERGENCES.md#div-16---a-certificate-names-the-provider-domains-it-carries-and-any-ca-in-the-client-bundle-may-issue-any-name)),
so nothing submitted is trusted until then.

## Requests our hub makes to yours

Our hub signs each request with the key published at `haven1._mimi.mimi.havenmessenger.com`, with a `From` header
naming `mimi.havenmessenger.com`. It reads your directory from
`https://<your domain>/.well-known/mimi-protocol-directory`, or from the base you gave us, and sends only to URLs on
your domain or a subdomain of it ([DIV-5](../DIVERGENCES.md#div-5---fan-out-to-other-providers-and-what-is-not-delivered-yet)).

## What this deployment does

These are the choices Haven's hub runs with, from its policy file (`mimihubd/README.md`, "The policy file"):

- A room this hub hosts takes its first Commit only with a Full GroupInfo and the full ratchet tree
  (draft-ietf-mls-ratchet-tree-options `full`), so it can tell who proposed each change after it
  ([DIV-10](../DIVERGENCES.md#div-10---closed-for-room-updates-by-commit-four-operations-have-no-wire-route-of-their-own)).
- keyMaterial requests carry a nonce, need the target user's consent for the requester they name (protocol-07 §5.7),
  and are rate-limited for each target user and requesting provider (problem type `key-material-rate-limited`).
- A last-resort KeyPackage is handed out once
  ([DIV-23](../DIVERGENCES.md#div-23---with-mimi_last_resort_reusetrue-a-last-resort-keypackage-is-handed-out-more-than-once)).
- identifierQuery finds only users enrolled on this hub.
- An external Commit is taken where a room's operational policy allows it, and where a room has no operational policy
  ([DIV-1](../DIVERGENCES.md#div-1---groupinfo-and-external-commit-join-built-for-rooms-whose-tree-the-hub-keeps)).
- Refusals are RFC 9457 problem details; [`docs/problems.md`](problems.md) lists each type.

## Reporting what you find

Open an [interop result](https://github.com/havenmessenger/interop/issues/new?template=interop-result.yml), or a
[bug or question](https://github.com/havenmessenger/interop/issues/new?template=bug-or-question.yml). Where you and this
hub read a draft differently, [`DIVERGENCES.md`](../DIVERGENCES.md) says which reading it takes, and why.
