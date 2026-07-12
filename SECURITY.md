# Security Policy

Haven is a privacy and security product. Coordinated disclosure from security researchers
is welcome.

## Reporting a vulnerability
- **Email:** security@havenmessenger.com
- **Encrypted reports:** the disclosure PGP key is published at
  [`havenmessenger.com/.well-known/security.txt`](https://havenmessenger.com/.well-known/security.txt).
  Please encrypt reports that contain sensitive detail (exploit steps, affected users).
- **Please do not** open a public issue, pull request, or discussion for a security-sensitive
  report - use the email channel so we can coordinate disclosure.
- **Include:** affected component, version/commit hash, reproduction steps, and an impact
  assessment.

## What to expect
- **Acknowledgement within 3 business days** that we received your report.
- An initial assessment and a **coordinated-disclosure timeline agreed with you** - we target
  public disclosure within **90 days**, sooner for a fix that is ready, later only by mutual
  agreement for a complex issue.
- Credit in the advisory if you wish (or anonymity if you prefer).

## Safe harbor
We will not pursue or support legal action against researchers who, in good faith, discover and
report a vulnerability under this policy - provided you avoid privacy violations against other
users, service degradation, and data destruction, and give us reasonable time to remediate
before any public disclosure. Good-faith security research is authorized.

## Scope
**In scope:** this repository - the MIMI/MLS spec-conformant interop library (the wire/content
codecs, participant-list and URI parsing, the ciphersuite accept-gates, consent, and room-policy
logic) and `mimi-hub`, the reference hub daemon (mTLS termination, durable state, endpoint
handlers). A code-level vulnerability in either is in scope regardless of who is running it.

**Out of scope (different process):** Haven's own production deployment of `mimi-hub` or any
other operator's deployment (configuration, infrastructure, and operational issues are the
deploying party's responsibility, not a code vulnerability in this repository), and Haven's
other operational infrastructure. You may report deployment-specific issues affecting Haven's
own production service to the same address, but note the underlying infrastructure is not in
this repo and is assessed separately.
