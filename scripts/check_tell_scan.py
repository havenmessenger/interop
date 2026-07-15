#!/usr/bin/env python3
"""Guard 4 (pre-commit + CI): a lightweight secrets/PII/network-hygiene linter for this
public repo. Blocks the shapes that most often leak into tracked source: private-key PEM
headers, well-known cloud/vendor API-key prefixes, non-placeholder email addresses, and
private (RFC 1918 10.0.0.0/8) IP literals.

This file intentionally ships with only generic, project-agnostic patterns. Project-specific
denylist entries (internal tracker IDs, internal doc-path references, or anything else
specific to this project's own conventions) load from a gitignored _tell_scan_denylist.py
sidecar if present (see _tell_scan_denylist.py.example for the expected shape) - a
maintainer or CI environment populates it locally, and it is never committed. Its absence
degrades this scan to shape-only coverage rather than breaking it.

Usage:
    check_tell_scan.py [file ...]   # pre-commit passes staged files
    check_tell_scan.py              # no args -> scan the whole tracked tree (CI mode)
    check_tell_scan.py --self-test  # fixture proof, see run_self_test()
"""

import re
import subprocess
import sys
from pathlib import Path

GENERIC_PATTERNS = {
    "private key material": re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"
    ),
    # Prefix-based, the same lightweight approach common secret scanners (e.g. gitleaks'
    # default ruleset) use for well-known vendor token shapes, rather than a full
    # entropy calculation.
    "cloud/vendor API key shape": re.compile(
        r"\bAKIA[0-9A-Z]{16}\b"  # AWS access key ID
        r"|\bgh[pousr]_[A-Za-z0-9]{36,}\b"  # GitHub token
        r"|\bgithub_pat_[A-Za-z0-9_]{22,}\b"  # GitHub fine-grained PAT
        r"|\bxox[baprs]-[A-Za-z0-9-]{10,}\b"  # Slack token
        r"|\bAIza[0-9A-Za-z_-]{35}\b"  # Google API key
        r"|\bsk_live_[0-9a-zA-Z]{24,}\b"  # Stripe secret key
        r"|\brk_live_[0-9a-zA-Z]{24,}\b"  # Stripe restricted key
    ),
    # Excludes RFC 2606 reserved documentation domains/TLDs (example.com/.org/.net/.edu,
    # .test/.invalid/.localhost) so test fixtures using those conventional placeholders
    # are not flagged as a PII leak.
    "email address (non-placeholder domain)": re.compile(
        r"\b[\w.+-]+@(?!(?:[\w-]+\.)?(?:example\.(?:com|org|net|edu)|test|invalid|localhost)\b)"
        r"[\w-]+(?:\.[\w-]+)+\b"
    ),
    "private network IP literal (10.0.0.0/8)": re.compile(r"\b10(?:\.\d{1,3}){3}\b"),
}

try:
    from _tell_scan_denylist import SENSITIVE_PATTERNS
except ImportError:
    SENSITIVE_PATTERNS = {}

PATTERNS = {**GENERIC_PATTERNS, **SENSITIVE_PATTERNS}

EXCLUDE_DIR_PARTS = {"target", ".git"}
EXCLUDE_FILES = {
    "scripts/check_tell_scan.py",  # this file legitimately names the shapes it blocks
    "scripts/_tell_scan_denylist.py",  # the sidecar itself contains the real sensitive literals
    "scripts/_tell_scan_denylist.py.example",  # the committed template — placeholder text only
    "SECURITY.md",  # the published security-contact address is intentional disclosure, not a leak
    "mimi-hubd/Cargo.toml",  # the .deb's Maintainer: field is the same intentional public contact
    # guard 5's self-test fixtures deliberately contain synthetic tell-shaped text (that's how it
    # proves it catches every class) — the same self-referential exclusion as this file's own entry.
    "scripts/check_public_comment_hygiene.py",
    "scripts/oss-external-pins.txt",
    "scripts/oss-public-token-manifest.txt",
}


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def tracked_files() -> list[Path]:
    root = repo_root()
    out = subprocess.run(
        ["git", "ls-files"], cwd=root, capture_output=True, text=True, check=True
    ).stdout
    return [root / line for line in out.splitlines() if line]


def scan(files: list[Path]) -> int:
    root = repo_root()
    hits = []
    for f in files:
        try:
            rel = f.resolve().relative_to(root)
        except ValueError:
            continue
        if EXCLUDE_DIR_PARTS & set(rel.parts) or str(rel) in EXCLUDE_FILES:
            continue
        if not f.is_file():
            continue
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        for label, pattern in PATTERNS.items():
            for m in pattern.finditer(text):
                line_no = text.count("\n", 0, m.start()) + 1
                hits.append(f"{rel}:{line_no}: [{label}] {m.group(0)}")

    if hits:
        print("TELL-SCAN VIOLATION — internal reference(s) found in public source:", file=sys.stderr)
        for h in hits:
            print(f"  {h}", file=sys.stderr)
        return 1
    print(f"tell-scan: OK ({len(files)} file(s) checked, zero hits)")
    return 0


# Realistic clean code this scan must NOT flag - each line exercises a specific
# false-positive risk the pattern comments above call out.
_SELF_TEST_CLEAN_FIXTURE = """
// A round-trip encode/decode proof.
fn verify_vec_roundtrip(bytes: &[u8]) -> bool { true }
// Ciphersuite pinned to 0x0001 (MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519).
const SUITE: u16 = 0x0001;
// Test fixtures use the RFC 2606 reserved documentation domain.
let uri = "mimi://a.example/u/alice";
let email = "alice@example.com";
// A curl example using @file redirection, not an email address.
// curl -X POST --data-binary @notify.bin https://localhost:8443/mimi/pl/notify
// A different private-network range, outside what this scan targets.
let addr = "192.168.1.1:8443";
let local = "127.0.0.1:0";
"""

# A planted tell this scan MUST flag - one instance of each generic committed class.
_SELF_TEST_TELL_FIXTURE = """
-----BEGIN RSA PRIVATE KEY-----
let key = "AKIAABCDEFGHIJKLMNOP";
let contact = "user@example-mail.com";
let host = "10.0.0.1";
"""


def run_self_test() -> int:
    """Proves the committed GENERIC_PATTERNS are false-positive-safe on realistic clean
    code AND still catch a planted tell of each class. Exits non-zero if either proof
    fails. This only exercises the patterns shipped in this file - sidecar-specific
    patterns (if a maintainer has populated one locally) are not covered here, since
    this file must be provable standalone on a fresh, sidecar-less clone."""
    clean_hits = [
        (label, m.group(0))
        for label, pattern in GENERIC_PATTERNS.items()
        for m in pattern.finditer(_SELF_TEST_CLEAN_FIXTURE)
    ]
    tell_hits = {
        label: list(pattern.finditer(_SELF_TEST_TELL_FIXTURE))
        for label, pattern in GENERIC_PATTERNS.items()
    }

    ok = True
    if clean_hits:
        ok = False
        print("SELF-TEST FAILED: clean fixture triggered false positive(s):", file=sys.stderr)
        for label, text in clean_hits:
            print(f"  [{label}] {text!r}", file=sys.stderr)
    else:
        print("self-test: clean fixture triggers zero hits (false-positive proof OK)")

    missing = [label for label, matches in tell_hits.items() if not matches]
    if missing:
        ok = False
        print(f"SELF-TEST FAILED: planted tell(s) NOT caught: {missing}", file=sys.stderr)
    else:
        print(f"self-test: planted tell caught for all {len(GENERIC_PATTERNS)} generic classes")

    return 0 if ok else 1


def main() -> int:
    if "--self-test" in sys.argv:
        return run_self_test()
    args = [Path(a) for a in sys.argv[1:]]
    files = args if args else tracked_files()
    return scan(files)


if __name__ == "__main__":
    sys.exit(main())
