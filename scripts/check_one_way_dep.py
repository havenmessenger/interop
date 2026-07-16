#!/usr/bin/env python3
"""Guard 3 (one-way-dependency): mimi-core is a leaf library. It must never import
app-specific or binding-layer types; the dependency arrow only ever points a
consumer -> mimi-core, never the reverse.

Fails if `src/**/*.rs` has actual CODE (not doc-comment prose) referencing
`flutter_rust_bridge`, a binding-crate name (loaded from the local
_tell_scan_denylist.py sidecar if present, see check_tell_scan.py's
docstring for why that lives in a gitignored sidecar rather than this
published script), or an `#[frb(...)]` attribute. For a crate that is *supposed*
to have zero non-crates.io dependencies, this is mostly a regression tripwire:
it should never fire, and firing is exactly the "a leaf reached up" bug this
guard exists to catch.

Deliberately comment-aware (unlike a bare grep): mimi-core's own doc-comments
legitimately SAY "no #[frb] exports" as architectural documentation of its OWN
FRB-freedom. A naive scan would false-positive on the exact sentences proving the
guard's invariant holds. Only lines that are not comment-only are checked (comment
lines start with `//`, `///`, or `//!` after trimming leading whitespace).
"""

import re
import sys
from pathlib import Path

try:
    from _tell_scan_denylist import ONE_WAY_DEP_SENSITIVE_PATTERN
except ImportError:
    ONE_WAY_DEP_SENSITIVE_PATTERN = None

FORBIDDEN_PATTERNS = [
    re.compile(r"\bflutter_rust_bridge\b"),
    re.compile(r"#\[frb\b"),
]
if ONE_WAY_DEP_SENSITIVE_PATTERN is not None:
    FORBIDDEN_PATTERNS.append(ONE_WAY_DEP_SENSITIVE_PATTERN)


def is_comment_only(line: str) -> bool:
    return line.strip().startswith("//")


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    # mimi-core's own src/ plus the mimi-hub and mimi-bot workspace members (runnable daemons over
    # mimi-core, equally subject to "no app-binding-layer symbol" references).
    src_dirs = [repo_root / "src", repo_root / "mimi-hub" / "src", repo_root / "mimi-bot" / "src"]
    hits = []
    for src_dir in src_dirs:
        if not src_dir.is_dir():
            continue
        for f in src_dir.rglob("*.rs"):
            for line_no, line in enumerate(f.read_text(errors="replace").splitlines(), start=1):
                if is_comment_only(line):
                    continue
                for pattern in FORBIDDEN_PATTERNS:
                    if pattern.search(line):
                        hits.append(f"{f}:{line_no}: {line.strip()}")

    if hits:
        print("ONE-WAY-DEPENDENCY VIOLATION: mimi-core has CODE (not comment) referencing app-binding symbols:", file=sys.stderr)
        for h in hits:
            print(f"  {h}", file=sys.stderr)
        return 1

    print("one-way-dep: OK (no flutter_rust_bridge / #[frb] CODE references in src/)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
