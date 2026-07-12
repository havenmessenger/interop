# Contributing to Haven Interop

Thank you for your interest. This implements the MIMI/MLS drafts; contributions that change
protocol behavior are held to the same bar as the spec itself.

## Ground rules
- **Spec conformance is the standard.** A change to wire encoding or protocol logic should
  cite the relevant draft section and, where one exists, keep the conformance tests green.
- **Divergences are documented, not silent.** If a change intentionally departs from the
  drafts, it goes in [`DIVERGENCES.md`](DIVERGENCES.md), not just a code comment.
- **`unsafe` is justified or absent.** Every `unsafe` block needs a documented rationale.
- **The standalone build stays standalone.** This repo has no dependency on Haven's closed
  backend or client; a fresh clone must build and test on its own.

## Workflow
1. Open an issue describing the change before large work.
2. `cargo fmt`, `cargo clippy --lib --bins -- -D warnings`, `cargo test`, and `cargo audit`
   must pass. CI also runs a manifest-purity check (no stray dependency on Haven's closed
   crates), a one-way-dependency check, and a tell-scan for internal references that should
   not appear in a public repo.

## License
By contributing you agree your contributions are licensed under [Apache-2.0](LICENSE).
