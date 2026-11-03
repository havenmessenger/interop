# Interoperating with Haven

## The premise
Haven champions interoperability over the walled garden. If you operate a messaging service
and want to interoperate with Haven, this library is the reference implementation of the
protocol surface you build against.

## What you can rely on
- A spec-conformant MIMI/MLS implementation tracking the IETF work.
- Clear documentation of any divergence from the drafts, in [`DIVERGENCES.md`](../DIVERGENCES.md).
- Coordinated communication about what is shipped versus experimental.

## Status
Early. Haven's hub is running at https://mimi.havenmessenger.com, and no other provider has
connected to it yet. One independent implementation has run against a local `mimi-hubd`; its
results are in [issue #1](https://github.com/havenmessenger/interop/issues/1). To test against
the hub, open an issue, or reach us through the contact in [`SECURITY.md`](../SECURITY.md) /
Haven's site.
