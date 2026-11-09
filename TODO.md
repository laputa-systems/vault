Prefix: VLT
Next: 3

# Backlog: vault

### VLT-2 · P2 · crypto-bigint 0.5.5 timing side channel

- **Area:** Security
- **Where:** `Cargo.lock` `crypto-bigint` 0.5.5, pulled in by `elliptic-curve` 0.13.8 through `age` 0.12.1
- **Problem:** `crypto-bigint` 0.5.5 has RUSTSEC-2026-0387, timing variability in operations that are supposed to be constant-time. The crates.io mirror has 0.7.10, and the only published `age` is 0.12.1, which resolves `elliptic-curve` 0.13.8 and stays on the 0.5 line. There is no newer `age` that moves off 0.5.5. Unblocks when a published `age` depends on a patched `crypto-bigint`, or the owner accepts an override.
- **Recommendation:** Upgrade `age` when a release leaves `crypto-bigint` 0.5. Do not add a `[patch]` that hides the advisory.
- **Fix with:** upgrade-the-world
- **Effort:** S

