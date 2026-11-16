# Filesystem boundary qualification

The owner resumed Tests from `35fa554` on 2026-11-16. Candidate base
`59158d9` also contains current main. The stopped filesystem mutation run
remains incomplete: 102 caught, 65 missed, six unviable and 59 untested.
Those results describe the original inputs, not the resumed candidate.

The first repaired boundary is `vault ls` through application-support
ancestors. The process test creates an isolated synthetic store and checks
literal `TOKEN` output through a trusted path. World-writable and group-writable
ancestors must produce exit 1, no listing and the trust refusal. A symlinked
data-home path must also fail. Restoring the trusted path restores the listing,
and the fixture contents remain unchanged. The test needs no hardware or actual
secret, clears the child's environment and owns a five-second process deadline.

Replacing `ensure_trusted_directory` with unconditional `Ok(())` reproduces
one saved survivor. The new process assertion fails because mode 0777 now
returns exit 0 instead of 1. Restoring the source returns the test to green.
This qualifies that one hand fault, not the remaining filesystem selection.
The other 64 original survivors and 59 untested mutants still need disposition
or execution against the current inputs.

The stopped driver filtered Cargo tests to `macos::tests::`, which excludes
integration-process tests. Its selected-test recipe cannot exercise this new
boundary. The next Scenario must explicitly include the integration binary and
this process test, then reconcile the selected mutants and fresh baseline. Do
not restart the old driver unchanged or treat its misses as whole-suite misses.

On macOS ARM64 with the pinned nightly, these commands pass under a one-core
guard and one build/test worker:

```sh
cargo test --offline --test integration listing_rejects_untrusted_ancestors_without_reading_the_store -- --exact
make test
make lint
```

The full suite passes 42 unit, 28 integration and four terminal tests; two
hardware cases remain ignored. Timing/cost comparison, coverage, fresh Scenario
mutation qualification and final platform evidence remain deferred. The host
was busy, so these runs establish correctness, not the Tests cost budget.
DSLP-4 remains open, and the draft source remains unmerged.
