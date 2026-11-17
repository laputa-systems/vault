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
Literal metadata-policy tables also distinguish current, root and foreign
owners; group and world writes; and the sticky-directory exception for root.
They use synthetic metadata from an owned fixture, without privileged ownership
changes. Removing the root-sticky negation or skipping the owned-data-home write
check fails its intended assertion. Both faults were restored.

The stopped driver filtered Cargo tests to `macos::tests::`, which excludes
integration-process tests. Its selected-test recipe cannot exercise this new
boundary. The resumed Scenario runs the full Cargo suite, including the
integration process test. Do not restart the old driver unchanged or treat its
misses as whole-suite misses.

## Qualified directory-policy Scenario

The complete selection is 21 mutants in `ensure_trusted_directory` and
`ensure_owned_data_home`. The first fresh run completed 19 (14 caught, five
missed) before the one-core guard stopped compilation; two were untested.
That interrupted run is not a pass. The corrected run uses two guarded cores,
one Cargo build job, one test thread and one mutation worker. Cargo-mutants
27.1.0 runs a fresh baseline, a 60-second test timeout, 300-second build timeout
and a 1,200-second total bound:

```sh
cargo mutants --gitignore true --file src/macos.rs \
  --re '(in (ensure_trusted_directory|ensure_owned_data_home)|replace (ensure_trusted_directory|ensure_owned_data_home) ->)' \
  --baseline run --timeout 60 --build-timeout 300 --jobs 1 --no-shuffle \
  --output .work/trust-scenario
```

The final result is 21 caught, zero missed, unviable or timed out, in nine
minutes. All identities match the inventory; every caught log contains a new
metadata-policy assertion failure. No exclusion was added. This covers all
seven saved survivors in this region, leaving 58 of the original 65 and all
59 originally untested mutants outside this qualification. It does not qualify
the whole filesystem scope or establish a CI-time target.

On macOS ARM64 with the pinned nightly, these commands pass under a two-core
guard and one build/test worker:

```sh
cargo test --offline --test integration listing_rejects_untrusted_ancestors_without_reading_the_store -- --exact
make test
make lint
```

Use a separate `CARGO_TARGET_DIR` for the mutation run and final ordinary
checks. The first final check reused the last mutant's executable from a shared
target and reproduced its 35-pass/nine-failure result; that run was rejected.
The restored source passes in an isolated `.work/target-trust-final` target:
44 unit, 28 integration and four terminal tests, two hardware cases ignored,
zero optional-check skips, and warnings-denied lint.

Timing/cost comparison, coverage, the remaining filesystem regions and final
platform evidence remain deferred. Host constraints mean these runs establish
correctness, not the Tests cost budget. DSLP-4 remains open and the draft remains
unmerged.

## Filename codec Scenario

On macOS arm64, base `0561a3e34828db0164d2a2baedfad2c1a7b3a611`,
this slice replaces the roundtrip-only filename oracle with literal encoding
and decoding examples, invalid filename cases and exact 125/126 UTF-8 byte
boundaries. The parser table remains private because malformed stems have a
wide input space. Changing `validate_store_name` from `>` to `>=` makes the
125-byte assertion fail; restoring the source passes. No production code was
changed. The integration cache fixture's shorter directory name allows its
socket to fit when the mandated worktree TMPDIR is used.

Cargo-mutants 27.1.0 listed all 36 generated mutants in `validate_name`,
`validate_store_name`, `secret_filename`, `decode_secret_filename`, and
`hex_digit`, including return and expression mutations. With `PATH` prefixed
by `/Users/josh/d/stuff/.work/tools/bin`, `TMPDIR=$PWD/.work/tmp`,
`RUSTC_WRAPPER=kache`, `CARGO_BUILD_JOBS=1`, `RUST_TEST_THREADS=1`, and
`CARGO_TARGET_DIR=$PWD/.work/target-codec-mutants`, the shared mutation lock
was held for a fresh baseline and this full-suite selection:

```sh
cpu-guard --cores 2 -- cargo mutants --gitignore true --file src/macos.rs \
  --re '(in (validate_name|validate_store_name|secret_filename|decode_secret_filename|hex_digit)|replace (validate_name|validate_store_name|secret_filename|decode_secret_filename|hex_digit) ->)' \
  --baseline run --timeout 60 --build-timeout 300 --jobs 1 --no-shuffle \
  --output .work/codec-retry
```

The completed run exits 2: 31 caught, four missed, one unviable, no timeouts.
All caught logs were inspected: 30 fail in the codec test's assertions or
unwraps; `hex_digit`'s `+` to `-` mutation instead panics on arithmetic
underflow in that test. The `+` to `*` mutation is unviable due to a compile-time
arithmetic overflow. Four misses are equivalent for the observable result:

- At 1153:24, `||` to `&&` lets empty and odd stems through the first guard;
  empty names fail validation, and odd stems cannot equal their re-encoding.
- At 1153:47, `||` to `&&` lets odd or oversized stems through; odd stems
  cannot equal their re-encoding, while oversized even stems fail name length
  validation (or UTF-8/hex decoding first).
- At 1160:32, `|` to `^` combines nonoverlapping high and low four-bit nibbles.
- At 1163:44, `||` to `&&` still returns `None` for an invalid name because
  `secret_filename` repeats the same validation and its `ok()?` exits.

No exclusions were added. The first baseline exited 4 before any mutant: two
cache integration tests rejected the overly long fixture socket path. After
shortening the fixture name, four focused cache-daemon tests and the fresh
baseline passed. The original stopped 232-case filesystem run remains 102
caught, 65 missed, six unviable and 59 untested; this component is not a
reclassification of those results. The 21-mutant directory qualification is
unchanged. Other filesystem regions, coverage, cost and platform evidence
remain open, so DSLP-4 remains open.

With the same environment and a separate `CARGO_TARGET_DIR=$PWD/.work/target-codec-final`,
`cpu-guard --cores 2 -- make test` and `cpu-guard --cores 2 -- make lint`
both pass. The suite reports 44 unit, 28 integration and four terminal tests
passed, two hardware tests ignored and zero optional skips. An initial test
wrapper lost its exit status to zsh's readonly `status` variable despite green
output; the command was rerun successfully.
