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
  `secret_filename` repeats the same validation and its `ok()?` exits. Valid
  names already came from an even-length, lowercase-hex stem and valid UTF-8,
  so their encoding is canonical. The earlier length guard rejects `414.age`
  before this comparison; an additional literal case verifies that dependency.

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

Parent review checked every caught log against the codec oracle, then repeated
all 36 identities with the additional odd-stem case and a fresh baseline,
selecting the codec unit test through `--cargo-test-arg=--bin
--cargo-test-arg=vault
--cargo-test-arg=macos::tests::secret_name_filename_encoding_is_canonical_and_path_safe`.
The result remains 31 caught, four equivalent misses, one unviable and no
timeouts; raw tool exit 2 remains visible. This omits unrelated cache waits from
the mutation runner. Full ordinary verification still runs the entire suite.

## Data-home resolver Scenario

On macOS arm64, base `8dc8fa8`, `application_support_path_uses_xdg_or_macos_default`
now compares independent literal outcomes for absolute, relative, absent and
empty XDG values, plus absent and relative HOME errors. An absolute XDG path
containing a non-UTF-8 byte remains an `OsString`/`PathBuf` roundtrip. The test
does not access the filesystem or impose validation beyond the resolver's
existing absolute-HOME check. Inverting the absolute-XDG condition fails the
`/custom/data` literal assertion; restoring it passes.

Cargo-mutants 27.1.0 listed the complete `data_home_from` selection, including
the function-return replacement and both unary-expression mutations (three
total). A fresh baseline passed under the exclusive mutation lock with the
owning unit test selected. All three were caught: return replacement fails the
absolute-XDG case, removing the XDG absolute-path negation fails the relative
fallback case, and removing the HOME absolute-path negation fails the expected
relative-HOME error. There were zero missed, unviable or timed-out mutants and
no exclusions. With a separate final target, `make test` passes (44 unit, 28
integration and four terminal tests; two hardware tests ignored, no optional
skips) and `make lint` passes with warnings denied. No timing claim is made.
Other filesystem regions remain open, so DSLP-4 remains open.

## Private-file admission Scenario

On macOS arm64, base `bf7a1eb9c3e55f25ce3f92e9773fb6b11af19fee`, the
private-file tests use owned TMPDIR fixtures for literal bytes at the limit,
empty, missing and oversized files, symlink, hard link, directory and FIFO
refusals, and repair from 0666 to 0600. An owned file's synthetic `Stat`
checks foreign-owner refusal. Production-used metadata and bounded-reader
helpers allow deterministic witnesses for a stream growing or shrinking after
metadata inspection, preserving the original syscall order, preallocation,
flags, read limit and errors. The FIFO check uses a deadline and reaps its
child if opening blocks. No timing or memory equivalence is claimed.

Removing the post-read size check made the growth assertion fail with four
bytes returned; replacing chmod's target with 0666 made the repair assertion
fail with the permissions error. Both hand faults were restored. The first
mutation run had 28 caught, four missed, one unviable and one timeout: the
FIFO-open flag mutant blocked the old in-process fixture. The bounded child
and the shrinking-stream witness resolved those gaps.

Cargo-mutants 27.1.0 generated 34 return and expression mutants across
`ensure_regular_file`, `ensure_regular_metadata`, `set_file_mode`,
`read_private_file`, and `read_private_contents`. The fresh baseline ran four
owning tests. The final run exited 2: 30 caught, three missed, one unviable,
zero timeouts or untested. All caught logs were inspected and failed the new
assertions, including the FIFO deadline. The three misses replace `|` by `^`
in the open flags: on this macOS target `RDONLY` is zero and `NOFOLLOW`,
`CLOEXEC`, and `NONBLOCK` have disjoint bits, so all three produce the same
flags. This is functional flag equivalence, not a timing or memory claim. The
unviable size-comparison mutant parses `<` after `as u64` as generic syntax
and does not compile. No exclusions were added.

With the mutation lock held and `PATH=/Users/josh/d/stuff/.work/tools/bin:$PATH`,
`TMPDIR=$PWD/.work/tmp`, `RUSTC_WRAPPER=kache`, `CARGO_BUILD_JOBS=1`,
`RUST_TEST_THREADS=1`, and `CARGO_TARGET_DIR=$PWD/.work/target-private-mutants`:

```sh
timeout 1200 sh -c 'while ! mkdir /Users/josh/d/stuff/.work/tmp/mutation.lock 2>/dev/null; do sleep 2; done; trap "rmdir /Users/josh/d/stuff/.work/tmp/mutation.lock" EXIT HUP INT TERM; cpu-guard --cores 2 -- cargo mutants --gitignore true --file src/macos.rs --re "(in (ensure_regular_file|ensure_regular_metadata|set_file_mode|read_private_file|read_private_contents)|replace (ensure_regular_file|ensure_regular_metadata|set_file_mode|read_private_file|read_private_contents) ->)" --baseline run --timeout 60 --build-timeout 300 --jobs 1 --no-shuffle --output .work/private-mutants-final --cargo-test-arg=--bin --cargo-test-arg=vault --cargo-test-arg=macos::tests::private_file'
```

With the same environment except the separate
`CARGO_TARGET_DIR=$PWD/.work/target-private-final`, `cpu-guard --cores 2 --
make test` and `cpu-guard --cores 2 -- make lint` both exit 0. The suite has
50 unit, 28 integration and four terminal tests passed, two hardware tests
ignored, and zero optional skips. The original stopped 232-case run remains
102 caught, 65 missed, six unviable and 59 untested; filename and data-home
results are unchanged. Other regions, coverage and platform evidence remain
open; DSLP-4 remains open.
