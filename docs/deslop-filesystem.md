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
metadata inspection, preserving the original file-operation order, preallocation,
flags, read limit and errors. The FIFO check uses a deadline and reaps its
child if opening blocks, including during unwinding. No timing or memory
equivalence is claimed.

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
zero timeouts or untested. Parent verification after adding unwind cleanup
repeated all 34 with the same classes in `.work/private-mutants-parent`.
All caught logs were inspected and failed the new
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

## Reconciliation with the stopped run

The saved 65 misses were matched against current outcomes by mutation site,
operator and function, following the unchanged expressions into the two
extracted private-file helpers. The filename names match exactly, including
their original locations. The private-file sites are the two admission/mode
return replacements, six open-flag operators, missing-file comparison, three
metadata-size decisions and two bounded-read arithmetic operators.

| Original missed region | Now caught | Equivalent | Still unresolved |
| --- | ---: | ---: | ---: |
| Directory policy | 7 | 0 | 0 |
| Filename validators and decoder | 6 | 4 | 0 |
| Private-file admission/read | 11 | 3 | 0 |
| Directory opening | 9 | 7 | 0 |
| Lock and mode repair | 5 | 4 | 0 |
| Other regions | 0 | 0 | 9 |

The two additional validator catches are `validate_name` returning `Ok(())`
and `validate_store_name` changing `>` to `>=`. The six original hex-digit
identities are `-` to `+` and `/` at 1171:34, `+` to `-` and `*` at
1172:41, and `-` to `+` and `/` at 1172:34; only `+` to `*` is unviable.
The four decoder and three private-file flag equivalences have the arguments above;
the seven directory-opening flag equivalences are justified below. This
resolves 56 saved misses (38 caught and 18 equivalent); it does not rewrite the historical raw run
(102 caught, 65 missed, six unviable, 59 untested). The nine remaining saved misses still need reconciliation. Six originally untested
hex-digit identities also match the complete filename selection: five caught
and one unviable. The shared mode return replacement also matches and is
unviable, leaving 52 originally untested identities unreconciled.
The private archive is retained at the canonical repository's
`.git/preserved-checkouts/d-overlap-20261116T185745-linear/`; its receipt
locates the original `mutants-macos-filesystem-final` inventory and outcomes.
Reproduce current qualification with the complete Scenario commands, rather
than restarting the stopped integration-filtering driver.

## Directory opening Scenario

On macOS arm64, base `a447af3875897205f3ec84c0ecc93158dec64529`,
the owned `directory_open_policy_and_descriptors` fixture checks missing lookup
and nested creation, descriptor identity and close-on-exec, relative, parent and
root paths, symlinks, regular files, unsafe parent and final modes, and the
trusted-parent wrapper. A read-only open of root-owned `/Users` as the final
component proves the final ownership check; no contents are read. The
production-used metadata helper preserves the open, fstat, type and owner
ordering and tests foreign ownership using synthetic metadata. O_DIRECTORY
prevents ordinary non-directory descriptors reaching the post-open type checks;
the helper additionally tests the type check directly. No chown or real user
data is involved.

Cargo-mutants 27.1.0 generated 28 return and expression mutants in
`open_data_home`, `open_directory_at`, `ensure_trusted_parent`, and
`ensure_opened_directory_metadata`. A fresh baseline selected one owning test.
The final run exited 2 with 19 caught, seven missed, two unviable and no
timeouts. All caught and survivor logs were inspected. The seven survivors are
four XOR flag substitutions in `open_data_home` and three in `open_directory_at`:
macOS RDONLY is zero, and DIRECTORY, NOFOLLOW, NONBLOCK and CLOEXEC are disjoint
bits, so each substituted expression produces identical flags. This is
functional flag equivalence only, not a timing or memory claim. The two
unviable return replacements require `File: Default`. The index `+` to `-`
mutant panics on unsigned underflow; `+` to `*` fails the `/Users` final-owner
assertion. All 16 original misses map by function and expression: nine caught
(two data-home flag ANDs, two create guards, index multiplication, trusted
parent return, and three directory-at flag ANDs), seven equivalent XORs.
No exclusions were added. The initial complete run had 17 caught, nine missed
and two unviable; its two additional AND survivors motivated exact ENOTDIR
assertions and it is superseded.

With `PATH=/Users/josh/d/stuff/.work/tools/bin:$PATH`, `TMPDIR=$PWD/.work/tmp`,
`RUSTC_WRAPPER=kache`, `CARGO_BUILD_JOBS=1`, `RUST_TEST_THREADS=1`, and
`CARGO_TARGET_DIR=$PWD/.work/target-directory-mutants`, the lock-protected run was:

```sh
timeout -k 5 1200 sh -c 'n=0; until mkdir /Users/josh/d/stuff/.work/tmp/mutation.lock 2>/dev/null; do n=$((n+1)); [ "$n" -lt 150 ] || exit 73; sleep 2; done; trap "rmdir /Users/josh/d/stuff/.work/tmp/mutation.lock" EXIT HUP INT TERM; cpu-guard --cores 2 -- cargo mutants --gitignore true --file src/macos.rs --re "(in (open_data_home|open_directory_at|ensure_trusted_parent|ensure_opened_directory_metadata)|replace (open_data_home|open_directory_at|ensure_trusted_parent|ensure_opened_directory_metadata) ->)" --baseline run --timeout 60 --build-timeout 300 --jobs 1 --no-shuffle --output .work/directory-mutants-final --cargo-test-arg=--bin --cargo-test-arg=vault --cargo-test-arg=macos::tests::directory_open'
```

A hand fault replacing the create guard with `true` made the owning test fail
on the missing read-only lookup (exit 101); restoring the source made the
same test pass (exit 0). Mutation also confirms the final-index fault fails
the intended root-owned-final assertion. With the same environment and
`CARGO_TARGET_DIR=$PWD/.work/target-directory-final`, `cpu-guard --cores 2 --
make test` and `cpu-guard --cores 2 -- make lint` exit 0: 51 unit, 28
integration and four terminal tests pass, two hardware tests are ignored, and
zero optional checks skip. An additional child test invocation is reported in
the test output.

With `CARGO_TARGET_DIR=$PWD/.work/target-directory-coverage` and the same
lock/timeout wrapper, `cpu-guard --cores 2 -- make coverage` exits 0. Its
partial aggregate was 2377/3110 lines and 291/446 branches, versus the
parent's partial base 2314/3058 and 284/444. Both omitted eight subprocess
profiles because two environment-isolating fixtures cleared
`LLVM_PROFILE_FILE`; the corrected collection below supersedes them. The
post-open non-directory branch in `open_data_home` remains kernel-unreachable
for a successful `O_DIRECTORY` open. The equivalent post-open checks in
`open_directory_at` are exercised with synthetic metadata through its
production helper; kernel refusal remains separately witnessed. Error and
race paths beyond these fixtures, Linux behavior and Secure Enclave hardware
remain unverified by this macOS slice. No coverage threshold or timing claim
is made. The 20 other saved misses and 59 previously untested identities
remain unresolved; DSLP-4 remains open.

## Subprocess coverage collection

Two integration fixtures deliberately clear the child environment. They now
forward only `LLVM_PROFILE_FILE` when instrumentation supplies it, keeping
the standalone help and filesystem-listing inputs isolated. Before the fix,
eight child profiles escaped to default files in the checkout and were not
merged. Afterward, none escape; all 51 unit, 28 integration and four terminal
tests pass, with two hardware tests ignored and zero optional skips. Ordinary
native tests and lint also pass. This changes test instrumentation only.

With cargo-llvm-cov 0.9.1, the pinned nightly, macOS ARM64, default features,
the shared lock and the environment above, `CARGO_TARGET_DIR=$PWD/.work/target-coverage-private`
and `cpu-guard --cores 2 -- make coverage` exit 0. The corrected report has
2,386/3,110 lines and 292/446 branches, including repeated cfg and
instantiations. Export it with `cargo llvm-cov report --branch --json
--output-path .work/tmp/coverage-integrated.json` under the same lock.

The report's four executable native modules are `main.rs`, `macos.rs`,
`secure_enclave.rs` and `store.rs`; `linux.rs` is not compiled on macOS.
Unrun Secure Enclave unwrap/recovery and hardware behavior remain separate
from synthetic metadata policy. At that point the unresolved saved filesystem misses included lock creation, mode repair, sidecar/identity parsing and store
bootstrap. OS-error and race branches outside the owned fixtures still need
witnesses or explicit dispositions. Source-coordinate duplicates must be
merged when locating an unrun decision. These counts are not a threshold,
a fixed-scope before/after detection score or a timing claim; DSLP-4 remains
open.


## Lock and mode repair Scenario

On macOS arm64 at base `62038b2a6b0c0b80f7d700e1dff3ed088ac8c99b`,
owned TMPDIR fixtures check creation of `.vault.lock` at 0600, reopening
without truncation, read/write access, CLOEXEC and NONBLOCK, permission repair,
and hard-link, symlink and directory refusals with causal errors and positive
controls. The descriptor alone does not lock: callers perform flock. An owned
directory is repaired to 0700; a file is refused and synthetic foreign-owner
metadata exercises the production admission helper without chown. A bound,
unconnected owned UnixListener socket is repaired from 0666 to 0600, and a
missing parent exercises chmod failure. Literal disk permissions exercise mode
conversion through its real lock and directory callers. The private helper
extraction in `8a7ba49` preserves fstat, admission, chmod and verification
order and error text. A hand fault changing lock chmod to 0666 fails the 0600
assertion (exit 101); restoring the source passes.

With `PATH=/Users/josh/d/stuff/.work/tools/bin:$PATH`, `TMPDIR=$PWD/.work/tmp`,
`RUSTC_WRAPPER=kache`, `CARGO_BUILD_JOBS=1`, `RUST_TEST_THREADS=1`, and
`CARGO_TARGET_DIR=$PWD/.work/target-lock-mutants`, the complete selection ran:

```sh
timeout -k 5 1200 sh -c 'n=0; until mkdir /Users/josh/d/stuff/.work/tmp/mutation.lock 2>/dev/null; do n=$((n+1)); [ "$n" -lt 150 ] || exit 73; sleep 2; done; trap "rmdir /Users/josh/d/stuff/.work/tmp/mutation.lock" EXIT HUP INT TERM; cpu-guard --cores 2 -- cargo mutants --gitignore true --file src/macos.rs --re "(in (open_lock_file|set_directory_mode|ensure_owned_directory_metadata|set_socket_permissions|mode)|replace (open_lock_file|set_directory_mode|ensure_owned_directory_metadata|set_socket_permissions|mode) ->)" --baseline run --timeout 60 --build-timeout 300 --jobs 1 --no-shuffle --output .work/lock-mutants-final --cargo-test-arg=--bin --cargo-test-arg=vault --cargo-test-arg=macos::tests::lock_mode'
```

The fresh baseline selected two tests. The original `.work/lock-mutants-final`
run and a repeat in `.work/lock-mutants-confirm` have identical identities
and classes; the repeat confirmed raw exit 2. All 19 generated identities ran: 13
caught, four missed, two unviable, none timed out or untested (tool exit 2).
All logs were inspected. Each caught mutant failed an owning assertion; four
misses replace OR with XOR among RDWR, CREATE, NOFOLLOW, NONBLOCK and CLOEXEC,
which have disjoint bits on this target: RDWR 0x2, CREATE 0x200,
NOFOLLOW 0x100, NONBLOCK 0x4 and CLOEXEC 0x1000000 (the installed libc
BSD and Apple constants). Thus the flags and functional result are identical. No timing or memory equivalence is asserted. The two unviable
return replacements require `File: Default` and `Mode: Default`, respectively.
The nine original misses in this region match five caught and four equivalent
mutants, including the extracted admission expression. The original untested
`mode` return replacement matches the unviable case. No exclusion was added;
raw historical counts remain 102 caught, 65 missed, six unviable and 59
untested. Parent integration reran corrected native coverage: 2454/3173 lines
and 295/446 branches, with no escaped child profiles. Other regions, Linux,
hardware and cost remain open, and DSLP-4 remains open.

With the same environment and `CARGO_TARGET_DIR=$PWD/.work/target-lock-final`,
`cpu-guard --cores 2 -- make test` and `cpu-guard --cores 2 -- make lint`
both exit 0. The suite reports 53 unit, 28 integration and four terminal tests
passed, two hardware tests ignored, zero optional skips, plus an isolated child
test invocation. The mutation and final-check targets are separate.

Parent integration is a fast-forward of the exact tested source, so the
worker's full ordinary test/lint receipts remain valid. The integrated owning
two-test filter and full `make coverage` also pass with the same native
53/28/4 suite, two hardware ignores and zero optional skips. Coverage uses
`.work/target-coverage-private`, distinct from both mutation and ordinary
targets. These counts locate remaining work; they do not close the quiet-host
cost or whole-step gates.
