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

## Atomic file Scenario

On macOS arm64, base `10d38f5da5155aefcc0b552058e5bf61d3901fd2`,
source candidate `726acb5e031be33f36733bc0e8d193850f1d2f67`, owned
fixtures verify missing and replacement writes, literal bytes, mode 0600,
no temporary leftovers, and symlink, directory and hard-link refusal with
objects intact. Synthetic metadata verifies foreign ownership and the type,
link-count, owner error priority. The extracted production helper preserves
that priority and the original syscalls. Private name injection checks one
collision, all 32 attempts, and a real open error. Real generated names carry
the prefix and PID and are unique; descriptors are write-only and CLOEXEC.
Cleanup preserves the primary error for unlink success and absence, and adds
the actual OS error while retaining a directory. Filename cases cover the
existing internal policy and actual names without extending it.

Hand faults skipping the hard-link guard and changing 32 attempts to 31 both
failed the intended tests (exit 101), then were restored. The extraction
moves the original three match guards into `ensure_atomic_destination_metadata`;
forcing each condition to `true` and then `false` independently produced six
more test failures (exit 101), with original source restored each time.

With cargo-mutants 27.1.0, the following uses a fresh baseline, the exclusive
lock and three selected tests. `PATH=/Users/josh/d/stuff/.work/tools/bin:$PATH`,
`TMPDIR=$PWD/.work/tmp`, `RUSTC_WRAPPER=kache`, `CARGO_BUILD_JOBS=1`,
`RUST_TEST_THREADS=1`, and `CARGO_TARGET_DIR=$PWD/.work/target-atomic-mutants`:

```sh
timeout -k 5 1200 sh -c 'n=0; until mkdir /Users/josh/d/stuff/.work/tmp/mutation.lock 2>/dev/null; do n=$((n+1)); [ "$n" -lt 150 ] || exit 73; sleep 2; done; trap "rmdir /Users/josh/d/stuff/.work/tmp/mutation.lock" EXIT HUP INT TERM; cpu-guard --cores 2 -- cargo mutants --gitignore true --file src/macos.rs --re "(in (atomic_write|ensure_atomic_destination_metadata|create_temporary_file|create_temporary_file_with|cleanup_temporary_file|validate_filename|next_temp_name)|replace (atomic_write|ensure_atomic_destination_metadata|create_temporary_file|create_temporary_file_with|cleanup_temporary_file|validate_filename|next_temp_name) ->)" --baseline run --timeout 60 --build-timeout 300 --jobs 1 --no-shuffle --output .work/atomic-mutants --cargo-test-arg=--bin --cargo-test-arg=vault --cargo-test-arg=macos::tests::atomic_file'
```

The complete 28-identity selection exits 2: 20 caught, four missed, four
unviable, zero timeouts or untested. Every caught and survivor log was
inspected. The four missed flag expressions replace OR with XOR: WRONLY 0x1,
CREATE 0x200, EXCL 0x800, NOFOLLOW 0x100, CLOEXEC 0x1000000 are disjoint
on this target, so each produces identical open flags. The four unviable
return replacements for the original wrapper and extracted helper require
`File: Default`. No exclusion was added, and no timing or memory equivalence
is claimed.

The original 31 untested identities map by expression: atomic write's return,
three guard true/false pairs and three operators are caught (six by the
restored manual injections); temporary creation's four AND flag mutations
are caught, four XOR expressions equivalent, and two wrapper return mutations
unviable; cleanup's two returns, filename's seven expressions and name
generator's two returns are caught. Thus 25 caught, four equivalent and two
unviable reconcile this slice. The generated scope additionally catches the
metadata-helper return and has two unviable name-provider-helper returns.
Historical raw counts remain 102 caught, 65 missed, six unviable and
59 untested; nine saved misses and 21 formerly untested identities remain.

Native fault-window continuation on macOS arm64, base
`f655ec01735fc23998d05d18ad1bb070c533b30f`: test source blobs
`src/macos.rs` `9ba3c2064f3efd65f98adc09c85777fa303756e5` and
`tests/atomic_fault.c` `caaabcdb2d7c671f95a5f9f9636f9cf9b3586d4f`.
The owned current-executable child loads a locally compiled DYLD interposer;
canonical fixture descriptor checks confine failures to its data root. Child
bootstrap, completion and per-call event markers prevent a missing child or
interposer from passing. The uninjected control commits literal new bytes.
Actual write, file fsync and renameatx_np failures preserve old bytes and leave
no temp; directory fsync failure reports an error after committing new bytes.
A write plus unlinkat failure reports both errors and retains the empty temp.
After file fsync and after rename, an event pauses the owned child; SIGKILL,
reap and clean retry confirm old and new states respectively, and final new
bytes. The first kill retains its fully written temp. These are process-crash
observations, not physical power-loss durability claims.

Rustix 1.1.6's Apple backend calls fsync and weakly resolves renameatx_np and
unlinkat; the actual events validate the ABI on this host. The focused command
below selected one parent test and passed; temporarily skipping cleanup made
its write case fail on the retained temp (exit 101), then was restored. No
mutation inventory was rerun: the prior 28 identities and classifications
remain unchanged. Hardware, cross-Mac recovery, other filesystem regions,
Linux and cost remain open; DSLP-4 stays open. The final ordinary target
`.work/target-atomic-fault-final` ran `cpu-guard --cores 2 -- make test`
(exit 0: 65 unit, 28 integration, four terminal; two hardware tests ignored,
zero optional skips) and `cpu-guard --cores 2 -- make lint` (exit 0), using
the same environment as below. The non-UTF-8 filename case was unrun because
this filesystem returned EILSEQ.

```sh
PATH=/Users/josh/d/stuff/.work/tools/bin:$PATH TMPDIR=$PWD/.work/tmp RUSTC_WRAPPER=kache CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1 CARGO_TARGET_DIR=$PWD/.work/target-atomic-fault cpu-guard --cores 2 -- cargo test --bin vault macos::tests::atomic_file_native_fault_windows -- --exact
```

With the same environment and `CARGO_TARGET_DIR=$PWD/.work/target-atomic-final`,
separate from mutation, `cpu-guard --cores 2 -- make test` exits 0 (56 unit,
28 integration and four terminal tests passed, two hardware tests ignored,
zero optional skips) and `cpu-guard --cores 2 -- make lint` exits 0. The unit
output also includes an isolated child invocation. No coverage rerun or
performance claim is made.

## Staging and listing Scenario

On macOS arm64, base `7db74f652af5cffc2fee21d956f1dc4dfcc091ec`,
`src/macos.rs` SHA-256 `21a77c9ffe1d21850122b29a137505d0faad6716c53dd8263c35a2beb9779675`,
the owned fixtures check literal encoded names, sorted decoded names, directory
entries, symlink admission, private staging descriptors, collision exhaustion,
and cleanup including nested-directory refusal and preservation of primary
errors. The sibling symlink target remains unchanged. The filesystem rejected
an invalid UTF-8 filename with EILSEQ; that case is explicitly unrun here.
A regular file descriptor produces a directory-read error. Concurrent replacement,
entry disappearance, individual syscall failures and other OS filesystems remain
unrun. Cleanup may remove earlier entries before refusing a nested directory;
no directory iteration order or atomic cleanup is assumed.

Changing the managed-name predicate to include symlinks regardless of the flag
made `staging_list_names_and_enumeration` fail (exit 101, unexpected `L`);
restoring it passes (exit 0). The fresh mutation baseline selected three tests.
Cargo-mutants 27.1.0 completed 19 generated return and expression mutants:
15 caught, four unviable, zero missed, timeout or untested. All caught logs
were inspected and fail the fixture assertions; the four unviable replacements
require `File: Default` and fail compilation. No exclusions were used. The
first command's outer exit status was not captured, so that proof was
incomplete. Parent completion repeated the same 19 identities with a fresh
baseline and saved outer exit 0 in `.work/tmp/staging-parent.exit`; all
classes match, and every caught log fails a staging/listing assertion. The
new outcomes are in `.work/staging-parent/mutants.out`; the first raw run is
retained separately.

The 17 original untested identities map by function and expression to 15 caught
(remove-staging two, remove-entries one, cleanup-failure two, managed-names
five, directory-names five) and two unviable staging-creation return replacements.
The extracted helper adds two unviable return replacements. The historical
232-case result remains unchanged. Four original untested identities in
`format_secure_enclave_error` and `io_error`, nine saved misses, hardware and
other platform and race evidence remain open; DSLP-4 remains open.

With PATH prefixed by `/Users/josh/d/stuff/.work/tools/bin`, TMPDIR set to
`$PWD/.work/tmp`, RUSTC_WRAPPER=kache, CARGO_BUILD_JOBS=1 and
RUST_TEST_THREADS=1, the mutation command was:

```sh
CARGO_TARGET_DIR=$PWD/.work/target-staging-mutants timeout -k 5 1200 sh -c 'while ! mkdir /Users/josh/d/stuff/.work/tmp/mutation.lock 2>/dev/null; do sleep 2; done; trap "rmdir /Users/josh/d/stuff/.work/tmp/mutation.lock" EXIT; cpu-guard --cores 2 -- cargo mutants --gitignore true --file src/macos.rs --re "(in (directory_names|managed_names|create_staging_directory|create_staging_directory_with|remove_directory_entries|remove_staging_directory|cleanup_failure)|replace (directory_names|managed_names|create_staging_directory|create_staging_directory_with|remove_directory_entries|remove_staging_directory|cleanup_failure) ->)" --baseline run --timeout 60 --build-timeout 300 --jobs 1 --no-shuffle --output .work/staging-mutants --cargo-test-arg=--bin --cargo-test-arg=vault --cargo-test-arg=macos::tests::staging_list'
```

With the separate `CARGO_TARGET_DIR=$PWD/.work/target-staging-final`,
`cpu-guard --cores 2 -- make test` and `cpu-guard --cores 2 -- make lint`
exit 0. Tests report 59 unit, 28 integration and four terminal passes, two
hardware ignores and zero named optional checks skipped. The unrepresentable
non-UTF-8 filename branch is separately unrun. No coverage or performance
claim is made.

### Identity input scenario

On macOS arm64, base `9dbf993cd8de9d9a98ba1a2efc194af142b797a6`, three `macos::tests::identity_input` tests cover all prompt literals, a public age test identity and invalid UTF-8, malformed, single CR, single LF and CRLF inputs, sidecar read/validation, and literal error formats. The fixture is structurally valid only: Swift `decodeSidecar` checks magic, version and lengths, not cryptographic validity. No hardware authentication, wrap or unwrap is exercised. A hand fault changing the Create prompt to `wrong prompt` failed the focused test (exit 101, literal assertion); restoration passed the three tests (exit 0). `cargo test --bin vault identity_input -- --list` listed exactly those three.

With `PATH=/Users/josh/d/stuff/.work/tools/bin:$PATH`, `TMPDIR=$PWD/.work/tmp`, `RUSTC_WRAPPER=kache`, `CARGO_BUILD_JOBS=1`, `RUST_TEST_THREADS=1`, and `CARGO_TARGET_DIR=$PWD/.work/target-identity-mutants`, cargo-mutants 27.1.0 ran the complete 11-item selection, including returns and expressions:

```sh
timeout -k 5 1200 sh -c 'n=0; until mkdir /Users/josh/d/stuff/.work/tmp/mutation.lock 2>/dev/null; do n=$((n+1)); [ "$n" -lt 150 ] || exit 73; sleep 2; done; trap "rmdir /Users/josh/d/stuff/.work/tmp/mutation.lock" EXIT; cpu-guard --cores 2 -- cargo mutants --in-place --file src/macos.rs --re "(in (RecoveryPrompt::prompt|identity_from_bytes|read_secure_enclave_sidecar|format_secure_enclave_error|io_error)|replace (RecoveryPrompt::prompt|identity_from_bytes|read_secure_enclave_sidecar|format_secure_enclave_error|io_error) ->)" --baseline run --timeout 60 --build-timeout 300 --no-shuffle --output .work/identity-mutants --cargo-test-arg=--bin --cargo-test-arg=vault --cargo-test-arg=macos::tests::identity_input'
```

Fresh baseline passed; 9 caught by assertions, 1 missed, 1 unviable, no timeouts; outer exit 2 (survivor), 22 seconds. `identity_from_bytes` replacement with `Default::default()` cannot compile because the age identity has no `Default`. The survivor, `||` to `&&`, is equivalent under pinned age 0.13.0 / age-core 0.13.0 and bech32 0.12.0: age's `native/x25519.rs` `FromStr` calls age-core `primitives.rs` `bech32_decode`, which uses `CheckedHrpstring::new::<Bech32Long>`; bech32 `primitives/decode.rs` `check_characters` rejects CR/LF in the data alphabet, and `primitives/hrp.rs` `Hrp::parse` rejects bytes outside 33..=126 in the HRP. Missing separator is also rejected. Both paths map parsing errors to the same fixed vault error. Single CR and LF appended to the known valid control are tested even on the mutant. This is functional equivalence, not a claim about zeroization or performance.

Reconciliation by original inventory identity, not fresh count subtraction: original prompt return mutants (2) and sidecar return mutants (3) now caught; original identity boolean mutant (1) equivalent. The four original untested formatting returns (two per helper) now caught. The original identity `Default` return was already unviable and remains so. From the prior 65 misses, 62 are resolved (43 caught, 19 equivalent), three hardware-sensitive initialization/staging mutants remain. From the original 59 untested, all are resolved (49 caught, 4 equivalent, 6 unviable). The original raw 102 caught / 65 missed / 6 unviable / 59 untested stays unchanged. DSLP-4 remains open; hardware/bootstrap, cross-Mac recovery and other scopes remain unverified.

Final ordinary target was separate from mutation. With the same environment above except `CARGO_TARGET_DIR=$PWD/.work/target-identity-final`, `cpu-guard --cores 2 -- make test` and `cpu-guard --cores 2 -- make lint` both exited 0. Test results: 62 unit passed, 2 hardware tests ignored; 28 integration and 4 terminal passed; zero named optional skips. A separate non-UTF-8 filename branch was unrun because the filesystem returned EILSEQ. Cargo.lock SHA-256 `7acf23752d82021d8945421b4ef5f3080d3718ef1bf7ef3e03b83e422ebbca67`; Swift source SHA-256 `c42c7f84d1a2a894d4dbbe549740ad5edd233c4b1c5629b78c940c91d4190b43`.

### Bootstrap domain scenario

On macOS arm64, base `f82546e15860197a2d893daabcff1cf2d8075dbe`, production refactor `1cd8fa8`, and final `src/macos.rs` SHA-256 `cc619164690ac1a1bbdebf3416c7d2348fc89a90f8c65b520f30ea605868bedc`, two `macos::tests::bootstrap_domain` tests run real filesystem operations and age encryption around a private wrapping callback. Production supplies `wrap_identity`; the fixture supplies a structurally framed sidecar or a real `SecureEnclaveError`, never device authentication. The callback checks that recovery and recipient exist and agree with the provided identity and binding before the sidecar or secrets directory exists. The published directory and files have exact names and 0700/0600 modes; recovery rejects the wrong passphrase and decrypts the literal value using the identity matching the recipient. Files contain neither that literal nor the recovered private key. A second initialization refuses replacement and leaves the first bytes unchanged; a wrap refusal preserves its error and removes the stage. The original entry point also rejects a regular-file directory descriptor before hardware. A hand fault changing `verified != value` to `==` made the focused test fail with encrypted-store verification error (exit 101); the comparison was restored.

With `PATH=/Users/josh/d/stuff/.work/tools/bin:$PATH`, `TMPDIR=$PWD/.work/tmp`, `RUSTC_WRAPPER=kache`, `CARGO_BUILD_JOBS=1`, `RUST_TEST_THREADS=1`, and `CARGO_TARGET_DIR=$PWD/.work/target-bootstrap-mutants`, cargo-mutants 27.1.0 listed the complete four return/expression mutants in `initialize_store`, `initialize_store_with`, and `populate_staging_directory`. The fresh baseline ran two tests. The following command exited 0: four caught, zero missed, unviable or timed out. Caught logs show the original entry-point return failed the invalid-descriptor refusal, the helper and population returns failed the wrapping error and publication witnesses, and the comparison flip failed the verification witness.

```sh
timeout -k 5 1200 sh -c 'n=0; until mkdir /Users/josh/d/stuff/.work/tmp/mutation.lock 2>/dev/null; do n=$((n+1)); [ "$n" -lt 150 ] || exit 73; sleep 2; done; trap "rmdir /Users/josh/d/stuff/.work/tmp/mutation.lock" EXIT; cpu-guard --cores 2 -- cargo mutants --in-place --file src/macos.rs --re "(in (initialize_store|initialize_store_with|populate_staging_directory)|replace (initialize_store|initialize_store_with|populate_staging_directory) ->)" --baseline run --timeout 60 --build-timeout 300 --no-shuffle --output .work/bootstrap-mutants-verified --cargo-test-arg=--bin --cargo-test-arg=vault --cargo-test-arg=macos::tests::bootstrap_domain'
```

The three saved original misses map by site to the entry-point return, population return, and flipped verification comparison, all caught. All 65 original misses are thus reconciled: 46 caught and 19 equivalent; all 59 original untested remain reconciled as 49 caught, four equivalent and six unviable. Historical raw counts remain 102 caught, 65 missed, six unviable and 59 untested.

The unrun crypto error branches are constrained by the caller and pinned age implementation: `set_secret_at` validates the name and 16 MiB limit before initialization; initialization validates UTF-8; population generates the identity and derives its recipient, encrypts into a fresh in-memory vector, then decrypts those exact bytes with that same identity. In age 0.13.0 `simple.rs`, encryption uses one recipient and a `Vec` writer; `native/x25519.rs` supplies one valid stanza with empty labels, and `protocol.rs` writes the header and payload to that vector. Under normal successful RNG and allocation, those paired keys and unmodified in-memory ciphertext exclude missing-recipient, I/O, authentication, size and UTF-8 failures in that verification. RNG failure or broken crypto implementation is not simulated. These are domain witnesses, not proof of hardware binding, real cold-store acceptance, cross-Mac recovery, injected fsync/rename failures, process-crash windows, or power-loss durability. The later atomic file continuation above exercises injected syscall and process-crash windows without establishing power-loss durability. DSLP-4 remains open.

Final ordinary verification used the same environment with `CARGO_TARGET_DIR=$PWD/.work/target-bootstrap-final`: `cpu-guard --cores 2 -- make test` and `cpu-guard --cores 2 -- make lint` each exited 0. The test run reported 64 unit passes, two hardware ignores, 28 integration passes, four terminal passes, and zero named optional skips. The non-UTF-8 filename case was unrun because the filesystem returned EILSEQ. An earlier lint run exited 2 on two needless test callback borrows; those were removed before the final mutation and ordinary runs. Cargo.lock SHA-256 `7acf23752d82021d8945421b4ef5f3080d3718ef1bf7ef3e03b83e422ebbca67`; Swift source SHA-256 `c42c7f84d1a2a894d4dbbe549740ad5edd233c4b1c5629b78c940c91d4190b43`.

Parent completion replaces computed filename/binding expectations with literal
`44554d4d59.age` and the documented binding prefix. The same four generated
mutants remain caught in a fresh `.work/bootstrap-parent` run, exit 0.
The separate ordinary target again passes the full 64/28/4 suite and lint.

## Native qualification at 6856

On macOS arm64, source `6856af3421b82cfb7ff6bf0d5b35eede660798aa`
passes fresh native coverage and the bounded two-core test-cost gate against
`47dfb47ec6a1f9de2ad2d0619d5fead9bc6d8d2d`. Rust is
`1.102.0-nightly (5b7b37aef 2026-11-08)`, LLVM 23.1.5; cargo-llvm-cov is 0.9.1.

Use short isolated worktree names: `.work/wt/b` for baseline and `.work/wt/q`
for current, both under the canonical repository. The longer initial names
exceeded macOS socket path limits in otherwise unchanged fixtures. Moving
them required fresh build targets: relocated artifacts retained embedded
old source and executable paths. Both failed attempts are excluded; no
production or fixture change was needed.

From each worktree root, create `.work/tmp` and use:

```sh
export TMPDIR=$PWD/.work/tmp RUSTC_WRAPPER=kache CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=2
export CARGO_TARGET_DIR=$PWD/.work/target-qualification-short
cpu-guard --cores 2 -- make test
```

Warm the targets outside measurement, then alternate baseline/current three
times. For every sample run `perf-gate-ready`, immediately time
`/usr/bin/time -p cpu-guard --cores 2 -- make test`, then immediately run
`perf-gate-ready -1`. All six pre/test/post exit triples are 0; the controller
exits 0. No external service was stopped. Same two-core cap, two test threads,
compiler, default features and test command apply to both revisions.

| Revision | Wall seconds, three runs | Median | User CPU seconds |
| --- | --- | ---: | --- |
| Baseline | 6.40, 6.42, 6.41 | 6.41 | 6.53, 6.61, 6.69 |
| Current | 23.18, 24.24, 24.27 | 24.24 | 38.28, 39.33, 40.24 |

The 17.83-second median increase is within the 30-second allowance; it is not
within 20%. New real cryptographic and filesystem witnesses add work, and no
runtime speedup is claimed. Exploratory serial runs were about 8/40 seconds,
just beyond the allowance; their controller was edited while running and
exited 1 after its samples, so they are not the accepted timing receipt. The
final fixed script was syntax-checked before collecting the table above.
Mutation runs continue to use one test thread. These costs are not compared
to older six-core/default-parallel measurements.

The current ordinary and instrumented suites each pass 65 unit, 28 integration
and four terminal tests, with two hardware ignores and zero named optional
skips. The non-UTF-8 filename branch remains unrun on EILSEQ. Native lint
passes with the ordinary target, exit 0.

Under the shared atomic mutation lock, use a separate
`CARGO_TARGET_DIR=$PWD/.work/target-qualification-coverage`, the environment
above, and `cpu-guard --cores 2 -- make coverage`; exit 0. Export with
`cargo llvm-cov report --branch --json --output-path .work/qualification/coverage.json`.
The report covers four first-party Rust files: 2,970/3,571 lines and 361/486
branches. It includes inline tests; it is not a production-only percentage.
No orphan `.profraw` files remain at the worktree root. Linux and Swift are
outside this native Rust report.

Remaining production decision regions include secret-operation paths requiring
a real hardware identity, Secure Enclave error categories, cache forwarding
and error replies, and terminal signal setup/restoration failures. Existing
in-memory crypto impossibility arguments and metadata guard equivalences
remain local dispositions, not blanket coverage exemptions. Store branches
are 20/20; macOS is 240/300, main 89/136, Secure Enclave 12/30. Signal error
witnesses are the next bounded local slice. Cross-Mac recovery and physical
power-loss behavior remain unverified.

CI at this head passes macOS, both Linux musl suites and lint, but the mutation
lane fails its twenty-minute budget. Its Linux job selects macOS-only changed
functions and reports them missed while that module is not compiled; the
51-case store phase passes (45 caught, six unviable). These Linux macOS misses
do not overturn the native component receipts and do not qualify CI. The
gate needs platform-aware coverage and a measured bounded recipe before
DSLP-4 can close; neither exclusions nor a larger timeout substitute for it.

Source hashes: `Cargo.lock`
`7acf23752d82021d8945421b4ef5f3080d3718ef1bf7ef3e03b83e422ebbca67`,
`src/macos.rs` `03869358e65e0720f143c7aca98acd446982c799bf81cb9d244eca9e6e7ae48b`,
`src/main.rs` `c88fcde17b60fbcfbd294038308d28a922e58fc25ba6a076d908b996c8324af6`,
`src/store.rs` `2011b7c805545c9ca93dedf2196988b0ea2322621e30ca71730bd63c5aad86ce`,
`src/secure_enclave.rs` `6d04f2d4fd6c98b2e120c50233a3be607384d15108a5971d345bfb6bf3f0f0db`.
