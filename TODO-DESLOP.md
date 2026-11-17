Prefix: DSLP
Next: 9

Deslop campaign backlog ([plan](https://github.com/laputa-systems/stuff/blob/main/docs/campaigns/deslop.md), tier A). One agent works this file with the `deslop` skill: take the lowest-numbered open ticket whose area does not start with `Needs owner ·`. After DSLP-5, work the open P1 and P2 findings, then fill in `## Report` below.

Atomic file continuation: 31 formerly untested identities reconcile to 25
caught, four equivalent flag expressions and two unviable; six moved guard
mutations were injected separately. OS fault windows and other regions remain
open. See [filesystem evidence](docs/deslop-filesystem.md#atomic-file-scenario).

Lock and mode continuation: the complete 19-mutant selection has 13 caught,
four equivalent flag expressions and two unviable. Nine saved misses map to
five caught and four equivalent; DSLP-4 remains open. See
[filesystem evidence](docs/deslop-filesystem.md#lock-and-mode-repair-scenario).

Directory-opening continuation: the complete 28-mutant selection has 19
caught, seven equivalent flag expressions and two unviable. The 16 saved
misses map to nine caught and seven equivalent; DSLP-4 remains open. See
[filesystem evidence](docs/deslop-filesystem.md#directory-opening-scenario).

Private-file continuation: owned fixture and synthetic metadata witnesses cover
admission, mode repair and post-metadata growth; the complete 34-mutant slice
has 30 caught, three equivalent flag expressions and one unviable. Full native
checks pass with two hardware tests ignored. The broader DSLP-4 remains open;
see [filesystem evidence](docs/deslop-filesystem.md#private-file-admission-scenario).

## Report

Current native coverage includes the environment-isolated child profiles:
2,454/3,173 lines and 295/446 branches after lock/mode integration. Eight profiles were previously omitted
when two fixtures cleared LLVM's path; those partial reports are superseded.
The current filesystem reconciliation resolves 56 saved misses (38 caught,
18 equivalent), leaving nine unresolved misses. Atomic-file reconciliation
resolves 31 more original untested identities (25 caught, four equivalent,
two unviable), leaving 21 originally untested identities.
Hardware/Linux and unrelated error/race decisions remain open;
see [filesystem evidence](docs/deslop-filesystem.md#subprocess-coverage-collection).

Ground: base `ca93f9dc1f3b2f74ca52915a31b54c324a25af06`; macOS arm64, Rust nightly 1.102.0, `cpu-guard --cores 6`: fresh-target `make test` 15.23s, warm 4.43s, `make lint` 9.80s; all exit 0. Tests: 56 passed, two hardware authentication tests ignored. No vendored source trees found. No performance workload exists; no established user-visible performance gate. No runtime code changed.

PR CI builds Linux musl images and runs `make test-ci`; it has no macOS lane, so macOS and Secure Enclave tests do not run there. Its image does not install rage 0.12.1, so the Linux interoperability test returns early; keyring checks can also return early when the kernel cache is unavailable. Actual CI execution and keyring availability are unverified locally. Open fleet lint findings (linux-musl-toolchain 3, laputa-rustix 2, binary-release-static 1, make-clean-target 1, owned-tool-support 1, registry-sources 1) remain fleet-rule work.

Types: 422 escape-hatch lines before and after (first-party Rust including build.rs). Findings below are distinct diagnostics on macOS arm64 / Linux arm64 musl; duplicate bin/test diagnostics excluded. Real = demonstrated defect; removable = possible escape-hatch deletion; FP = intentional or non-defect. No new setting met the adoption rule; existing profile retained.

| Setting | Findings macOS / Linux | Real | Removable | FP macOS / Linux | Decision |
| --- | ---: | ---: | ---: | ---: | --- |
| unsafe_code | 23 / 25 | 0 | 0 | 23 / 25 | Reject: FFI |
| wildcard_enum_match_arm | 0 / 0 | 0 | 0 | 0 / 0 | Reject: no witness |
| match_wildcard_for_single_variants | 0 / 0 | 0 | 0 | 0 / 0 | Reject: no witness |
| cast_possible_truncation | 5 / 4 | 0 | 0 | 5 / 4 | Reject: bounded or intentional casts |
| cast_sign_loss | 5 / 5 | 0 | 0 | 5 / 5 | Reject: bounded or intentional casts |
| unwrap_used | 0 / 0 | 0 | 0 | 0 / 0 | Reject: no witness |
| expect_used | 6 / 6 | 0 | 1 / 1 | 5 / 5 | Reject: too many false positives |
| redundant_clone | 0 / 0 | 0 | 0 | 0 / 0 | Reject: no witness |
| needless_pass_by_value | 4 / 3 | 0 | 0 | 4 / 3 | Reject: ownership and callbacks |

Tests (in progress): macOS arm64, base `47dfb47ec6a1f9de2ad2d0619d5fead9bc6d8d2d`; line/branch coverage before 1596/2639 and 192/422, intermediate 1627/2665 and 199/422. Store mutation (51 listed): before 18 caught, 27 missed, 6 unviable in 102.66s; intermediate 37 caught, 8 platform-unrun, 6 unviable in 231.22s. No exclusions. The 8 are Linux-only `validate_name`; the six shared-code survivors were caught by size-boundary tests. Exec/terminal selection (61): before 39 caught, 9 missed, 6 unviable, 7 timeouts in 434.97s; after 50 caught, 2 missed, 6 unviable, 3 unconfirmed timeouts in 392.13s. Timeout confirmation, macOS cache scope, final store mutation and final coverage remain pending. Two warm tests passed under host contention in 14.64s and 15.55s; their timing is not an uncontended comparison. DSLP-8 records the stale-socket race. DSLP-4 remains open.

Tests continuation: the three remaining exec/terminal timeouts were confirmed at 180s; the two misses are signal-handler error/cleanup paths without a host witness. The macOS selection had 81 mutants before changes (39 caught, 24 missed, 18 unviable in 370.50s); after focused tests and two equivalent age ciphertext-size exclusions, 79 ran (56 caught, 5 missed, 18 unviable in 390.27s). Four misses require the ignored Secure Enclave cold-cache path; a fifth accept-error path was then covered by a descriptor-limited daemon test. The final macOS rerun and its one retry both failed their unmutated baseline because that test's daemon exited before binding; the retry reported SIGABRT without stderr. The cause is unestablished and final mutation and coverage evidence is incomplete. A later store run had a false catch from a nonblocking mock-server read; that fixture was corrected, but the run cannot establish a final count. The other 636 originally listed mutants remain outside the selected scopes. DSLP-4 stays open.

Harness continuation: the accept-failure scenario now interposes only a ready
listener's `accept`, returning EMFILE without starving daemon startup of file
descriptors. It passes normally and fails when the daemon swallows the accept
error. The earlier SIGABRT's cause remains unclaimed. The stale-socket fixture
creates and closes its listener in an executed child, then waits for exit, so
concurrent forks of the test process cannot retain that listener. Native macOS
`make test lint mutants-selftest` passes, with two hardware tests ignored.

Linux ARM64 musl `make test lint` passes in the repository Docker image. Its
rage interoperability scenario executes with the checksum-pinned owned rage
0.12.1 release `0323ec863466ce8d242b27670ea6707d33f7d60c`. A missing-tool
negative control under CI fails with the required-version assertion. The two
keyring checks visibly skip because the container denies keyring syscalls;
`tests/security_linux/README.md` defines the required separate host check.
CI now includes native macOS and retains mutation artifacts.

The Linux store gate at `a0337e2` selects 51: 45 caught, six unviable, zero
missed or timed out in 808.4 seconds. A test of literal ciphertext file bounds
catches the five earlier constant survivors. The closed, unmerged control
PR #31 at `e00a9c1` deletes a real limit test and adds a reachable uncovered
validation branch: ordinary checks pass, but mutation reports 55 selected,
37 caught, 12 missed and six unviable. No control code is in this candidate.

The earlier attribution of four cache survivors to hardware authentication
was too broad. `tests/cache_spawn.rs` includes the actual production modules
in a disposable process, starts the actual detached cache daemon and supplies
only a generated RAM identity through its private seed pipe. A structurally
valid but unusable sidecar is checked with interaction disallowed before
cached public secret operations run. No real key or authentication prompt is
used. An owned-child guard reaps the daemon, and its watchdog exits when the
recorded parent disappears, including a parent that dies before child startup.
The probe checks cache handoff, set/get/list/delete/purge, duplicate reads,
failed recovery and the literal 900-second cache TTL.

The native macOS cache/store component now selects 98 production mutants:
69 caught, 29 unviable, zero missed or timed out in about seven minutes.
The 98 are all generated mutants in the 24 selected functions, whereas the
old 79-case run selected only a subset within those functions. They are not
matched score comparisons. One newly selected seed OR/AND survivor is caught
by the process contract for either missing field; its focused mutant run
also reports one caught. The third exact exclusion is XNU's `setsid() == -1`
minus deletion: a fresh owned fork child cannot inherit its own PGID or PID 1,
so successful `setsid` returns that child's PID and both comparisons are false.
The XNU source/precondition is linked in `.cargo/mutants.toml`. There is no
accepted-risk exclusion in this component.

A full macOS-file selection contains 330 mutants and remains unqualified.
The initial run was interrupted after discovering the larger scope. A later
six-worker attempt exceeded the six-core guard; neither is a pass. A local
copy attempt also recursively copied scratch because the tool did not honor
the worktree's info-exclude. Tracked `/.work/` exclusion and explicit
`--gitignore true` prevent the demonstrated recursion. A partial regex-only
selection omitted function-return mutants and was interrupted, not accepted;
the final 98-case selection includes both return and expression operators.
Remaining filesystem, execution and platform dispositions, final coverage,
uncontended test cost and the new exact-head CI gate remain open.

Owner stop, 2026-11-16: the remaining native macOS filesystem selection
contains 232 mutants (the complement of the qualified 98-case cache scope).
The owner stopped this run after 173 completed: 102 caught, 65 missed,
6 unviable, zero timeouts and 59 untested. This is incomplete and does not
qualify the filesystem scope. Preserve `.work/mutants-macos-filesystem-final/`
and `.work/tmp/macos-filesystem-qualified.log`; the bounded driver is
`.work/tmp/run-macos-filesystem.py`. It used cargo-mutants 27.1.0, three jobs,
six guarded cores, a 60-second test timeout and `macos::tests::` filtering.
The unmutated baseline passed. Survivor dispositions and any test changes
remain undone; DSLP-4 remains open. No source or test inputs changed in this
continuation. The owner resumed on 2026-11-16. The resumed branch merges
current main and adds a process-level trust-boundary check. An unconditional
trusted-directory success now fails that check; source restoration passes.
Literal metadata tables now guard owner, write-bit and root-sticky policy.
The complete 21-mutant directory-policy Scenario is qualified: all caught,
none missed, unviable or timed out, with every identity and assertion checked.
It covers all seven saved survivors in this region; 58 original survivors and
59 untested cases remain. The restored source passes an isolated-target full
suite (44 unit, 28 integration, four terminal, two hardware cases ignored) and
lint. A first final run reused the last mutant's shared-target artifact and
was rejected. Coverage, quiet-host cost and the remaining regions keep DSLP-4
open. [The filesystem record](docs/deslop-filesystem.md) retains exact proof
and limits.

Filename codec continuation: the complete 36-mutant component Scenario has 31
caught, four equivalent misses, one unviable and no timeouts. Literal codec and
UTF-8 byte-limit assertions have a restored hand-fault witness; the full suite
and lint pass in a separate target. The original 232-case run remains
incomplete with its original counts, and unrelated regions, coverage and cost
remain open. See [the filesystem record](docs/deslop-filesystem.md).

Prompt confidentiality finding PR34 merged as `6a4b7d5`. One terminal session
now spans prompt publication and input; the deterministic operation-order
witness fails on the base sequence and passes after. Native macOS and Linux
ARM64 checks pass for the finding. The combined Tests tree retains its prior
restore-failure oracle and passes native tests/lint in a separate target;
broader DSLP-4 acceptance remains open. See the
[finding proof and limits](docs/deslop-terminal-echo.md).

## Tickets




### DSLP-4 · P2 · Tests: coverage, boundary gaps, mutation

- **Area:** deslop · tests
- **Where:** test suites and CI
- **Problem:** Coverage and mutation results are unmeasured; no deslop mutation lane exists.
- **Recommendation:** Run the deslop Tests step. Accept: no undispositioned survivor in critical code, the test cost budget holds, and the lane is green where the tools are mirrored.
- **Fix with:** deslop
- **Effort:** M

### DSLP-5 · P2 · Dead code: tools and debloat

- **Area:** deslop · dead code
- **Where:** whole repository
- **Problem:** No dead-code scan has run.
- **Recommendation:** Run the deslop Dead code step. Accept: tools clean or allowlisted with reasons; walk-backs filed as Needs owner tickets.
- **Fix with:** deslop
- **Effort:** M


### DSLP-6 · P2 · Interoperability and keyring checks can be skipped in CI

- **Area:** Tests · CI
- **Where:** tests/terminal_cli.rs:718, src/linux.rs:1353
- **Problem:** The Linux rage and keyring checks can return early without exercising their boundaries. make test now displays and counts these skips, but CI can still pass without the checks; the cargo, mirror and OCI catalogs did not list rage 0.12.1 on 2026-11-15. CI has no macOS lane and hardware authentication tests remain ignored.
- **Recommendation:** Provision pinned rage 0.12.1 from an approved source and make the interoperability check required in CI; provide a usable kernel keyring or document an owner-run check. Keep skipped checks visible until they can run.
- **Fix with:** test-audit
- **Effort:** S


### DSLP-8 · P2 · Stale socket test races with concurrent process creation

- **Area:** Tests · macOS
- **Where:** src/macos.rs:1706, src/macos.rs:475
- **Problem:** A warm parallel make test failed with identity cache connection closed early in stale_cache_socket_is_removed_without_prompting. Ten isolated runs each on base and candidate passed. A controlled fork overlap on the base test reproduced the same error: a child retained the listening descriptor after the parent dropped it, so connect succeeded before the child closed it. The exact interleaving in the original failure was not observed.
- **Recommendation:** Create the stale socket in an isolated child process and wait for it to exit before testing, or otherwise prevent a concurrent fork from retaining the listener; preserve the stale-socket removal assertion and verify it under concurrent process creation.
- **Fix with:** root-cause
- **Effort:** S


### DSLP-7 · P3 · Cross-Mac recovery has no end-to-end check

- **Area:** Tests · recovery
- **Where:** src/macos.rs:291, src/macos.rs:1474, tests/security_macos/README.md:19
- **Problem:** Test-gap finding: recovery decrypts the backup identity and replaces the device-bound sidecar, but the ignored roundtrip exercises only one Mac; the harness documentation says cross-Mac recovery requires a separate check. Failure of cross-Mac recovery is unproven. A user discovering an incompatibility only after moving a backup could lose access to secrets.
- **Recommendation:** Add a documented, repeatable two-Mac recovery boundary check using a disposable store, verifying recovery and readback after transfer, plus rejection of a wrong passphrase. Include src/macos.rs, src/secure_enclave.rs and src/store.rs in the critical mutation scope.
- **Fix with:** test-audit
- **Effort:** M

