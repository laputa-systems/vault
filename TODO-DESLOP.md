Prefix: DSLP
Next: 12

Deslop campaign backlog ([plan](https://github.com/laputa-systems/stuff/blob/main/docs/campaigns/deslop.md), tier A). One agent works this file with the `deslop` skill: take the lowest-numbered open ticket whose area does not start with `Needs owner ·`. After DSLP-5, work the open P1 and P2 findings, then fill in `## Report` below.

## Report

DSLP-1 base: `ca93f9dc1f3b2f74ca52915a31b54c324a25af06`, an ancestor of report admission `1fff677b0f6910c74e8a89f4907e209d82b6d510`. The cumulative review covers that diff, including terminal prompt ownership, file admission and publication, cache admission, CLI behavior and the new tests. No additional demonstrated defect or supported new finding was established.

**Scorecard** (base → admission). Line counts are physical lines in first-party Rust and C: `src/` and `build.rs` count as source until `#[cfg(test)] mod tests`; inline test modules and `tests/` count as tests. This is a simple partition, not a coverage measurement.

| Measure | Before | After / disposition |
| --- | --- | --- |
| Source / test lines | 3,991 / 2,677 | 4,010 / 3,951 |
| Warm `make test` | 4.43s, macOS arm64, six cores | Not measured under a quiet host; acceptance run checks correctness, not a timing gate. |
| Line / branch coverage | No comparable DSLP-1 baseline | Main not measured. A macOS branch-only receipt recorded 2,386/3,110 lines and 292/446 branches, including repeated instantiations and excluding Linux and hardware; it is not a before/after comparison. |
| Escape-hatch lines | 422 | 651 across first-party Rust including tests and build.rs; test additions account for much of the increase. Types alone was 422 → 422. This count is not a soundness verdict. |
| Dead code / dependencies removed | — | 0 lines / 0 dependencies (#39); two test helpers narrowed in visibility. |
| Findings filed / fixed | — | Diagnose: 0 defects, one P3 gap (DSLP-7); Ground: one P2 gap (DSLP-6), fixed by #41. Bench: three P3 gaps (DSLP-9–11); branch tests: one P3 gap (DSLP-8). No P1 findings. No P3 fixed. One additional terminal echo defect was fixed in #34; its priority was not recorded. |
| Performance | No workload or gate | No benchmarks; #40 audit filed retrieval, scaling and startup/size gaps. No performance regression verdict is possible. |
| Escaped regressions | Not systematically recorded | Terminal prompt-to-read echo exposure escaped earlier tests; #34 fixes it and adds an ordering witness. No other escape count is established. |

**Mutation evidence:** the required contracts named in #37 cover store encryption, authentication and limits; platform identity, bootstrap, atomic publication and cleanup; terminal and CLI handling; and macOS cache admission. The recorded branch-only store selection (required-contract subset, `e8c79312`) reported 45 caught, 0 missed reported, 0 timeouts reported, 6 unviable; the macOS cache/store selection (required-contract subset) reported 69 caught, 0 missed reported, 0 timeouts reported, 29 unviable. Absence of a reported result class is not proof of zero across the full scope. The advisory macOS filesystem run at `35fa554` recorded 102 caught, 65 missed, 6 unviable and 59 unrun; follow-ups classified the 65 as 46 caught and 19 equivalent, and the 59 as 49 caught, 4 equivalent and 6 unviable. Three historical terminal hangs and a Linux terminal-flag equivalence question remain unresolved. A required-contract terminal scenario at `bf3dcd9b` took 45 seconds (0.75 runner-minutes), with 4 caught and 0 missed, timed out or unviable; a required-contract directory-policy scenario took 9 runner-minutes, with 21 caught and 0 missed, timed out or unviable. Runner-minutes for the wider historical scopes and their timeout totals were not recorded; #37 added 0 mutation runner-minutes. The advisory [#30](https://github.com/laputa-systems/vault/pull/30) matrix failed with incomplete and budget-exhausted shards. Wide Vault mutation is paused; branch receipts do not establish a passing main or complete required scope. History retains details (`deslop/cli-oracle:docs/deslop-filesystem.md`, `deslop/signal-failure-tests:docs/deslop-signal-tests.md`, `deslop/platform-ci:docs/deslop-platform-ci.md`). Count the 15 behavior groups protected below, not mutation kills.

**Steps and cost.** Ground (#24): added the test entrypoint and boundary inventory; cold test 15.23s, warm 4.43s, lint 9.80s on macOS arm64, six cores, 56 passed and two ignored. Diagnose (#25): no demonstrated defects; filed cross-Mac recovery gap and corrected stale instructions. Types (#26): no strict candidate met the adoption rule; FFI and intentional casts accounted for false positives. Tests (#37–38): exact surplus-name regression and 15 fault-proven groups: filename codec; data home; atomic writes and crash windows; directory trust; private files; locks; staging/listing; bootstrap; identity input; store formats; decrypted limits; Linux ciphertext limits; signal failures; passphrase cleanup; uninitialized store. One injected fault per group failed its focused test. The #37 manual fault cost 62s build plus 0.27s test; no new mutation run. Dead code (#39): compiler checks and cargo-machete found no removable code or dependency. Bench (#40): no representative workload, with three ranked P3 gaps. Findings (#41): rage absence now fails in CI; Linux keyring is an explicit owner-run boundary after container keyctl denial. Other step wall times and CI runner-minutes were not recorded; do not infer them from test counts.

**Method feedback and shared-file gaps.** Prompt publication and reading must share the same hidden terminal session; an operation-order test would have exposed the echo window earlier. The wide mutation matrix exhausted its budget and had incomplete shards, so it cannot certify the critical scope. The dead-code and strict-profile steps found no qualifying cuts or settings. Shared deslop guidance needs a bounded mutation recipe and explicit incomplete-result accounting for platform-specific secret stores; fleet CI rules still report linux-musl-toolchain (3), laputa-rustix (2), binary-release-static (1), make-clean-target (1), owned-tool-support (1) and registry-sources (1). Those shared files are outside this worktree.

**Open boundaries.** DSLP-7 (P3) requires two Macs for cross-Mac recovery. DSLP-8 (P3) retains the native cache startup test and stranded branches. DSLP-9–11 (P3) cover performance evidence. Secure Enclave authentication and same-Mac hardware recovery require hardware and remain ignored by default; Linux session-keyring assertions require a host with a usable keyring and readable `/proc/keys`, since the container denies keyctl. Physical power-loss durability is not proved by process-crash tests. Non-UTF-8 filename listing is unavailable on this macOS filesystem. These are unverified boundaries, not demonstrated failures.

## Tickets









### DSLP-7 · P3 · Cross-Mac recovery has no end-to-end check

- **Area:** Needs owner · two-Mac recovery
- **Where:** src/macos.rs:291, src/macos.rs:1474, tests/security_macos/README.md:19
- **Problem:** Test-gap finding: recovery decrypts the backup identity and replaces the device-bound sidecar, but the ignored roundtrip exercises only one Mac; the harness documentation says cross-Mac recovery requires a separate check. Failure of cross-Mac recovery is unproven. A user discovering an incompatibility only after moving a backup could lose access to secrets.
- **Recommendation:** Add a documented, repeatable two-Mac recovery boundary check using a disposable store, verifying recovery and readback after transfer, plus rejection of a wrong passphrase. Include src/macos.rs, src/secure_enclave.rs and src/store.rs in the critical mutation scope.
- **Fix with:** test-audit
- **Effort:** M


### DSLP-8 · P3 · Port the native cache startup test from the stranded branches

- **Area:** deslop · tests
- **Where:** deslop/platform-ci tests/cache_spawn.rs; Cargo.toml test targets
- **Problem:** The stranded branches carry a native cache startup test that needs its own Cargo test target; it was not ported when the other branch tests landed, so cache spawn and startup on macOS have no witness on main.
- **Recommendation:** Port the test with its Cargo test target, prove it with one injected startup fault, then delete the stranded deslop branches.
- **Fix with:** deslop
- **Effort:** S


### DSLP-9 · P3 · Secret retrieval latency has no representative measurement

- **Area:** Performance · retrieval
- **Where:** src/macos.rs:162, src/macos.rs:193, src/linux.rs:202, README.md:59
- **Problem:** Unproven regression risk: normal get and exec retrieval have no performance workload, so slower cache hits or unlocks can reach users unseen. macOS uses a socket cache or Secure Enclave and Linux uses a keyring or passphrase; authentication interaction must be separated from processing time.
- **Recommendation:** Measure verified retrieval on disposable stores for macOS cache hit and unlock and Linux keyring hit and passphrase unlock; record host, samples, baseline and completed results, and use platform profilers to attribute regressions.
- **Fix with:** bench-pyramid
- **Effort:** M


### DSLP-10 · P3 · Store growth has no list or retrieval performance evidence

- **Area:** Performance · scaling
- **Where:** src/macos.rs:251, src/linux.rs:258, src/macos.rs:162, src/linux.rs:202
- **Problem:** Unproven regression risk: no representative list or get workload compares store sizes or secret sizes, so a scaling regression can ship without being noticed until users have larger stores.
- **Recommendation:** Measure successful list and get on disposable stores across representative entry counts and value sizes, verify names and values, and compare interleaved runs against a recorded baseline; use filesystem syscall counts and CPU sampling for attribution.
- **Fix with:** bench-pyramid
- **Effort:** M


### DSLP-11 · P3 · CLI startup and distribution size have no ongoing performance comparison

- **Area:** Performance · startup
- **Where:** Makefile:23, Cargo.toml:26, docs/deslop-terminal-echo.md:44
- **Problem:** Unproven regression risk: a one-off release-profile size comparison is not an ongoing distribution-size or startup measurement, so changes can increase download footprint or delay every invocation unnoticed.
- **Recommendation:** Record distribution binary size and verified CLI startup latency for representative release builds on supported platforms, with host and baseline and interleaved timing; use process-level CPU sampling if startup regresses.
- **Fix with:** bench-pyramid
- **Effort:** S

