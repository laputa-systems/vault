Prefix: DSLP
Next: 9

Deslop campaign backlog ([plan](https://github.com/laputa-systems/stuff/blob/main/docs/campaigns/deslop.md), tier A). Work the lowest-numbered open ticket whose area does not start with `Needs owner ·`.

## Report

Ground: base `ca93f9dc1f3b2f74ca52915a31b54c324a25af06`; macOS arm64, Rust nightly 1.102.0, six guarded cores: fresh `make test` 15.23s, warm 4.43s, lint 9.80s, all exit 0; 56 passed, two hardware tests ignored. No vendored trees or representative runtime performance workload were identified. These older parallel timings are not comparable to the serial qualification below.

Diagnose: findings and status are in the tickets below. Linux musl and native macOS CI were added; Linux keyring checks require the separate host described in [security_linux](tests/security_linux/README.md). Cross-Mac recovery remains DSLP-7; terminal prompt proof is in [terminal evidence](docs/deslop-terminal-echo.md). Fleet lint findings remain fleet-rule work.

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

Tests remain in progress (DSLP-4). The original 232 filesystem mutations retain their raw classes: 102 caught, 65 missed, six unviable, 59 unrun. By original identity, the 65 misses now map to 46 caught and 19 equivalent; the 59 unrun map to 49 caught, four equivalent and six unviable. This reconciliation does not qualify the entire Tests step. Component results, hand faults, bootstrap and atomic syscall/process-crash witnesses, source provenance and limits are in [filesystem evidence](docs/deslop-filesystem.md). Power-loss durability, hardware authentication and cross-Mac recovery remain unverified.

The Linux store selection had 51 mutants: 45 caught, six unviable, none missed or timed out. The native macOS cache/store selection had 98: 69 caught, 29 unviable, none missed or timed out. The exec/terminal selection has two signal-handler error/cleanup misses and three confirmed hangs; these remain bounded next work. The original macOS 81 and later 79 selections are not matched to the 98-function selection. The incomplete 232-case inventory is not a whole-crate mutation pass.

Fresh native coverage at `6856af3` has 2970/3571 lines and 361/486 branches across four first-party Rust files, including inline tests. Three interleaved two-core/two-test-thread pairs have median warm costs 6.41s before and 24.24s after, a 17.83s increase within the 30s allowance; every pre/test/post exit is 0. Ordinary and instrumented suites pass 65 unit, 28 integration and four terminal cases, two hardware ignores and zero named optional skips; the non-UTF-8 filename branch is unrun on EILSEQ. Short worktree names and fresh targets repair the path-only qualification failure. See [native qualification](docs/deslop-filesystem.md#native-qualification-at-6856) for exact settings, rejected serial receipts and remaining decision regions. CI mutation remains unqualified: its Linux job selects uncompiled macOS functions and exhausts the twenty-minute budget. Native signal-error witnesses and a platform-aware bounded CI recipe remain open; this is not a whole-Tests pass.

## Tickets




### DSLP-4 · P2 · Tests: coverage, boundary gaps, mutation

- **Area:** deslop · tests
- **Where:** src/main.rs, src/store.rs, src/linux.rs, src/macos.rs, tests/integration.rs, tests/terminal_cli.rs, tests/cache_spawn.rs, scripts/mutants_gate.py
- **Problem:** Vault #30 passed ordinary macOS and both Linux musl jobs at 0671858. The hosted Linux mutation run found survivors and exceeded its budget. Supported contract inventory: CLI arguments and exit codes (integration.rs); controlling-terminal input and signal restoration (terminal_cli.rs and main.rs witnesses); store formats, length limits and age interoperability (store.rs and Linux fixtures); macOS private file and cache admission (macos.rs and cache_spawn.rs). Hardware Secure Enclave, two-Mac recovery and real Linux keyring behavior still need separate qualification.
- **Recommendation:** Use docs/deslop-platform-ci.md for the exact receipts. Compare the artifact identities with the current source, then finish terminal/CLI and store survivors before broadening tests. Account for each Linux and macOS selection and match the ordinary make test/lint platform shape. Keep the total budget and check the diagnostics for partial outcomes. Execute the hosted deletion-only, uncovered-branch, mixed, incomplete and documentation controls. Record total CI runner cost and the gated ordinary suite cost before closing.
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

