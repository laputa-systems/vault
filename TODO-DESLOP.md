Prefix: DSLP
Next: 8

Deslop campaign backlog ([plan](https://github.com/laputa-systems/stuff/blob/main/docs/campaigns/deslop.md), tier A). One agent works this file with the `deslop` skill: take the lowest-numbered open ticket whose area does not start with `Needs owner ·`. After DSLP-5, work the open P1 and P2 findings, then fill in `## Report` below.

## Report


**Branch tests landed**

Each fault below was injected into production code, produced a failing focused test (exit 101), and was reverted.

| Group | Protected behavior | Injected fault |
| --- | --- | --- |
| Filename codec | Canonical path-safe encoding and byte limits | Encode hex in uppercase |
| Data home | XDG and HOME fallback, invalid and non-UTF-8 paths | Use the wrong fallback directory |
| Atomic writes | Destination admission, failed writes and syncs, rename and crash windows | Skip file sync |
| Directory trust | Listing rejects writable and symlinked ancestors | Allow writable parents |
| Private files | Reject links and nonregular files, repair modes, enforce read limits | Follow symlinks on open |
| Locks | Reject unsafe lock files and repair permissions | Skip lock mode repair |
| Staging and listing | Filter entries and refuse unsafe nested cleanup | Include symlinks in ordinary listings |
| Bootstrap | Publish a private recoverable store, refuse replacement, reject empty recovery passphrases and clean failed stages | Skip cleanup after wrapping fails |
| Identity input | Reject invalid Secure Enclave identity bytes and sidecars | Skip sidecar validation |
| Store formats | Reject mismatched recipients and malformed identity formats | Accept mismatched recipients |
| Decrypted sizes | Accept exact bounds and reject oversized values | Reject values at the exact secret limit |
| Signal failures | Report setup and restoration failures and retry failed restoration | Discard handlers whose restoration failed |
| Passphrase terminal I/O | Restore terminal and signals and report open, prompt, input and combined errors | Skip explicit signal restoration |
| Uninitialized store | List, purge and lock without creating a store | Create the data home during listing |

Dropped: generated temporary-name spelling, descriptor flag and fake-metadata assertions that track implementation details; duplicate path, codec and cleanup checks covered by the wider tests above or existing main tests; mutation selection, shard budgets, CI and qualification receipts because wide mutation runs are paused. The non-UTF-8 filename listing case is unavailable on this macOS filesystem, while non-UTF-8 data-home resolution is covered. Linux ciphertext-file exact-boundary and native cache startup candidates remain unported and unverified here; hardware authentication and physical power-loss durability remain unverified.

Fully superseded stranded branches: none established. Their histories also contain the unported Linux ciphertext and cache candidates, so retain them until those are dispositioned; do not infer safe deletion from these ports alone.

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

Tests (DSLP-4): required scope is `src/store.rs` encryption, authentication and size bounds; `src/macos.rs` and `src/linux.rs` identity and bootstrap validation, atomic publication and cleanup; `src/main.rs` passphrase input, signal restoration, CLI limits and exit statuses; and the macOS cache socket admission and protocol. The ordinary suite exercises age format and tampering, recipient matching, terminal echo and signal restoration, input limits, child status and socket requests. `tests/integration.rs` rejects surplus names before storage. Atomic syscall failures and process-crash windows, bootstrap domain, and signal syscall failures now have witnesses in the landed groups above.

Recorded mutation dispositions are grouped by behavior. The store selection on `e8c79312` records 45 caught and six unviable; the macOS cache/store selection records 69 caught and 29 unviable. These receipts use branch tests and do not establish main's mutation result. The original macOS filesystem run at `35fa554` was incomplete: 102 caught, 65 missed, six unviable, 59 unrun. Follow-up branch tests reconcile the misses as 46 caught and 19 equivalent and the unrun as 49 caught, four equivalent and six unviable. Equivalent groups include disjoint open-flag OR/XOR, redundant filename validation and newline rejection by age parsing. Unviable replacements do not provide evidence. Private temporary-name spelling and incidental diagnostics, including the shard 9 size-display arithmetic, need no further tests. Linux shard 13's surplus-name survivor is covered by the ordinary CLI regression; the terminal-flag OR/XOR survivor remains unresolved pending a Linux-specific equivalence check. Signal setup and restoration failures have branch witnesses; three historical terminal hangs remain incomplete. Exact trials are in `git show deslop/cli-oracle:docs/deslop-filesystem.md`, `git show deslop/signal-failure-tests:docs/deslop-signal-tests.md` and `git show deslop/platform-ci:docs/deslop-platform-ci.md`.

The advisory platform matrix in [draft #30](https://github.com/laputa-systems/vault/pull/30) at `0671858b` passed ordinary macOS and both Linux musl jobs, but the aggregate mutation run failed, including budget-exhausted and incomplete shards. No wide matrix was rerun for this closure. No new mutation trial was run (0 runner-minutes). A hand fault changed `require_exact_name` from `> 1` to `< 1`; the CLI regression failed, and the fault was restored. Cargo reported 62 seconds building and 0.27 seconds running that fault trial. The remaining unrun shards and unconfirmed timeouts are incomplete, not passes. Hardware authentication, live Linux keyring assertions, two-Mac recovery, physical power-loss durability and remote CI remain environment items. DSLP-6 remains open for silently skipped tool-dependent checks.

Local branch inventory against `origin/main` at `553fb720`. Tests listed as worth landing are candidates for separate PRs; their historical receipts do not qualify main.

| Branch | Head | Status | Reason |
| --- | --- | --- | --- |
| deslop/acc-socket | 0e72b211 | already merged | Socket fixture is in main. |
| deslop/atomic-fault-windows | 6856af34 | contains unlanded tests worth landing | `atomic_file_native_fault_windows` exercises syscall failures and process crashes. |
| deslop/atomic-file-tests | 7db74f65 | contains unlanded tests worth landing | `atomic_file_replacement_and_admission`, `atomic_file_names_and_cleanup` and `atomic_file_temporary_names_flags_and_collisions` protect atomic publication. |
| deslop/bootstrap-domain-tests | f655ec01 | contains unlanded tests worth landing | `bootstrap_domain_publishes_private_recoverable_store_and_refuses_replacement` and `bootstrap_domain_wrap_failure_cleans_stage_and_preserves_error` protect initialization. |
| deslop/cli-oracle | 94c2210b | contains unlanded tests worth landing | `cache_daemon_rejects_an_empty_seed` and `cache_daemon_rejects_either_missing_seed_field` protect seed admission; it also inherits crash and terminal witnesses. |
| deslop/identity-validation-tests | f82546e1 | contains unlanded tests worth landing | `identity_input_identity_bytes` and `identity_input_sidecar_read_and_validation` exercise malformed identity and sidecar input. |
| deslop/lock-mode-tests | 2c0035b6 | contains unlanded tests worth landing | `lock_mode_descriptor_and_admission` and `lock_mode_directory_and_socket_repair` exercise admission and permissions. |
| deslop/passphrase-error-tests | c68d9ccd | contains unlanded tests worth landing | `read_passphrase_owned_terminal_cleanup` exercises real PTY cleanup and error propagation. |
| deslop/passphrase-main | 0e72b211 | already merged | Same head as the merged socket branch. |
| deslop/platform-ci | e8c79312 | contains unlanded tests worth landing | Inherits `atomic_file_native_fault_windows` and `signal_handler_native_faults`; the advisory matrix is paused. |
| deslop/signal-contracts | bf3dcd9b | contains unlanded tests worth landing | `read_passphrase_owned_terminal_cleanup` adds terminal I/O fault witnesses. |
| deslop/signal-failure-tests | e939a06d | contains unlanded tests worth landing | `signal_handler_native_faults` exercises installation and restoration failures. |
| deslop/staging-list-tests | 9dbf993c | contains unlanded tests worth landing | `staging_list_creation_and_cleanup` and `staging_list_cleanup_refuses_nested_directories` protect cleanup admission. |
| deslop/tests-close | 553fb720 | superseded by main | At admission its head is identical to main. |
| deslop/tests-qualification | 63b25c74 | contains unlanded tests worth landing | Inherits `atomic_file_native_fault_windows` and records native coverage limits. |

## Tickets





### DSLP-5 · P2 · Dead code: tools and debloat

- **Area:** deslop · dead code
- **Where:** whole repository
- **Problem:** No dead-code scan has run.
- **Recommendation:** Run the deslop Dead code step. Accept: tools clean or allowlisted with reasons; walk-backs filed as Needs owner tickets.
- **Fix with:** deslop
- **Effort:** M


### DSLP-6 · P2 · Interoperability and keyring tests pass silently when their tool is missing

- **Area:** Tests · CI
- **Where:** tests/terminal_cli.rs:718, src/linux.rs:1353
- **Problem:** The Linux interoperability test returns early (passes) when rage 0.12.1 is not installed, and the keyring assertions skip when no keyring is available, so CI can report green without exercising either boundary. CI has no macOS lane, and the two hardware authentication tests are #[ignore].
- **Recommendation:** Install a pinned rage 0.12.1 in the CI image and make the test fail rather than return when CI=true and it is missing; do the same for the keyring path, or record it as an owner-run boundary in Verification.
- **Fix with:** test-audit
- **Effort:** S


### DSLP-7 · P3 · Cross-Mac recovery has no end-to-end check

- **Area:** Needs owner · two-Mac recovery
- **Where:** src/macos.rs:291, src/macos.rs:1474, tests/security_macos/README.md:19
- **Problem:** Test-gap finding: recovery decrypts the backup identity and replaces the device-bound sidecar, but the ignored roundtrip exercises only one Mac; the harness documentation says cross-Mac recovery requires a separate check. Failure of cross-Mac recovery is unproven. A user discovering an incompatibility only after moving a backup could lose access to secrets.
- **Recommendation:** Add a documented, repeatable two-Mac recovery boundary check using a disposable store, verifying recovery and readback after transfer, plus rejection of a wrong passphrase. Include src/macos.rs, src/secure_enclave.rs and src/store.rs in the critical mutation scope.
- **Fix with:** test-audit
- **Effort:** M

