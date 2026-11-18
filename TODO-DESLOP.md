Prefix: DSLP
Next: 8

Deslop campaign backlog ([plan](https://github.com/laputa-systems/stuff/blob/main/docs/campaigns/deslop.md), tier A). One agent works this file with the `deslop` skill: take the lowest-numbered open ticket whose area does not start with `Needs owner ·`. After DSLP-5, work the open P1 and P2 findings, then fill in `## Report` below.

## Report

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

The platform trial [#30](https://github.com/laputa-systems/vault/pull/30)
at `0671858b` passed the ordinary Linux x86-64 musl, Linux ARM64 musl
and macOS jobs. The aggregate failed. Fourteen Linux mutation shards
failed after roughly 20 minutes, and the 12 failed macOS shards
included incomplete runs. A separate
[budget receipt](https://github.com/laputa-systems/vault/commit/e8c79312e9fa1faa503b90708ab50b414e720ecf)
records the change that preserves partial results.

The ordinary jobs leave Secure Enclave authentication, two-Mac
recovery and the Linux session keyring unqualified. The recovery
check requires two independent Secure Enclave Macs, owner
authentication and a disposable store. The Linux keyring check
requires a runner with a usable session keyring and confirmation
that its assertions executed.

## Tickets




### DSLP-4 · P2 · Tests: coverage, boundary gaps, mutation

- **Area:** deslop · tests
- **Where:** test suites and CI
- **Problem:** Draft #30 supplies platform and store mutation evidence, but the union failed and the required cost and controls are unqualified.
- **Recommendation:** Account for the remaining Linux and macOS identities at their actual job budgets. Qualify the executed controls and record the separate hardware and keyring evidence.
- **Fix with:** deslop
- **Effort:** M

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

