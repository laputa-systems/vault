Prefix: DSLP
Next: 8

Deslop campaign backlog ([plan](https://github.com/laputa-systems/stuff/blob/main/docs/campaigns/deslop.md), tier A). One agent works this file with the `deslop` skill: take the lowest-numbered open ticket whose area does not start with `Needs owner ·`. After DSLP-5, work the open P1 and P2 findings, then fill in `## Report` below.

## Report

Ground: base `ca93f9dc1f3b2f74ca52915a31b54c324a25af06`; macOS arm64, Rust nightly 1.102.0, `cpu-guard --cores 6`: fresh-target `make test` 15.23s, warm 4.43s, `make lint` 9.80s; all exit 0. Tests: 56 passed, two hardware authentication tests ignored. No vendored source trees found. No performance workload exists; no established user-visible performance gate. No runtime code changed.

PR CI builds Linux musl images and runs `make test-ci`; it has no macOS lane, so macOS and Secure Enclave tests do not run there. Its image does not install rage 0.12.1, so the Linux interoperability test returns early; keyring checks can also return early when the kernel cache is unavailable. Actual CI execution and keyring availability are unverified locally. Open fleet lint findings (linux-musl-toolchain 3, laputa-rustix 2, binary-release-static 1, make-clean-target 1, owned-tool-support 1, registry-sources 1) remain fleet-rule work.

## Tickets



### DSLP-3 · P2 · Types: strict profile and typing findings

- **Area:** deslop · types
- **Where:** type checker and lint configuration; Rust sources
- **Problem:** The strict-profile candidates in the deslop skill's tools reference have not been measured here.
- **Recommendation:** Run the deslop Types step. Accept: clean at the adopted profile, escape hatches not increased, witnesses recorded.
- **Fix with:** deslop
- **Effort:** M

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


### DSLP-6 · P2 · Interoperability and keyring tests pass silently when their tool is missing

- **Area:** Tests · CI
- **Where:** tests/terminal_cli.rs:718, src/linux.rs:1353
- **Problem:** The Linux interoperability test returns early (passes) when rage 0.12.1 is not installed, and the keyring assertions skip when no keyring is available, so CI can report green without exercising either boundary. CI has no macOS lane, and the two hardware authentication tests are #[ignore].
- **Recommendation:** Install a pinned rage 0.12.1 in the CI image and make the test fail rather than return when CI=true and it is missing; do the same for the keyring path, or record it as an owner-run boundary in Verification.
- **Fix with:** test-audit
- **Effort:** S


### DSLP-7 · P3 · Cross-Mac recovery has no end-to-end check

- **Area:** Tests · recovery
- **Where:** src/macos.rs:291, src/macos.rs:1474, tests/security_macos/README.md:19
- **Problem:** Test-gap finding: recovery decrypts the backup identity and replaces the device-bound sidecar, but the ignored roundtrip exercises only one Mac; the harness documentation says cross-Mac recovery requires a separate check. Failure of cross-Mac recovery is unproven. A user discovering an incompatibility only after moving a backup could lose access to secrets.
- **Recommendation:** Add a documented, repeatable two-Mac recovery boundary check using a disposable store, verifying recovery and readback after transfer, plus rejection of a wrong passphrase. Include src/macos.rs, src/secure_enclave.rs and src/store.rs in the critical mutation scope.
- **Fix with:** test-audit
- **Effort:** M

