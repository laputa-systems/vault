# Campaign: macOS protected-storage completion follow-up

Repository: https://github.com/laputa-systems/vault
Audited baseline: a1eb442bf1fd7c33059a44c3b953ccdf1c3887bb (2026-10-21)
Companion: campaign-macos-hardening.md

## Status and mission

The shared CLI hardening and isolated macOS security harness have been implemented, but **macOS protected storage is not complete**. Do not reinterpret an implementation checkpoint as a security sign-off.

The harness has already demonstrated that a dummy file-based Keychain item requesting userPresence can be read with interaction disabled. An explicit Data Protection Keychain add failed with missing-entitlement. The examined host had zero valid code-signing identities and no suitable provisioning profile; thus biometric enforcement, second-identity denial, authenticated multi-secret reads, and migration were not verified. See tests/security_macos/README.md.

This follow-up is an implementation campaign to close the remaining macOS authorization/storage gate when prerequisites are available, not a request to weaken the policy or to reimplement completed CLI hardening.

## P0 — establish signing and entitlement prerequisites

1. Inspect the latest main, existing security harness, code-signing identities, and available provisioning profiles. Reuse the harness; do not write to the real login Keychain service in tests.
2. Consult Apple TN3137/TN3125 and Secretive's current signing/entitlement and SecureEnclaveStore implementation. Distinguish macOS file-based from Data Protection Keychains and clarify entitlements, bundle identifier, Team ID, and provisioning-profile requirements for the intended CLI packaging.
3. Try only authorized existing identities/profiles. Do not claim a self-signed or ad-hoc certificate is sufficient to grant restricted entitlements. Do not fabricate/sign with unavailable credentials or enroll the user in an Apple Developer account without explicit approval.
4. If necessary, construct the smallest app-like bundle around the Rust CLI. Prefer no GUI, background helper, IPC, daemon, or LaunchAgent. Validate the real installed PATH invocation, re-signing/update behavior, and recovery of stable Keychain identity.
5. If external identity/profile prerequisites remain unavailable, stop just that gate, list exactly what credentials/configuration the owner must provide, and finish the independent documentation/tests. Do not claim protected storage is working.

Acceptance: a genuine provisioned/signature-valid configuration with an entitlement-enabled Data Protection Keychain item, or an explicit blocked status with reproducible errors and user action required. Never silently fall back to the file-based Keychain.

## P0 — prove effective policy, not UI appearance

With isolated dummy service/accounts, validate SecItemAdd, SecItemCopyMatching, SecItemUpdate, SecItemDelete and attribute-only listing using explicit Data Protection Keychain selection and kSecAttrSynchronizable=false.

- Enforce WhenUnlockedThisDeviceOnly with an OS-validated userPresence policy.
- Verify noninteractive reads fail without authorization. Use LAContext and the supported Keychain authentication context, including fresh-context denial and cancellation tests.
- Demonstrate authorized Touch ID (or supported password fallback) under a real login session. A successful prompt alone is insufficient.
- Verify separate signed executables without access-group authority cannot read the item.
- Test context reuse across multiple secrets in one exec invocation, invalidation afterward, and separate invocation behavior. Do not claim one-touch-per-command if the OS does not enforce this reliably.
- Explicitly test creation/update over preexisting weaker-policy items; never permit an update to preserve weaker access control silently.
- Record macOS version, architecture, signing configuration, and result codes. Make interactive experiments opt-in. Tests must not touch production service/account values.

## P1 — safe current-service migration and legacy boundaries

Implement an explicit, idempotent, fail-closed migration only **after** the protected backend is proven:

- Existing current service: dev.joshuarli.vault.secure in file-based Keychain. Distinguish it from the old forbidden-to-read dev.joshuarli.vault namespace.
- No implicit migration or fallback during get/set/exec.
- Read a source item with authorization, create a destination protected item, verify actual value and effective policy, and retain the original source. Never delete original data before full verification or on partial failure.
- Conflicts, duplicate records, interruptions, keychain locking, and retry all need tests. Report names/status only, not secret values.
- Scope rm/purge to exact known records and preserve the documented legacy cleanup contract. Recheck that destructive operations never accidentally affect unrelated items.
- After migration, no supposedly protected read should silently return a legacy item.
- Back up migration/recovery instructions before enabling it; do not claim Secure Enclave hardware keys are exportable or recoverable.

## P1 — honest current macOS behavior pending migration

While the signing gate remains unresolved, the existing backend continues to use the file-based Keychain with unproven userPresence protection. Make the unsafe assumption conspicuous in help and README, and document exactly what currently works.

Decide explicitly whether unprotected-by-policy new writes should continue as a clearly labeled legacy compatibility mode or be gated until secure setup. Do not silently change the stored format, break existing reads, or destroy data; if a fail-closed policy change is needed, implement it with a clear migration/recovery path and documented compatibility impact.

The removed macOS vault lock command must stay removed unless an actual revocation mechanism is demonstrated by negative tests; do not reintroduce the old partition-list workaround.

## P1 — terminal, tmux, sudo Touch ID boundary

Review https://github.com/joshuarli/usr/blob/main/macos/setup-macos. It configures root-owned pam_reattach and pam_tid in /etc/pam.d/sudo_local for **sudo**. This is not an authentication token for vault and must not be reused as one.

Test direct terminals, local tmux (attached and detached), lack of GUI session, remote SSH/tmux and unavailable Touch ID against a real protected item. If GUI bootstrap isolation is the blocker, investigate the narrow supported reattachment mechanism and associated security risks. Do not modify PAM, require sudo/root, or build a persistent helper just to obtain prompts. Document platform restrictions and password fallback without overstating support.

Preserve the completed fail-closed termios, signal restoration, isolated Keychain tests, safe stdout, purge argument checks, and parent environment isolation. Do not cosmetically redo this work.

## P2 — distribution and public security claims

- Decide on a real signed, reproducible release/update path for any entitlement-dependent backend. A downloaded ad-hoc-resigned single binary may lose its app identity and authorization; do not recommend it without proof.
- Cross-check Makefile, docs, binary locations, certificate requirements, verification options, and tests under the packaging choice. Modify CI/release files only when necessary for a supported protected storage outcome and explicitly justify it.
- Reference Secretive as a non-exportable signing-key example, not as evidence that arbitrary API token plaintext can stay in Secure Enclave. Study Secure Enclave envelope encryption only if a concrete unmet threat justifies the added crypto and migration complexity.
- Verify all default tests are isolated and noninteractive. Ensure worktree/security artifacts are outside tracked state. Avoid logging sensitive data, entitlement material, or unnecessary machine-specific identifiers.
- Keep development and production identities separated, and document recoverability when a developer identity/profile expires or changes.

## Execution and completion

1. Re-run the isolated harness and pin exact test observations to the latest macOS host.
2. Resolve the Apple signing/profile gate with real supported credentials or record an explicit blocker. Do not burn cycles repeatedly trying ad-hoc entitlements.
3. With an authorized configuration, prove Data Protection Keychain userPresence via positive **and negative** checks.
4. Implement one explicit protected SecItem query boundary, then non-destructive migration and consistent CRUD/list semantics.
5. Validate Touch ID + password fallback, local tmux, a fresh process, a second signing identity, and a code-signed update. For remote/locked session states, report precise unsupported cases rather than inferring success.
6. Run existing safe tests, security opt-in tests, clippy, and production-like installation validation without using real user secrets.
7. Simplify and commit the change; update campaign-macos-hardening.md's status/acceptance evidence and README honestly.

Definition of done: real protected Keychain items; denied unauthenticated access; reliable authorized read; stable signed CLI identity; safe idempotent migration; accurate session behavior; preserved macOS/Linux CLI regressions; no weaker fallback, privilege escalation, unwanted daemon, or secret-bearing IPC.

If credentials are still unavailable, the outcome is **blocked, not complete**. Final report must enumerate the exact identity/profile required and the next reproducible experiment, alongside finished independent work, rather than claim completion.
