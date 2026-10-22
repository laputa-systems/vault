# macOS storage security experiments

This directory contains the isolated Data Protection and file-Keychain harness. The vault Secure Enclave checks are Rust/Swift opt-in tests under `src/secure_enclave.rs` and `src/macos.rs`; they do not query the user's production Keychain.

## Secure Enclave checks for vault

Default unit tests validate sidecar framing, native status mapping, and age file-format behavior without prompting. Run them with:

```sh
TMPDIR=.work/tmp cargo test --bin vault
```

Two opt-in tests require Secure Enclave hardware and may present device-owner authentication. They use generated keys, dummy age ciphertexts, and no production service:

```sh
TMPDIR=.work/tmp cargo test --bin vault secure_enclave_wrap_denies_noninteractive_access_and_unlocks_age_identity -- --ignored --exact --nocapture
TMPDIR=.work/tmp cargo test --bin vault macos::tests::secure_enclave_store_roundtrips_age_secret_from_private_files -- --ignored --exact --nocapture
```

The in-memory test denies a noninteractive unwrap, authorizes an unwrap, decrypts a dummy age ciphertext, then denies another noninteractive unwrap with a fresh authentication context. Its latest run passed in 4.73 seconds. The file-backed test initializes a complete store in a unique `.work/tmp` directory, confirms an incorrect recovery passphrase leaves its sidecar unchanged, rewraps with the correct passphrase, and decrypts the same dummy value through vault's storage path. Its latest run passed in 5.63 seconds. The authentication method was not recorded; the result establishes authorized device-owner authentication, not Touch ID specifically.

Both tests clean up their disposable in-memory or file state. Ensure `.work/` is ignored through `.git/info/exclude` and set `TMPDIR=.work/tmp`. The file-backed test does not create or read Keychain entries. A later rerun after tightening test-directory cleanup remained at LocalAuthentication for over 60 seconds in this session, with no visible prompt; it was stopped and its exact temporary directory was removed. The completed recovery run above predates that cleanup-only change.

Still untested: explicit cancellation, whether the successful authentication used Touch ID or password, authorized reads over attached or detached tmux and SSH, a locked or non-GUI session, copying and recovering a disposable store on another Mac, and identity access after a rebuilt executable. Do not infer these from the positive test.

## Data Protection and file-Keychain harness

This directory contains a repeatable, isolated Keychain experiment. It does not accept service, account, or keychain path arguments.

## Run the noninteractive checks

Run `tests/security_macos/run.sh` from any directory inside the worktree. The default run never allows authentication UI.

The harness compiles `Harness.swift` into `.work/tmp`, signs the executable ad hoc, and creates a temporary file based keychain. It uses the fixed service `dev.joshuarli.vault.security-harness` and UUID scoped accounts. It creates dummy bytes in memory and never prints them or writes them to ordinary files.

The harness sets `kSecUseDataProtectionKeychain` on every SecItem operation and sets `kSecAttrSynchronizable` to `false`. File based operations name the temporary keychain directly. Data Protection operations use the current user’s Data Protection Keychain.

An exit trap attempts exact Data Protection record deletion with interaction disabled, deletes exact file-Keychain records, deletes the temporary keychain, and checks that the user keychain search list matches its starting value. It reports cleanup failures and never opens authorization UI from the trap. Keep `.work/` ignored through `.git/info/exclude` before running the script.

## Run the signing gate

Run `tests/security_macos/run.sh --gate` to repeat the noninteractive checks and inspect existing code signing identities and provisioning profiles. The script tries the ad hoc executable first. It then prefers an installed Apple Development identity, followed by Developer ID Application and `Vault Signing`. When a profile matches the selected identity and macOS application identifier, it creates, signs, verifies, and runs a minimal app bundle from `.work/tmp`. It does not create identities or profiles.

The app-like attempt reads the native macOS `com.apple.application-identifier` entitlement from the profile and signs the bundle with that identifier. The Data Protection probe uses the app's private application-identifier group by omitting `kSecAttrAccessGroup`; it does not require Keychain Sharing. The separate ad hoc reader then requests that exact private group to check cross-identity denial. If no matching profile is installed, the script records the missing prerequisite and parks that attempt.

Self-signing or ad-hoc signing alone does not authorize a restricted access group. A free Personal Team profile is a promising local route, but its native macOS Data Protection Keychain behavior and lifetime remain unverified. A clean exit from `--gate` only means the isolated run and cleanup completed; require `data_protection_probe=success` from the provisioned app run as evidence that its Data Protection add and exact read worked. `data_protection_probe=blocked` is not a pass.

## Run the interactive checks

Run `tests/security_macos/run.sh --interactive` from a terminal to opt in. The script requires a TTY before it starts. It repeats the ad-hoc, existing-identity, and matching-profile gate, then uses the strongest available existing signer and app bundle for the interactive check. It records the hardware model, macOS version, selected signing attempt, TTY, SSH, tmux, console user, and launchd manager session.

If protected Data Protection items can be created, the harness reads one with a fresh `LAContext`. It then disables interaction on that same context and reads a second item. It launches a separate process with a fresh noninteractive context and checks that the process cannot read the first item without new authorization. This tests authorization state through matching item data and SecItem results, not by counting prompts. Before the interactive command, the script rejects a missing TTY before creating a keychain or querying Keychain items.

## Read the results

The latest `--gate` run on 2026-10-21 used macOS 27.0.1 on arm64 hardware `Mac17,7`. The standalone ad-hoc executable added and read a dummy item in the temporary file based keychain. A dummy file item with `userPresence` remained readable with interaction disabled. The explicit Data Protection query did not find the file item, and the Data Protection add returned `missing-entitlement`. The partition-list command left both file items readable. The run found no valid `Vault Signing`, Developer ID Application, or Apple Development identity and no `.provisionprofile` in either standard per-user Xcode profile directory. It ran without a TTY in an attached local tmux session, queried no production service, deleted its exact records and disposable keychain, and restored the original search list.

A separate disposable ad-hoc Swift probe on the same host created a P-256 Secure Enclave key protected by `privateKeyUsage` and `userPresence`, wrapped a random dummy identity, then attempted to unwrap it from a fresh process with `LAContext.interactionNotAllowed`. The operation was denied with `com.apple.LocalAuthentication` code `-1004` (`notInteractive`). That earlier probe alone established only noninteractive denial. The current vault age integration and recovery results are in the Secure Enclave section above.

On the recorded host, macOS 27.0.1 on arm64 hardware `Mac17,7`, the ad hoc executable added and read an item in the temporary file based keychain. An explicit Data Protection query did not find that file based item. The explicit Data Protection add returned `missing-entitlement`.

`security find-identity -v -p codesigning` reported `0 valid identities found`. The standard per-user Xcode provisioning profile directories were absent. The existing identity attempt was unavailable, and the app-like attempt lacked both a matching identity and profile. The Data Protection access control, noninteractive denial, update behavior, cross-identity access, and `LAContext` reuse checks remain unproven on this host because the ad-hoc add returned `missing-entitlement`. No Data Protection item was created, and cleanup reported `unavailable_missing_entitlement`; exact file records were deleted, the disposable file keychain was removed, and the original search list was restored.

The harness ran `security set-generic-password-partition-list` with `-S ''` against both the unprotected and `userPresence` file-based dummy items in the temporary keychain. Both commands succeeded. Before and after each command, an explicit read returned the matching dummy bytes, including a read with interaction disabled for the `userPresence` item. These file-Keychain reads did not enforce the requested presence check, and the partition-list command did not revoke access in either tested case.

The default harness ran without a TTY in a local attached tmux session (`tmux_attached:1`) and in a detached tmux session (`stdin_tty:yes`, `tmux_attached:0`); both completed with exit 0. `--interactive` without a TTY exited 2 before Keychain reads. The TTY opt-in run repeated identity and profile discovery; because neither prerequisite was installed, it used the ad-hoc executable. It reported Touch ID and device-owner authentication available without prompting, then stopped at `missing-entitlement`. `SSH_TTY` and `SSH_CONNECTION` were absent, the console user matched the process user, and the launchd manager UID matched. SSH, user switching, and a locked macOS session were not exercised because no separate session was available. A biometric-unavailable host state was unavailable to test because Touch ID was available; biometric cancellation and passcode fallback were not exercised because no protected Data Protection item could be created.

The harness does not run the `vault` executable because its service is the production service, which the harness must never query. It tests SecItem behavior using the fixed harness service instead.

## Apple API constraints

Apple’s [TN3137](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains) says SecItem defaults to the file based Keychain on macOS. Set `kSecUseDataProtectionKeychain` to select the Data Protection Keychain. TN3137 also says Data Protection access groups come from code signing entitlements, restricted entitlements require an authorized provisioning profile, and the profile needs an app like bundle.

Apple’s [TN3125](https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles) specifies `com.apple.application-identifier` as the standard macOS App ID entitlement and explains how profiles authorize restricted entitlements. Apple’s [Keychain access-group guidance](https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps) says the app ID is the private default group when no keychain group is configured. Apple documents [`userPresence`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/userpresence) as allowing biometrics or the device passcode. Apple documents [`kSecUseAuthenticationContext`](https://developer.apple.com/documentation/security/ksecuseauthenticationcontext) as the reusable `LAContext` for Keychain authentication.
