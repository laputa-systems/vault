# macOS Keychain harness

This directory contains a repeatable, isolated Keychain experiment. It does not accept service, account, or keychain path arguments.

## Run the noninteractive checks

Run `tests/security_macos/run.sh` from any directory inside the worktree. The default run never allows authentication UI.

The harness compiles `Harness.swift` into `.work/tmp`, signs the executable ad hoc, and creates a temporary file based keychain. It uses the fixed service `dev.joshuarli.vault.security-harness` and UUID scoped accounts. It creates dummy bytes in memory and never prints them or writes them to ordinary files.

The harness sets `kSecUseDataProtectionKeychain` on every SecItem operation and sets `kSecAttrSynchronizable` to `false`. File based operations name the temporary keychain directly. Data Protection operations use the current user’s Data Protection Keychain.

An exit trap attempts exact Data Protection record deletion with interaction disabled, deletes exact file-Keychain records, deletes the temporary keychain, and checks that the user keychain search list matches its starting value. It reports cleanup failures and never opens authorization UI from the trap. Keep `.work/` ignored through `.git/info/exclude` before running the script.

## Run the signing gate

Run `tests/security_macos/run.sh --gate` to repeat the noninteractive checks and inspect existing code signing identities and provisioning profiles. The script tries the ad hoc executable first. It then uses an installed `Vault Signing`, Developer ID Application, or Apple Development identity if one exists. When a matching profile authorizes a keychain access group, it creates, signs, verifies, and runs a minimal app bundle from `.work/tmp`. It does not create identities or profiles.

The app-like attempt requires an existing profile that authorizes the signing identity, the bundle identifier, and the `keychain-access-groups` entitlement. If no matching profile is installed, the script records the missing prerequisite and parks that attempt.

## Run the interactive checks

Run `tests/security_macos/run.sh --interactive` from a terminal to opt in. The script requires a TTY before it starts. It repeats the ad-hoc, existing-identity, and matching-profile gate, then uses the strongest available existing signer and app bundle for the interactive check. It records the hardware model, macOS version, signing identity, TTY, SSH, tmux, console user, and launchd manager session.

If protected Data Protection items can be created, the harness reads one with a fresh `LAContext`. It then disables interaction on that same context and reads a second item. It launches a separate process with a fresh noninteractive context and checks that the process cannot read the first item without new authorization. This tests authorization state through matching item data and SecItem results, not by counting prompts. Before the interactive command, the script rejects a missing TTY before creating a keychain or querying Keychain items.

## Read the results

The latest `--gate` run on 2026-10-21 used macOS 27.0.1 on arm64 hardware `Mac17,7`. The standalone ad-hoc executable added and read a dummy item in the temporary file based keychain. A dummy file item with `userPresence` remained readable with interaction disabled. The explicit Data Protection query did not find the file item, and the Data Protection add returned `missing-entitlement`. The partition-list command left both file items readable. The run found no valid `Vault Signing`, Developer ID Application, or Apple Development identity and no `.provisionprofile` in either standard per-user Xcode profile directory. It ran without a TTY in an attached local tmux session, queried no production service, deleted its exact records and disposable keychain, and restored the original search list.

On the recorded host, macOS 27.0.1 on arm64 hardware `Mac17,7`, the ad hoc executable added and read an item in the temporary file based keychain. An explicit Data Protection query did not find that file based item. The explicit Data Protection add returned `missing-entitlement`.

`security find-identity -v -p codesigning` reported `0 valid identities found`. The standard per-user Xcode provisioning profile directories were absent. The existing identity attempt was unavailable, and the app-like attempt lacked both a matching identity and profile. The Data Protection access control, noninteractive denial, update behavior, cross-identity access, and `LAContext` reuse checks remain unproven on this host because the ad-hoc add returned `missing-entitlement`. No Data Protection item was created, and cleanup reported `unavailable_missing_entitlement`; exact file records were deleted, the disposable file keychain was removed, and the original search list was restored.

The harness ran `security set-generic-password-partition-list` with `-S ''` against both the unprotected and `userPresence` file-based dummy items in the temporary keychain. Both commands succeeded. Before and after each command, an explicit read returned the matching dummy bytes, including a read with interaction disabled for the `userPresence` item. These file-Keychain reads did not enforce the requested presence check, and the partition-list command did not revoke access in either tested case.

The default harness ran without a TTY in a local attached tmux session (`tmux_attached:1`) and in a detached tmux session (`stdin_tty:yes`, `tmux_attached:0`); both completed with exit 0. `--interactive` without a TTY exited 2 before Keychain reads. The TTY opt-in run repeated identity and profile discovery; because neither prerequisite was installed, it used the ad-hoc executable. It reported Touch ID and device-owner authentication available without prompting, then stopped at `missing-entitlement`. `SSH_TTY` and `SSH_CONNECTION` were absent, the console user matched the process user, and the launchd manager UID matched. SSH, user switching, and a locked macOS session were not exercised because no separate session was available. A biometric-unavailable host state was unavailable to test because Touch ID was available; biometric cancellation and passcode fallback were not exercised because no protected Data Protection item could be created.

The harness does not run the `vault` executable because its service is the production service, which the harness must never query. It tests SecItem behavior using the fixed harness service instead.

## Apple API constraints

Apple’s [TN3137](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains) says SecItem defaults to the file based Keychain on macOS. Set `kSecUseDataProtectionKeychain` to select the Data Protection Keychain. TN3137 also says Data Protection access groups come from code signing entitlements, restricted entitlements require an authorized provisioning profile, and the profile needs an app like bundle.

Apple’s [TN3125](https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles) explains how a provisioning profile authorizes restricted entitlements. Apple documents [`userPresence`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/userpresence) as allowing biometrics or the device passcode. Apple documents [`kSecUseAuthenticationContext`](https://developer.apple.com/documentation/security/ksecuseauthenticationcontext) as the reusable `LAContext` for Keychain authentication.
