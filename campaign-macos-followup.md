# Campaign follow-up: local Secure Enclave storage

Repository: https://github.com/laputa-systems/vault
Companion: [campaign-macos-hardening.md](campaign-macos-hardening.md)

## Decision

Use CryptoKit Secure Enclave P-256 key agreement to wrap the existing Rust `age` X25519 identity. This gives the local CLI an OS-authenticated unlock path without relying on a provisioned Data Protection Keychain access group. `age-plugin-se` and Foundry's Rust plus Swift implementation informed the design; vault uses its own narrow Swift bridge so it can unwrap once per `get` or `exec` invocation and preserve the existing per-secret age ciphertext format.

This design does not isolate the sidecar from other processes owned by the same user. They can copy the sidecar and request their own device-owner authentication. Once unlocked, the age identity exists in vault's memory. The intended protection is at-rest encryption plus OS-mediated authentication for each new-store read, not process isolation within one user account.

## Implementation

The macOS store contains:

| File | Purpose |
| --- | --- |
| `identity.age` | Age-encrypted recovery copy of the X25519 identity |
| `identity.se` | Versioned CryptoKit Secure Enclave key representation and authenticated identity envelope |
| `recipient` | Public age recipient used to encrypt secrets |
| `secrets/<hex-name>.age` | Age ciphertext for each secret |

Rust owns age encryption, decryption, file permissions, locking, atomic writes, and the CLI storage operations. The small Swift C ABI bridge uses CryptoKit for Secure Enclave P-256 key generation/agreement, HKDF-SHA256, and ChaChaPoly authenticated encryption; LocalAuthentication requires device-owner authentication. The `identity.se` envelope binds the wrapped identity to a format label and the store's public age recipient. A fresh `LAContext` is used for each unwrap and invalidated afterward.

The first `set` creates the store and asks for a recovery passphrase twice. `isset` remains silent for the value but still requires this first-use recovery setup. Further `set` calls encrypt through the public recipient and do not unlock the identity. `get` and `exec` each unwrap once, then decrypt all requested age files. Failed authentication, unavailable hardware, invalid sidecars, and decryption errors stop the read; there is no weaker fallback.

The recovery passphrase decrypts `identity.age`; `vault recover` validates that identity against the stored recipient and writes a new Secure Enclave sidecar. On device replacement, copy the encrypted identity, recipient, and encrypted secret files, then run recovery on the new device. The previous `identity.se` cannot be used on another Secure Enclave. Keep recovery material independently protected.

The implementation requires macOS 10.15 or later and supported Secure Enclave hardware. It links a Swift object into the Rust executable at build time; macOS builds require the Command Line Tools and Swift. Local ad-hoc signing works without an Apple Developer account, profile, app bundle, or restricted Keychain entitlement. No Xcode project, daemon, or external CryptoKit dependency is required.

## Existing Keychain data

Existing `dev.joshuarli.vault.secure` file-Keychain names remain visible and readable in compatibility mode. When no age store exists, normal reads use that service. Once an age store exists, a successful Secure Enclave unwrap is required before a missing age name can be read from Keychain. An unlock failure never falls through to Keychain. Replace an individual value by setting that same name through the normal `vault set` command.

The compatibility path does not have a verified user-presence guarantee: the isolated harness read a dummy file-Keychain item marked `userPresence` with interaction disabled. Treat those entries as unprotected until replaced with age ciphertext.

`vault set NAME` replaces one name: the age ciphertext is committed first, then the same-name Keychain entries are removed. Other Keychain names are preserved. `rm` and `purge` continue the existing exact cleanup behavior, including cleanup of the old `dev.joshuarli.vault` namespace; that legacy namespace is never read. No campaign test touched the user's production Keychain.

## Verification record

The in-memory opt-in Secure Enclave test uses a generated age identity and disposable age ciphertext. On the examined Mac it:

1. Denied a noninteractive unwrap.
2. Unwrapped the identity after an authorized device-owner prompt and decrypted the dummy age ciphertext.
3. Denied a second noninteractive unwrap using a fresh authentication context.

The successful authentication method was not recorded. The test proves an authorized CryptoKit unwrap on that host, not specifically Touch ID. The earlier standalone probe also denied a fresh noninteractive unwrap with LocalAuthentication `-1004` (`notInteractive`).

The file-backed opt-in test initializes a complete private test store, rejects a wrong recovery passphrase without changing `identity.se`, then uses the correct passphrase to write a new Secure Enclave sidecar and decrypts the same dummy secret through the storage path. Its latest completed run passed in 5.63 seconds on the current Mac. A later rerun after tightening test-directory cleanup remained at LocalAuthentication for over 60 seconds with no visible prompt; it was stopped and its exact temporary directory was removed. The completed recovery run predates that cleanup-only change. The test does not access the user's production Keychain. See [tests/security_macos/README.md](tests/security_macos/README.md).

The following remain open and must not be described as verified:

- Explicit prompt cancellation and exact Touch ID versus password behavior.
- Fresh-process behavior beyond noninteractive denial, including update/rebuild stability.
- Authorized reads in attached/detached tmux, SSH, locked-session, and no-GUI contexts.
- Cross-device recovery with a copied disposable store.
- Recovery after biometric enrollment changes, Secure Enclave loss, or a damaged recovery copy.
- Interaction with keychain compatibility entries under every partial failure condition.

## Useful focused commands

Default tests do not present authentication UI:

```sh
TMPDIR=.work/tmp cargo test --bin vault
TMPDIR=.work/tmp cargo clippy --all-targets --all-features -- --deny warnings
```

Opt-in tests use only dummy data and may present macOS authentication UI:

```sh
TMPDIR=.work/tmp cargo test --bin vault secure_enclave_wrap_denies_noninteractive_access_and_unlocks_age_identity -- --ignored --exact --nocapture
TMPDIR=.work/tmp cargo test --bin vault macos::tests::secure_enclave_store_roundtrips_age_secret_from_private_files -- --ignored --exact --nocapture
```

Run those from the repository root after ensuring `.work/` is ignored through `.git/info/exclude`. Do not use production secret material in the tests.

## Data Protection Keychain findings

The separate `tests/security_macos` harness still documents the Data Protection Keychain experiment. On the examined Mac, an ad-hoc Data Protection insertion failed with `errSecMissingEntitlement`; a file-Keychain item requesting `userPresence` remained readable with interaction disabled. There was no valid signing identity or installed matching profile, so the free Personal Team route was not tested. This is historical evidence about that route, not a requirement for the Secure Enclave implementation.
