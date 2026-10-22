# Campaign: macOS hardening for vault

Repository: https://github.com/laputa-systems/vault

Status: the Secure Enclave age store and CLI hardening are implemented locally. Focused macOS checks pass, including store recovery with a wrong passphrase, rewrapping with the correct passphrase, and decrypting a disposable secret afterward. Broader session, cancellation, and cross-device behavior remain unverified; see [campaign-macos-followup.md](campaign-macos-followup.md) and [tests/security_macos/README.md](tests/security_macos/README.md). No commit, install, or push was made.

## Current macOS storage

New secrets use age-encrypted files under `$XDG_DATA_HOME/vault` when that variable is absolute, or `~/Library/Application Support/vault` otherwise. A CryptoKit Secure Enclave P-256 key wraps one age X25519 identity. Reads unwrap it once per `get` or `exec` invocation and decrypt the requested age files. Authentication uses device-owner authentication and may accept Touch ID or the Mac password.

The recovery identity is also encrypted with age using a user-supplied recovery passphrase. It is stored beside the device-bound `identity.se` sidecar. `vault recover` uses the recovery passphrase to make a new Secure Enclave sidecar. Recovery requires a copy of the store and its passphrase; the sidecar alone is not portable.

The CLI is still a normal executable. The CryptoKit bridge is linked into it at build time, and local ad-hoc signing does not require an Apple Developer identity, provisioning profile, app bundle, or restricted Keychain entitlement. Building on macOS requires Swift and the Command Line Tools. The bridge requires macOS 10.15 or later and Secure Enclave hardware; the repository's existing deployment target may be lower, in which case the bridge reports that the operation is unavailable.

Existing current-service file-Keychain items remain readable in compatibility mode. `ls` lists both stores. When the age store exists, every read first unlocks its Secure Enclave identity; only then may a name absent from the age store be read from the current Keychain service. An unlock failure or corrupt age ciphertext is an error and never falls back to Keychain. `vault set NAME` writes the age ciphertext before deleting the same-name compatibility item. Unrelated Keychain items remain available. The old `dev.joshuarli.vault` namespace is never read, and the existing `set`, `rm`, and `purge` cleanup behavior remains.

Do not assume compatibility entries enforce user presence. The isolated harness read a dummy file-Keychain item marked `userPresence` with interaction disabled. Replace names individually through `vault set` to store them in the age store.

This is a single-user CLI. Replace an existing name individually by reading and setting it through the normal commands. Its old Keychain entry is removed only after the corresponding `set` succeeds.

## Security boundaries

- `identity.se` contains an opaque, device-bound CryptoKit key representation and authenticated envelope, not a plaintext private key. The Secure Enclave enforces device-owner authentication when the private key is used.
- The sidecar is an ordinary file and does not bind access to the `vault` code signature. Another process owned by the same macOS user can copy it and request its own authentication.
- After authentication, the age identity is briefly available in the `vault` process. A compromised process can inspect its memory and requested secret values.
- Cancellation, unavailable hardware, lockout, invalid sidecar data, and envelope authentication errors fail closed. Existing Keychain entries are not used to mask these errors.
- The recovery passphrase is an alternate route to the age identity. Protect it independently; a copy stored beside the encrypted identity is not equivalent to offline backup protection.
- Secret names and the age recipient are visible. File permissions protect against other local users, not hostile same-user processes.

## Evidence

The isolated CryptoKit tests use generated identities, dummy plaintext, and private files under `.work/tmp`. The in-memory opt-in test verified a noninteractive denial, an authorized unwrap followed by age decryption, and another noninteractive denial using a fresh `LAContext`. The file-backed opt-in test exercises initialization and decryption through the actual private-file storage code. It also proves a wrong recovery passphrase leaves the sidecar unchanged and a correct passphrase replaces it with a new sidecar that still decrypts the same secret. Authentication modality was not recorded, so the successful prompt is evidence of device-owner authorization, not Touch ID specifically.

`TMPDIR=.work/tmp cargo test` passed with 15 library, 19 binary, 22 integration, and 3 PTY tests; two Secure Enclave hardware tests are ignored by default. `TMPDIR=.work/tmp cargo clippy --all-targets --all-features -- --deny warnings` passed on macOS. Both ignored Secure Enclave tests also passed interactively: the in-memory denial/unwrap/age-decryption test in 4.73 seconds and the file-backed recovery/decryption test in 5.63 seconds. A Linux-targeted all-target clippy check also passed after removing an unused import from the Linux backend. The ad-hoc signature check passed on a temporary copy of the final debug binary.

The Data Protection Keychain campaign remains a separate, isolated experiment. On the examined Mac, an ad-hoc Data Protection add failed with `errSecMissingEntitlement`, while a file-Keychain item requesting `userPresence` remained readable with interaction disabled. This rules out the current file-Keychain access policy as proof of user-presence enforcement; it does not rule out a Personal Team profile. That route is no longer required by the selected local Secure Enclave design.

## CLI hardening completed

- Removed the ineffective `vault lock` command and its exported Rust API after an isolated test showed the partition-list edit did not revoke reads.
- Terminal secret and passphrase input fails closed if terminal settings cannot be read or echo cannot be disabled. Read, write, and restoration errors are surfaced; interrupt and job-control handling restore the terminal.
- Exec constructs child environment overrides without mutating the parent, spawns directly without a shell, inherits streams, and returns the child status.
- `purge` rejects extra arguments before touching storage.
- Default tests do not query the user's production Keychain for absent items. The dedicated Keychain harness uses an isolated disposable keychain and exact dummy identifiers.

## Remaining verification

Still unverified: whether each successful prompt used Touch ID or the Mac password; explicit cancellation behavior on the current hardware; attached and detached tmux, SSH, locked-session, and non-GUI behavior for an authorized read; recovery after copying the encrypted store to another Mac; and continued access after rebuilding or replacing the CLI. Do not infer these from the local positive test.

## Earlier campaign decisions

- The pinned Rust nightly, CI, and release workflow were left unchanged.
- No production Keychain items were accessed by campaign tests.
- No daemon, GUI, privileged helper, PAM integration, IPC service, or external CryptoKit crate was added.
- The existing Rust `age` implementation and `zeroize` dependency are reused; CryptoKit is provided by macOS. A narrow Swift C ABI bridge avoids an external plugin process. This adds a Swift compiler requirement to macOS builds. The final debug binary is 4,897,552 bytes, up 4,050,368 bytes from the recorded 847,184-byte pre-campaign baseline. No clean-build timing comparison was made.

## References

- Apple [Secure Enclave P-256 key agreement](https://developer.apple.com/documentation/cryptokit/secureenclave/p256/keyagreement/privatekey)
- Apple [Storing CryptoKit keys in the Keychain](https://developer.apple.com/documentation/cryptokit/storing-cryptokit-keys-in-the-keychain)
- Apple [TN3137: On Mac keychains](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains)
- [`age-plugin-se`](https://github.com/remko/age-plugin-se) design reference
- Foundry [Secure Enclave keystore design](https://github.com/foundry-rs/foundry/issues/15815) reference
