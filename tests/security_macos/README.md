# macOS security harnesses

This directory holds isolated checks for the Secure Enclave store and the
legacy file-Keychain behavior. The checks use disposable data, not vault's
production Keychain service.

## Secure Enclave tests

Run the noninteractive unit tests with:

```sh
TMPDIR=.work/tmp cargo test --bin vault
```

These two ignored tests require Secure Enclave hardware and may request
device-owner authentication:

```sh
TMPDIR=.work/tmp cargo test --bin vault secure_enclave_wrap_denies_noninteractive_access_and_unlocks_age_identity -- --ignored --exact --nocapture
TMPDIR=.work/tmp cargo test --bin vault macos::tests::secure_enclave_store_roundtrips_age_secret_from_private_files -- --ignored --exact --nocapture
```

They use generated keys and dummy age ciphertexts. The tests check noninteractive
denial, authorized unwrap, age decryption, and recovery with a disposable store.
They do not establish whether authentication used Touch ID or the login
password. SSH, locked sessions, cross-Mac recovery, and rebuilt-binary access
remain untested. The file-backed test does not access Keychain.

Ensure `.work/` is ignored in `.git/info/exclude` and create `.work/tmp` before
running commands that use it.

## Data Protection and file-Keychain harness

Run the noninteractive checks from the worktree:

```sh
tests/security_macos/run.sh
```

The harness uses the fixed service `dev.joshuarli.vault.security-harness`,
UUID-scoped accounts, dummy values, and a temporary file Keychain. Cleanup
attempts to delete exact test records and restore the original Keychain search
list.

`tests/security_macos/run.sh --gate` also inspects installed signing identities
and profiles. It creates no signing identities or profiles. A successful script exit does not
prove Data Protection access; require `data_protection_probe=success` from the
provisioned app attempt. `tests/security_macos/run.sh --interactive` requires a
terminal and may present an authentication prompt.

The Data Protection probe tests the restricted Keychain route. It does not
validate the current age and Secure Enclave storage backend.
