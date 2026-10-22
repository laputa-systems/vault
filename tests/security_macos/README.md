# macOS Secure Enclave checks

The ignored hardware tests use generated keys, disposable age ciphertexts, and
temporary store files. They do not access production secrets or Keychain items.

Run noninteractive unit tests with:

```sh
TMPDIR=.work/tmp cargo test --bin vault
```

These ignored tests require Secure Enclave hardware and may request device-owner authentication:

```sh
TMPDIR=.work/tmp cargo test --bin vault secure_enclave_wrap_denies_noninteractive_access_and_unlocks_age_identity -- --ignored --exact --nocapture
TMPDIR=.work/tmp cargo test --bin vault macos::tests::secure_enclave_store_roundtrips_age_secret_from_private_files -- --ignored --exact --nocapture
```

They check noninteractive denial, authorized unwrap, age decryption, and recovery
with a disposable store. They do not establish whether authentication used Touch
ID or the login password. SSH, locked sessions, cross-Mac recovery, and rebuilt-
binary access require separate interactive checks.

Ensure `.work/` is ignored in `.git/info/exclude` and create `.work/tmp` before
running commands that use it.
