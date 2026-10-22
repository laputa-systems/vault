# vault

macOS and Linux secret manager. [README.md](README.md) is the user guide.

## Commands

- Build: `cargo build`
- Test: `cargo test`; Secure Enclave authentication tests are ignored by default.
- Check: `cargo clippy --all-targets --all-features -- --deny warnings`
- Release: `make dist` uses the pinned nightly and `rust-src`.
- Install: `make install` signs ad hoc by default; set `SIGN_ID` to use another identity. macOS requires Swift and Command Line Tools.

## Invariants

- macOS stores new secrets as age ciphertexts under one Secure Enclave wrapped X25519 identity with a separate age-encrypted recovery identity.
- Linux stores age ciphertexts under a passphrase-encrypted X25519 identity and caches the unlocked identity in the Linux user-session keyring for 15 minutes of inactivity.
- With an age store present on macOS, read Keychain compatibility items only after successfully unlocking the Secure Enclave identity and only for names absent from the age store.
- Limit secret values to 16 MiB and never log or write plaintext secret values to disk.
- Never read `dev.joshuarli.vault`; `set`, `rm`, and `purge` clean up that legacy namespace.
- In exec mode, parse `--` between environment specs and the command; only nonempty `NAME=VALUE` strings with exactly one `=` are literal.
- Spawn commands without a shell, inherit environment and standard streams, and return the child status.
- Read terminal input without echo, restore terminal settings, and reject invalid UTF-8.

## Topic map

- macOS storage harnesses: [tests/security_macos/README.md](tests/security_macos/README.md)
