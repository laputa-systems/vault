# vault

macOS and Linux secret manager. [README.md](README.md) is the user guide.

## Commands

- Build: `cargo build`
- Test: `cargo test`; Secure Enclave authentication tests are ignored by default.
- Check: `cargo clippy --all-targets --all-features -- --deny warnings`
- Release: `make dist` uses the pinned nightly and `rust-src`.
- Install: `make install` installs to `~/.local/bin`; set `PREFIX` to change the path. macOS requires Swift and Command Line Tools and signs ad hoc unless `SIGN_ID` is set.

## Invariants

- macOS stores secrets as age ciphertexts under one Secure Enclave wrapped X25519 identity with a separate age-encrypted recovery identity.
- Linux stores age ciphertexts under a passphrase-encrypted X25519 identity; cache behavior and the same-UID trust boundary are documented in [README.md](README.md).
- macOS reads and writes secrets only in the age store protected by the Secure Enclave identity.
- Limit secret values to 16 MiB and never log or write plaintext secret values to disk.
- Do not use the retired Keychain services `dev.joshuarli.vault.secure` and `dev.joshuarli.vault`.
- In exec mode, parse `--` between environment specs and the command; only nonempty `NAME=VALUE` strings with exactly one `=` are literal.
- Spawn commands without a shell, inherit environment and standard streams, and return the child status.
- Read terminal input without echo, restore terminal settings, and reject invalid UTF-8.

## Topic map

- Why vault avoids the macOS Keychain: [docs/keychain.md](docs/keychain.md)
- macOS storage harnesses: [tests/security_macos/README.md](tests/security_macos/README.md)
