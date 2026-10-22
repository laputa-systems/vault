# vault

`vault` is a macOS and Linux CLI for storing secrets and injecting them into child processes. macOS stores new secrets as age ciphertexts under a Secure Enclave protected identity; existing file-Keychain items remain readable in compatibility mode. Linux uses the age store with a passphrase-unlocked identity. The [README](README.md) documents installation and commands.

## Commands

- Build: `cargo build`
- Test: `cargo test`; Keychain authorization tests are ignored by default.
- Check: `cargo clippy --all-targets --all-features -- --deny warnings`
- Release build: `make dist` uses the pinned nightly and `rust-src`.
- Local install: `make install` signs ad hoc by default; set `SIGN_ID` to use another signing identity. macOS builds also require Swift and the Command Line Tools.

## Invariants

- On macOS, encrypt new secrets (up to 16 MiB each) with age under one X25519 identity wrapped by a Secure Enclave P-256 key. Keep a separately age-encrypted recovery identity. Existing `dev.joshuarli.vault.secure` file-Keychain items remain compatibility entries with unverified user-presence enforcement; after the age identity store exists, unlock it successfully before reading a missing age name from Keychain. Never fall back to Keychain after an unlock or ciphertext error.
- On Linux, retain the age-encrypted identity, per-secret age ciphertexts, and Linux session-keyring cache.
- Never read the legacy `dev.joshuarli.vault` namespace; `set`, `rm`, and `purge` clean up its entries.
- Never log or write secret values to disk.
- In exec mode, parse `--` between environment specs and the command; only a nonempty `NAME=VALUE` containing exactly one `=` is literal, and all other specs are vault secret names.
- Spawn commands without a shell, inherit the process environment and standard streams, and return the child status.
- Read terminal input for `set` without echo, restore terminal settings, and reject invalid UTF-8.
