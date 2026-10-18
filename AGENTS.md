# vault

`vault` is a macOS CLI for storing secrets in Keychain and injecting them into child processes. The [README](README.md) documents installation and commands.

## Commands

- Build: `cargo build`
- Test: `cargo test`; Keychain authorization tests are ignored by default.
- Check: `cargo clippy --all-targets --all-features -- --deny warnings`
- Release build: `make dist` uses the pinned nightly and `rust-src`.
- Local install: `make install` signs with `SIGN_ID`; configure it to an available code-signing identity if needed.

## Invariants

- Store secrets as Generic Password items in the login Keychain under `dev.joshuarli.vault.secure`, keyed by name and protected by user presence.
- Never read the legacy `dev.joshuarli.vault` namespace; `set`, `rm`, and `purge` clean up its entries.
- Never log or write secret values to disk.
- In exec mode, parse `--` between environment specs and the command; only a nonempty `NAME=VALUE` containing exactly one `=` is literal, and all other specs are Keychain names.
- Spawn commands without a shell, inherit the process environment and standard streams, and return the child status.
- Read terminal input for `set` without echo, restore terminal settings, and reject invalid UTF-8.
