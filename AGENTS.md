# vault

macOS and Linux secret manager. [README.md](README.md) is the user guide.

The roadmap, [docs/roadmap.md](docs/roadmap.md), holds all current and future work; its Status is the resume point.

## Commands

- Build: `cargo build`
- Test: `make test`; Secure Enclave authentication tests are ignored by default.
- Check: `cargo clippy --all-targets --all-features -- --deny warnings`
- Release: `make dist` uses the pinned nightly and `rust-src`.
- Install: `make install` installs to `~/.local/bin`; set `PREFIX` to change the path. macOS requires Swift and Command Line Tools and signs ad hoc unless `SIGN_ID` is set.

## Verification

`make clean` removes the checkout’s ordinary `./target` directory. It refuses a file or symlink at that path.

- `cpu-guard --cores 6 -- make test`: macOS arm64 cold 15.23s, warm 4.43s; two Secure Enclave authentication tests ignored.
- `cpu-guard --cores 6 -- make lint`: macOS arm64 9.80s after test build.
- CLI usage, arguments, exec environment, output and child exit status: `tests/integration.rs`; terminal input, echo and signals: `tests/terminal_cli.rs` and `src/main.rs` tests.
- Prompt-to-read echo ownership and prompt-failure restoration: `src/main.rs` tests `prompt_and_read_share_one_hidden_terminal_session` and `prompt_failure_restores_echo_and_reports_restore_failure`; Linux controlling-terminal behavior: `tests/terminal_cli.rs`. Exact proof and limits: `docs/deslop-terminal-echo.md`.
- Secret set/get/list/remove, passphrases, size limits and cache: Linux `tests/terminal_cli.rs` and `src/linux.rs` tests; macOS `src/macos.rs` tests, with hardware roundtrip ignored by default.
- age ciphertext and identity formats, authentication and tampering: `src/store.rs` tests; Linux external rage interoperability requires rage 0.12.1 in CI and visibly skips locally when unavailable.
- Secure Enclave sidecar and ABI: `src/secure_enclave.rs` tests; hardware authentication test ignored by default. Same-Mac recovery roundtrip is ignored by default; cross-Mac recovery: none.
- macOS cache socket protocol: `src/macos.rs` identity cache tests. Linux session keyring assertions are an owner-run boundary: run `CI=true cargo test identity_cache_permissions_expiry_refresh_and_revocation_are_enforced -- --nocapture` on a Linux host with a usable session keyring and readable `/proc/keys`. The CI container returns `Operation not permitted` for keyctl, so `make test-ci` names and excludes that test; cache-scope assertions in `cache_clear_is_store_scoped_and_recipient_replacement_does_not_hide_stale_cache` also skip when unavailable.
- Public library API and network endpoints: none; this is a CLI.
- Performance workload: none; no benchmark or established user-visible performance gate exists. Ranked gaps are tickets in [TODO.md](TODO.md).

## Invariants

- macOS stores age ciphertexts beside a Secure Enclave wrapped X25519 identity and a separate age-encrypted recovery identity.
- Linux stores age ciphertexts under a passphrase-encrypted X25519 identity. Cache behavior and the same-UID trust boundary are in [README.md](README.md).
- macOS reads and existing-store writes use the cached identity when its public key is the recipient file, and otherwise unwrap the Secure Enclave identity. The write fails when that public key does not match the recipient. Secret values stay in the age store.
- Limit secret values to 16 MiB and never log or write plaintext secret values to disk.
- Do not use the retired Keychain services `dev.joshuarli.vault.secure` and `dev.joshuarli.vault`.
- In exec mode, parse `--` between environment specs and the command; only nonempty `NAME=VALUE` strings with exactly one `=` are literal.
- Spawn commands without a shell, inherit environment and standard streams, and return the child status.
- Read terminal input without echo, restore terminal settings, and reject invalid UTF-8.

## Topic map

- Why vault avoids the macOS Keychain: [docs/keychain.md](docs/keychain.md)
- macOS storage harnesses: [tests/security_macos/README.md](tests/security_macos/README.md)
- Existing-store writes encrypt only to an identity that matches `recipient`: [docs/rfc/VLT-1-recipient-write.md](docs/rfc/VLT-1-recipient-write.md)
