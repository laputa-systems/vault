# vault

macOS and Linux secret manager. [README.md](README.md) is the user guide.

## Commands

- Build: `cargo build`
- Test: `make test`; Secure Enclave authentication tests are ignored by default.
- Check: `cargo clippy --all-targets --all-features -- --deny warnings`
- Release: `make dist` uses the pinned nightly and `rust-src`.
- Install: `make install` installs to `~/.local/bin`; set `PREFIX` to change the path. macOS requires Swift and Command Line Tools and signs ad hoc unless `SIGN_ID` is set.

## Verification

- Edit: `cpu-guard --cores 2 -- cargo test --bin vault <test-filter>`; check the selected count. Use short worktree paths so Unix sockets fit macOS limits.
- Mutation gate self-test: `cpu-guard --cores 2 -- make mutants-selftest`; requires Python 3.11 or newer.
- Change: `RUST_TEST_THREADS=2 cpu-guard --cores 2 -- make test` and `cpu-guard --cores 2 -- make lint`; native macOS warm test median 24.24s at `6856af3` versus 6.41s before, three interleaved gated pairs. Two hardware tests are ignored. [Settings and limits](docs/deslop-filesystem.md#native-qualification-at-6856).
- Coverage: `RUST_TEST_THREADS=2 cpu-guard --cores 2 -- make coverage`, using the shared mutation lock and a distinct target. Native Rust report: 2970/3571 lines, 361/486 branches, including inline tests; Linux and Swift are outside it.
- Scenario mutation: one test thread, one mutant at a time, fresh baseline, separate mutation/ordinary targets and shared lock. Exact bounded selections and survivor dispositions: [filesystem evidence](docs/deslop-filesystem.md). The whole-change CI gate is unqualified for changed macOS-only functions on Linux.
- Full mutation is manual only; the historical whole-crate listing had 829 identities, not a current completed result. Linux musl runs `make test-ci`; hardware qualification remains separate.
- CLI usage, arguments, exec environment, output and child exit status: `tests/integration.rs`; terminal input, echo and signals: `tests/terminal_cli.rs` and `src/main.rs` tests.
- Prompt-to-read echo ownership and prompt-failure restoration: `src/main.rs` tests `prompt_and_read_share_one_hidden_terminal_session` and `prompt_failure_restores_echo_and_reports_restore_failure`; Linux controlling-terminal behavior: `tests/terminal_cli.rs`. Exact proof and limits: `docs/deslop-terminal-echo.md`.
- Secret set/get/list/remove, passphrases, size limits and cache: Linux `tests/terminal_cli.rs` and `src/linux.rs` tests; macOS `src/macos.rs` tests, with hardware roundtrip ignored by default.
- age ciphertext and identity formats, authentication and tampering: `src/store.rs` tests; CI requires rage 0.12.1 from the checksum-pinned owned release, installed by `scripts/install-rage.sh`; developer skips remain visible.
- Secure Enclave sidecar and ABI: `src/secure_enclave.rs` tests; hardware authentication test ignored by default. Same-Mac recovery roundtrip is ignored by default; cross-Mac recovery: none.
- macOS cache socket protocol: `src/macos.rs` identity cache tests and accept-refusal interposition; Linux keyring assertions can skip when unavailable and `make test` reports and counts the skip. Required host checks: `tests/security_linux/README.md`.
- macOS cache startup and cached secret operations: `cargo test --test cache_spawn`; it uses a disposable RAM identity, private directory and owned daemon, without a real hardware key or prompt. Integration checks reject either missing daemon-seed field.
- Public library API and network endpoints: none; this is a CLI.
- Performance workload: none; no benchmark or established user-visible performance gate exists.

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
