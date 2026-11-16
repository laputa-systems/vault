# vault

macOS and Linux secret manager. [README.md](README.md) is the user guide.

## Commands

- Build: `cargo build`
- Test: `make test`; Secure Enclave authentication tests are ignored by default.
- Check: `cargo clippy --all-targets --all-features -- --deny warnings`
- Release: `make dist` uses the pinned nightly and `rust-src`.
- Install: `make install` installs to `~/.local/bin`; set `PREFIX` to change the path. macOS requires Swift and Command Line Tools and signs ad hoc unless `SIGN_ID` is set.

## Verification

- Edit: `cpu-guard --cores 6 -- cargo test --bin vault <test-filter>`; cost depends on filter, unmeasured in general; check selected test count.
- Mutation gate self-test: `cpu-guard --cores 6 -- make mutants-selftest`; requires `python3` 3.11 or newer on PATH.
- Change: `cpu-guard --cores 6 -- make test` and `cpu-guard --cores 6 -- make lint`; macOS arm64 baseline test cold 15.23s, warm 4.43s, lint 9.80s; two hardware tests ignored.
- Scenario: `cpu-guard --cores 6 -- make coverage` (macOS arm64 15.22s before later tests); mutation `RUST_TEST_THREADS=2 cpu-guard --cores 6 --spin 300 -- cargo mutants --baseline run --gitignore true --jobs 3 --timeout 60 --build-timeout 300 --file src/store.rs` (51 mutants, 231.22s with timeout 120 before later terminal tests).
- Full, manual only: whole-crate mutation lists 829 mutants; 778 outside the store scope, estimated over 20 minutes. Linux musl matrix: CI `make test-ci`, cost unmeasured locally; macOS and hardware remain separate.
- CLI usage, arguments, exec environment, output and child exit status: `tests/integration.rs`; terminal input, echo and signals: `tests/terminal_cli.rs` and `src/main.rs` tests.
- Secret set/get/list/remove, passphrases, size limits and cache: Linux `tests/terminal_cli.rs` and `src/linux.rs` tests; macOS `src/macos.rs` tests, with hardware roundtrip ignored by default.
- age ciphertext and identity formats, authentication and tampering: `src/store.rs` tests; Linux external rage interoperability test skips without rage 0.12.1 and `make test` reports and counts the skip.
- Secure Enclave sidecar and ABI: `src/secure_enclave.rs` tests; hardware authentication test ignored by default. Same-Mac recovery roundtrip is ignored by default; cross-Mac recovery: none.
- macOS cache socket protocol: `src/macos.rs` identity cache tests; Linux keyring assertions can skip when unavailable and `make test` reports and counts the skip.
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
