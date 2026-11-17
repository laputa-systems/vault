# Terminal prompt echo proof

At base `e028e29b984fe50acede18a4a2f3072e9502c96c`, the passphrase caller restored terminal settings after publishing the prompt and before `read_without_echo` entered its own session. The secret caller published its prompt before disabling echo. A person or terminal recorder observing echoed input could see a credential entered in either gap.

The owned `prompt_and_read_share_one_hidden_terminal_session` fixture records terminal operations, prompt output, and input reads. To reproduce the base observation, transplant that test's `ObservedTerminal` and `ObservedIo` fixtures onto the base and replace its reader call with the base caller's sequence:

```rust
let mut session = super::TerminalSession::enter(&mut terminal).unwrap();
output.write_all(b"prompt: ").unwrap();
output.flush().unwrap();
session.restore().unwrap();
read_without_echo(&mut input, &mut output, true, 100, &mut terminal, || None, || Ok(())).unwrap();
```

With the test's unchanged event assertion, the focused command below exited 101 on the base. The observed sequence was `hide, prompt, restore, hide, read, restore`, rather than `hide, prompt, read, restore`. This is a deterministic model of the base passphrase caller using the real common reader. It is not a native PTY reproduction of the scheduler race.

```sh
CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1 TMPDIR="$PWD/.work/tmp" CARGO_TARGET_DIR="$PWD/.work/target-native" RUSTC_WRAPPER=kache cpu-guard --cores 2 -- cargo test --bin vault tests::prompt_and_read_share_one_hidden_terminal_session -- --exact
```

The candidate passes that fixture. Its common reader publishes the prompt inside its terminal session and restores the saved settings before suspension. The prompt failure fixture checks both successful restoration and a simultaneous restoration failure. Existing PTY tests check interruption and suspend/resume restoration, and the Linux controlling-terminal test checks that its disposable passphrase is absent from output.

The final native commands both exited 0:

```sh
CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1 TMPDIR="$PWD/.work/tmp" CARGO_TARGET_DIR="$PWD/.work/target-native" RUSTC_WRAPPER=kache cpu-guard --cores 2 -- make test
CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1 TMPDIR="$PWD/.work/tmp" CARGO_TARGET_DIR="$PWD/.work/target-native" RUSTC_WRAPPER=kache cpu-guard --cores 2 -- make lint
```

Two Secure Enclave tests requiring interactive hardware authentication remained ignored. The final Linux ARM64 focused and full tests exited 0:

```sh
docker run --rm --name vault-tty-prompt-worker --cpus 2 --platform linux/arm64 -v "$PWD:/vault" -w /vault -e CARGO_BUILD_JOBS=1 -e RUST_TEST_THREADS=1 -e TMPDIR=/vault/.work/tmp -e CARGO_TARGET_DIR=/vault/.work/target-linux vault-deslop:arm64 sh -c 'cargo test --bin vault tests::prompt_and_read_share_one_hidden_terminal_session -- --exact && cargo test --test terminal_cli unix_pty::controlling_tty_passphrase_is_independent_of_piped_secrets_and_exec_prompts_once -- --exact && make test'
```

The image contained rage 0.12.1 and the interoperability test passed. A separate `--nocapture` run showed that keyring permission and cache scope assertions skipped because the container kernel denied access. No forced scheduler or syscall delay was used, and no claim is made that the observed CI failure was reproduced on a PTY.

No release build was run. One macOS debug `vault --help` observation reported 7,192,576 bytes maximum RSS and a 2,784,976-byte binary. These are observations, not performance gates.
