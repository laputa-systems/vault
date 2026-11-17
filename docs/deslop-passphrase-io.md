# Passphrase descriptor and prompt I/O boundary

This component exercises the actual private `read_passphrase` in a child attached to a disposable parent-owned PTY. The child never accesses a store. The existing harness supplies deadline-bounded compiler and child waits, process-group termination, PTY closure and reaping; it inherits `LLVM_PROFILE_FILE`. The child compares its descriptor set before and after the call, and the parent compares terminal settings (excluding Darwin's transient PENDIN bit).

The interposer is armed only by a marker in the owned child directory. It fails an exact `/dev/tty` open, or an exact prompt/newline write to a descriptor whose Darwin `F_GETPATH` is exactly `/dev/tty` in the child with its owned controlling PTY. It records the injected call; a separately armed control runs the actual operations without injection. The open failure must become the controlling-terminal-required error. Prompt and final newline failures must retain EIO and the prompt operation; invalid UTF-8 plus newline failure must preserve both errors. The parent observes prompt publication and hidden echo before feeding input, except when an earlier injected failure makes that impossible.

This component does not qualify `isatty`, either descriptor clone, terminal get/set syscalls, or signal delivery in the narrow post-read window. It does not repeat the previously qualified signal primitives or the five `read_passphrase` mutants. Linux, hardware, cross-Mac recovery and CI remain outside this native component; broader DSLP-4 remains open.

## Reproduction and results

On Darwin arm64, base `c67f65fe73dde98fdcc8d0924cd145fa85f8bc09`, with the pinned nightly and cargo-mutants 27.1.0, run from the worktree:

```sh
mkdir -p .work/tmp
export PATH=/Users/josh/d/stuff/.work/tools/bin:$PATH TMPDIR=$PWD/.work/tmp
export CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1 RUSTC_WRAPPER=kache
cpu-guard --cores 1 -- cargo test --bin vault read_passphrase_owned_terminal_cleanup -- --exact tests::read_passphrase_owned_terminal_cleanup --nocapture
cpu-guard --cores 1 -- make test
cpu-guard --cores 1 -- make lint
```

All three exited 0. The focused test selected one and passed; the full suite passed 69 unit tests (two hardware ignores), 29 integration and four terminal tests; cache-spawn passed and named optional skips were zero. The non-UTF-8 filename case was unrun due to Darwin EILSEQ. Before the final focused pass, an early-failure child exited before the PTY inspection and the test failed with ENOTTY; the bounded child/parent release handshake fixes that test-harness race.

For a negative control, temporarily change the `(Err(read), Err(source))` arm in `read_passphrase` to `let _ = source; return Err(read);` and run the focused command above. It exited 101: the `io-invalid-newline` child reported `wrong combined error: Err(InvalidUtf8)`. Restore the original arm before proceeding. The final full suite exercised the restored code.

Inventory and selection (the lock belongs only to its successful `mkdir` owner):

```sh
cargo mutants --no-config --skip-calls-defaults=false -f src/main.rs --list --json > .work/tmp/io-all.json
cargo mutants --no-config --skip-calls-defaults=false -f src/main.rs -F 'read_without_echo([^_a-z]|$)' --list --json > .work/tmp/io-selected.json
jaq -r '.[] | select(.function.function_name == "read_without_echo") | .name' .work/tmp/io-all.json | sort > .work/tmp/io-all-selected.txt
jaq -r '.[].name' .work/tmp/io-selected.json | sort > .work/tmp/io-filter-selected.txt
diff -u .work/tmp/io-all-selected.txt .work/tmp/io-filter-selected.txt
export CARGO_TARGET_DIR=$PWD/.work/tmp/io-mutant-target
timeout -k 5 1200 sh -c 'n=0; until mkdir /Users/josh/d/stuff/.work/tmp/mutation.lock 2>/dev/null; do n=$((n+1)); [ "$n" -lt 150 ] || exit 73; sleep 2; done; trap "rmdir /Users/josh/d/stuff/.work/tmp/mutation.lock" EXIT; cpu-guard --cores 1 -- cargo mutants --in-place --no-config --skip-calls-defaults=false -f src/main.rs -F "read_without_echo([^_a-z]|$)" --baseline run --timeout 60 --build-timeout 300 --output .work/tmp/io-mutation -- --bin vault read_passphrase_owned_terminal_cleanup'
```

Both inventories had the same four identities and the diff exited 0. The mutation command exited 0 with a fresh passing baseline, four caught, zero missed, unviable or timed out:

- `src/main.rs:756:5: replace read_without_echo -> Result<String, CliError> with Ok(String::new())` — caught at the prompt deadline.
- `src/main.rs:756:5: replace read_without_echo -> Result<String, CliError> with Ok("xyzzy".into())` — caught at the prompt deadline.
- `src/main.rs:794:34: replace == with != in read_without_echo` — caught by the signal trace assertion.
- `src/main.rs:802:8: delete ! in read_without_echo` — caught by the prompt I/O error assertion.

These four generated mutations do not individually mutate the open or combined-output branches; the injected syscall cases and negative control are the direct evidence for those boundaries. This is not a full-crate mutation result.
