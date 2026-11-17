# Signal failure witnesses

Parent acceptance: create the scratch directory exclusively before acquiring
its cleanup guard, so a creation failure cannot delete a pre-existing path.
The focused native test passes after this test-only correction, exit 0;
final `src/main.rs` SHA-256 is
`464c5ac8436b5b4f76ac34c518ee94e99bd2d59e778d6f0830493b0db682800d`.
An independent `cargo mutants --list --json --no-config
--skip-calls-defaults=false -f src/main.rs -F
'SignalHandlers::(install|restore|suspend_and_resume)'` produces the same eight
identities as the completed receipt, compared as sorted exact names. No new
production code or assertion changed; the mutation evidence remains valid.

Scope: `SignalHandlers::{install,restore,suspend_and_resume}` at base `6856af3421b82cfb7ff6bf0d5b35eede660798aa`. The macOS-only test runs each case in a separately owned test process. A Darwin `DYLD_INSERT_LIBRARIES` fixture is armed only after that child enters the test. It writes syscall events and injected error markers to a private scratch directory; the parent requires both entry and completion markers and the exact event sequence. Compiler and test children have deadlines and group cleanup. The child inherits `LLVM_PROFILE_FILE`. No user store, authentication, or hardware is used.

The fixture supplies otherwise impractical syscall failures, not evidence that ordinary valid calls fail. Cases cover a second installation failure, interruption setup failure after saving its prior disposition, combined setup and cleanup errors with a drop retry, multiple restore failures with first-error selection and retained retry entries, failure to raise after restoration, and suspend-time restore failure. The uninjected control installs real handlers, sends SIGINT to its own child, observes the pending signal, and restores the handlers. Existing real PTY tests cover terminal behavior; no Linux or hardware behavior is inferred from interposition. The separate passphrase restore/error mapping is not exercised by this fixture. The broader DSLP4 remains open; the three historical confirmed hangs remain separately recorded.

## Reproduction and results

Host: Darwin arm64, selected nightly from `rust-toolchain.toml`, cargo-mutants 27.1.0. Tested source SHA-256: `src/main.rs` `ac9045302254da2138d2e1e9ba0c170c647040c3b21e6aff4035509f84f10e05`; `tests/signal_fault.c` `c440d2b35e7d0717c7fa6541e3f69b9c734447d64986b24d05a716095c5ab2be`. Base commit above; this is a tests-only working-tree change. All commands below ran from the worktree; `.work/tmp` existed and was the absolute `TMPDIR`. The environment was:

```sh
export PATH=/Users/josh/d/stuff/.work/tools/bin:$PATH
export TMPDIR=$PWD/.work/tmp RUSTC_WRAPPER=kache CARGO_BUILD_JOBS=1
```

Focused test: `RUST_TEST_THREADS=1 cpu-guard --cores 2 -- cargo test --bin vault signal_handler_native_faults -- --nocapture`: exit 0, one passed, 67 filtered. An earlier execution corrected the Darwin SIGTSTP literal from 20 to 18; the final run above passed.

Hand fault: in the first `SignalSetup` failure branch, temporarily replace `let restore = handlers.restore().err();` with `let restore = None;`, run that same focused command, then restore the original line. Exit 101: the combined case asserted `None` versus `Some(5)` for the lost cleanup error. This was an actual failing new oracle, not a source-shape check. The original line was restored before final inventory.

The final inventory used a distinct mutation target and exclusive shared lock, with a bounded lock wait, an outer deadline and an explicit recorded exit:

```sh
export RUST_TEST_THREADS=1 CARGO_TARGET_DIR=$PWD/.work/tmp/mutation-target
lock=/Users/josh/d/stuff/.work/tmp/mutation.lock
acquired=0
for attempt in {1..300}; do
  if mkdir "$lock" 2>/dev/null; then acquired=1; break; fi
  sleep 1
done
[ "$acquired" = 1 ] || exit 90
trap 'rmdir "$lock"' EXIT
set +e
timeout -k 5 1200 cpu-guard --cores 2 -- cargo mutants --in-place --baseline run \
  --file src/main.rs --re 'SignalHandlers::(install|restore|suspend_and_resume)' \
  --timeout 60 --build-timeout 300 --output .work/tmp/mutation-final-output -- --bin vault
result=$?
printf 'outer exit: %s\n' "$result"
```

Outer exit 0; fresh baseline: 66 passed, two ignored; eight generated mutations: seven caught, one unviable, zero missed and zero timeout. The unviable replacement of `install` with `Ok(Default::default())` fails E0277 because `SignalHandlers` has no `Default`; it provides no test evidence. The other seven are the two install comparison reversals, removal of the minus sign from `-1`, replacement of suspend with `Ok(())`, reversal of the raise comparison, replacement of restore with `Ok(())`, and reversal of the restore comparison. Their individual logs show failures in `signal_handler_native_faults`; no critical survivor remains. An earlier inventory before the strengthened control also reported seven caught and one unviable, but its outer exit was not captured and it is not the final proof.

Final checks used a separate target:

```sh
export RUST_TEST_THREADS=2 CARGO_TARGET_DIR=$PWD/.work/tmp/final-target
cpu-guard --cores 2 -- make test
cpu-guard --cores 2 -- make lint
```

Both exited 0. The native suite reported 66 binary tests passed, two hardware tests ignored, 28 integration tests passed, four PTY tests passed, and zero named optional skips; the `cache_spawn` harness also exited successfully. The non-UTF-8 filename case reported unrun due to Darwin `EILSEQ` (error 92). The two Secure Enclave tests requiring hardware and interactive authentication were ignored. Linux host/keyring and cross-Mac behavior were not tested. No coverage or full-crate mutation run was performed in this task; the supplied base coverage was 2970/3571 lines and 361/486 branches. A pass here does not close the broader DSLP4 or the separately recorded historical hangs.
