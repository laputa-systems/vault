# Platform CI work: incomplete local evidence

At `bf3dcd9b4d893dce12de453705ef0b73dae4e0bf` on Darwin arm64, the
`read_without_echo` scenario completed with a fresh baseline in 45 seconds:
four caught, zero missed, unviable or timed out. This is not a whole-change
or CI qualification. `src/main.rs` SHA-256:
`97cf062200fc50de2ede8f8bf3ca4379c793b8cf2e53e9c96273bdfe752cf76d`.
Cargo-mutants was 27.1.0, with the pinned nightly and default features.

With the shared mutation lock acquired first and one heavy slot owned, and
`PATH=/Users/josh/d/stuff/.work/tools/bin:$PATH`, `TMPDIR=$PWD/.work/tmp`,
`CARGO_BUILD_JOBS=1`, `RUST_TEST_THREADS=1`, `RUSTC_WRAPPER=kache`,
`PYTHON_CPU_COUNT=2`, and
`CARGO_TARGET_DIR=$PWD/.work/tmp/platform-mutant-target`, the command was:

```sh
cpu-guard --cores 2 -- cargo mutants --gitignore true --no-config --skip-calls-defaults=false -f src/main.rs -F 'read_without_echo([^_a-z]|$)' --baseline run --timeout 180 --build-timeout 300 --jobs 1 --no-shuffle --output .work/tmp/platform-scenario -- --bin vault read_passphrase_owned_terminal_cleanup
```

Exit 0. All four identities were caught: line 756 return `Ok(String::new())`,
line 756 return `Ok("xyzzy".into())`, line 794 `==` to `!=`, and line 802
`delete !`. The first two fail the prompt witness; the latter two fail the
signal trace and error assertions. Logs and the complete identities are in
`.work/tmp/platform-scenario/mutants.out`.

A configured `--in-diff` listing against `origin/main` selected 41 macOS
identities; this is only one part of the changed-code union. Existing filesystem
evidence includes equivalent survivors and cannot be replaced by a green
result from another platform. No platform-aware partition or whole-change
qualification is established here. Hardware authentication, cross-Mac
recovery, Linux keyring behavior and remote CI remain unverified.
