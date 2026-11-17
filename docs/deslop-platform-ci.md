# Platform-aware mutation CI: local evidence

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
result from another platform. The later gate partitions the selected union; this observation does not
qualify the whole change or either remote platform job. Hardware authentication, cross-Mac
recovery, Linux keyring behavior and remote CI remain unverified.


## Selection and limits

The CI plan generates every numbered shard for both Linux and macOS from the
same configured count. Each job classifies the entire change, independently
builds its platform union, writes a fresh run directory and `inventory.json` with the reasons for every
identity, and selects its disjoint sorted slice. A shard fails if the union
would exceed 20 identities per shard. The entire run has a 1,200-second budget;
incomplete results, unconfirmed timeouts and missing critical selections fail.
The `CI` aggregator requires the planner and the whole job matrix. A local
`make mutants-diff` requires an explicit `MUTANTS_SHARD`; one shard is not a
whole-change verdict.

Changed production lines are unioned with the platform's critical selection
for test, fixture, build or gate changes. When changed lines produce no active
mutants, the current file is selected. Deleted production selects the critical
scope. A changed Swift production file cannot be mutated by this gate and
fails closed. Unknown paths, unrecognized conditional-compilation forms and
unsupported source files fail closed. Linux selects store and terminal input;
macOS selects store, terminal input and the cache functions. Existing exact
exclusions are unchanged. Hardware authentication remains outside these
noninteractive jobs. The 51-store result is a component receipt only, and
13 minutes is not a ten-minute median claim.

## Candidate mixed-change negative control for the parent

In a throwaway PR, delete the entire `store::tests::decrypted_values_enforce_size_limits`
test. In the unrelated production function `parse_env_spec` replace
`!value.contains('=')` with `value.split('=').count() == 1`; this preserves the
parser's result and its existing literal and secret-spec tests exercise it.
Run the ordinary Linux checks first and require them to pass. Then run every
Linux mutation shard against that PR's base and retain all artifacts.

The proposed critical witness is the `decrypt_identity` comparison at the
1,024-byte limit (`>` changed to `>=`): the deleted test supplies an exact
1,024-byte plaintext and checks the distinct invalid-identity error. Inspect
the inventory for this identity labeled `critical src/store.rs`, and require
its result to be missed after deletion. Also require the inventory to contain
changed `parse_env_spec` identities labeled `changed src/main.rs`, and inspect
at least one changed-code mutant's caught log. The aggregate must fail because
of the reopened store miss. If the witness is still caught, ordinary checks
fail, the changed identity is missed, or either inventory label is absent,
this control has not proved the union and needs investigation. This is a
blueprint, not an executed negative-control result; the parent owns the
throwaway PR and remote qualification.

A fresh configured store listing at the base contained 51 identities. Replaying
its metadata through the platform selector includes all 51 on Linux and 43 on
macOS; all eight `validate_name` identities are Linux-only. Cargo-mutants
reports the function span beginning at the `#[cfg]` attribute, and its
constant-expression identities have no function object. Both forms are covered
by selector regression tests. The first PR-inventory attempt failed before a
baseline on the missing function object. A second attempt was stopped after
its inventory revealed that it incorrectly assigned a Linux-only identity to
macOS; its partial mutation results do not qualify anything.

## Earlier gate execution

Before the final scope and selector corrections, a native macOS gate shard
against `bf3dcd9` completed in 131.6 seconds, exit 0. With config SHA-256
`2aa1fcfc940425b4a0abe98b7fbc3286e32144b37b6baadae6454465d5c45d98`,
it selected six of a 91-identity union: two caught (`store_cached_identity`
return and `seed_line` return) and four unviable (`clear_identity_cache`,
`read_cache_line`, `read_daemon_seed` and `handle_cache_request` returns).
There were no misses or timeouts. This is an earlier configuration receipt,
not a qualification of the current gate or its complete union. Its logs are
in `.work/tmp/platform-gate-shard0.log` and `.work/mutants-gate/phase-0/`.

## Current native shard receipt

On Darwin arm64 at base `bf3dcd9b4d893dce12de453705ef0b73dae4e0bf`, with
`src/main.rs` SHA-256 `97cf062200fc50de2ede8f8bf3ca4379c793b8cf2e53e9c96273bdfe752cf76d`,
`src/macos.rs` SHA-256 `b22790e78652145be94e1db63cf3fe77fd705dc1d0aacb256dcb46933e46f1f5`,
`src/store.rs` SHA-256 `2011b7c805545c9ca93dedf2196988b0ea2322621e30ca71730bd63c5aad86ce`,
and gate-config SHA-256 `bb89f6a66f12fcc872e6b24726b8c24697233d5648af075c9b669a1302a3d28c`,
the following ran under the shared mutation lock and one owned heavy slot,
with the same environment as the four-mutant receipt above:

```sh
cpu-guard --cores 2 -- python3 -B scripts/mutants_gate.py bf3dcd9b4d893dce12de453705ef0b73dae4e0bf macos 0
```

The gate reported a successful fresh baseline, a 134-identity platform union,
and nine identities in shard zero. The full inventory and logs are under
`.work/mutants-gate/run-se7b61tq/`; the command log is
`.work/tmp/platform-current-shard0.log`. In 239.6 seconds it reported five
caught, four unviable, no misses or timeouts. The shell exit was not captured
after the controlling turn was interrupted; the complete gate log reports
no failure. Exact selected identities and classes:

- Unviable: `src/macos.rs:319:5` replace `clear_identity_cache` with `Ok(Default::default())`.
- Caught: `src/macos.rs:434:5` replace `store_cached_identity` with `Ok(())`.
- Unviable: `src/macos.rs:497:5` replace `read_cache_line` with `Ok(Zeroizing::from_iter([vec![1]]))`.
- Unviable: `src/macos.rs:576:5` replace `read_daemon_seed` with `Ok(("xyzzy".into(), Zeroizing::from_iter(["xyzzy".into()])))`.
- Caught: `src/macos.rs:600:5` replace `seed_line` with `Ok("xyzzy".into())`.
- Unviable: `src/macos.rs:728:5` replace `handle_cache_request` with `Default::default()`.
- Caught: `src/store.rs:123:30` replace `!=` with `==` in `parse_recipient`.
- Caught: `src/store.rs:34:24` replace `>` with `==` in `decrypt_secret`.
- Caught: `src/store.rs:8:66` replace `+` with `-`.

The unviable replacements need unsupported `Default` or `Zeroizing::from_iter`;
they do not provide test evidence. No survivor or confirmed hang was reported.
Other shards, Linux execution, remote CI and the mixed-change negative control
remain unverified; a passing shard is not a whole-change qualification.

## Hosted Linux receipts

Run [44177303366](https://github.com/laputa-systems/vault/actions/runs/44177303366)
uses candidate `0671858badb1f1fb7fea852e35bbe8929f092afe` against
`0e72b21112b840aa5b7fa373eeeab79e63ed59bb`. Ordinary tests passed on
macOS and both Linux musl architectures. The mutation jobs exceeded their
Linux budget and also found survivors.

Linux shard 6's uploaded outcomes file records nine caught, one unviable
and one unresolved identity. The old gate reported zero outcomes when the
watchdog interrupted cargo-mutants. The successor validates the partial
file, reports the ten completed outcomes, and still fails the gate.
`make mutants-selftest` exercises interruption with one caught mutation
and one unresolved identity. The assertion fails on the earlier gate.

Linux shard 13 observed `require_exact_name` changed from `> 1` to `< 1`.
The CLI fixture now requires the literal surplus-argument diagnostic and
empty stdout for all four secret commands in an isolated environment.
`cargo test --locked --test integration
secret_commands_reject_surplus_names_before_accessing_storage` passes.
The exact injected comparison fails the assertion and is then restored.
The other reported shard 13 survivor changed a union of disjoint terminal
flag bits to XOR. Its equivalence needs a recorded platform disposition
before the next full run.

The shard 6 baseline spent 115.72 seconds on the 47 unit tests and 10.14
seconds on its eight terminal tests. Establish a cheaper test selection
with proof of the same critical decisions before rerunning the whole
Linux matrix. Ordinary platform tests keep their existing coverage.
