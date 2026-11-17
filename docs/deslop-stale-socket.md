# Stale cache socket fixture

The stale-socket test must leave a socket pathname with no listener. Binding in the test process and dropping the listener is insufficient: a concurrent fork can inherit the listener before the drop. A connection then succeeds, but no process serves it, so the cache read fails instead of removing the socket. `connect_cache` removes a socket only after connection refusal. The fixture now binds in a separate invocation of the test binary and waits for its exit. The test process never owns that listener. The existing fetch, socket removal, and already-clear assertions remain in place; the fetch path does not prompt.

## Controlled overlap

On macOS arm64, with base `6a4b7d5936a88dcb13c03ffa02545a9ed2d9a006`, a temporary test-only fault inserted the following immediately after the original bind, before `drop(listener)`:

```rust
unsafe extern "C" { fn fork() -> i32; fn sleep(seconds: u32) -> u32; fn _exit(status: i32) -> !; }
let pid = unsafe { fork() };
assert!(pid >= 0);
if pid == 0 { unsafe { sleep(1); _exit(0) } }
```

Run the focused command below. The child holds the inherited listener until it exits. The original test exited 101 with `identity cache connection closed early` at the fetch assertion. This is a bounded fault injection, not a production change.

For the candidate, temporarily replace the fixture's `status()` call with `spawn()`, passing a `VAULT_TEST_RELEASE` pathname in the test directory. In the helper, after binding, wait until that pathname exists. In the parent, wait for the socket pathname, fork a child that sleeps two seconds and exits, create the release file, and wait for the socket-creating child to exit before performing the unchanged assertions. Wait for the forked child after the assertions. This forces the fork while the listener exists in the separate child. The same focused command exited 0: fetch returned no identity and removed the socket while the forked child was still alive. Remove the temporary synchronization and fork instrumentation afterward. Use a disposable test directory and only async-signal-safe functions in the forked child.

```sh
CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1 RUSTC_WRAPPER=kache TMPDIR=$PWD/.work/tmp cpu-guard --cores 1 -- cargo test macos::tests::stale_cache_socket_is_removed_without_prompting -- --exact --nocapture
```

For concurrent process stress, temporarily spawn a thread in the candidate test before starting the socket helper. Have it launch `/usr/bin/true` 100 times with `Command::status`, assert each succeeds, and join it after the existing assertions. Run the focused command ten times. All ten runs passed, with 1,000 process launches. Remove the stress thread afterward. These experiments use only disposable sockets and no Keychain, Secure Enclave authentication, user store, or live cache.

Final native verification used the same environment with `cpu-guard --cores 1 -- make test` and `cpu-guard --cores 1 -- make lint`: both exited 0. The suite ignored two hardware authentication tests. This is a test-only change; no artifact or runtime performance claim is made and no timing gate was measured.
