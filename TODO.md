Prefix: VLT
Next: 8

# Backlog: vault

### VLT-3 · P3 · Cross-Mac recovery has no end-to-end check

- **Area:** Needs owner · two-Mac recovery
- **Where:** src/macos.rs:291, src/macos.rs:1474, tests/security_macos/README.md:19
- **Problem:** Test-gap finding: recovery decrypts the backup identity and replaces the device-bound sidecar, but the ignored roundtrip exercises only one Mac; the harness documentation says cross-Mac recovery requires a separate check. Failure of cross-Mac recovery is unproven. A user discovering an incompatibility only after moving a backup could lose access to secrets.
- **Recommendation:** Add a documented, repeatable two-Mac recovery boundary check using a disposable store, verifying recovery and readback after transfer, plus rejection of a wrong passphrase. Include src/macos.rs, src/secure_enclave.rs and src/store.rs in the critical mutation scope.
- **Fix with:** test-audit
- **Effort:** M

### VLT-4 · P3 · Port the native cache startup test from the stranded branches

- **Area:** tests
- **Where:** deslop/platform-ci tests/cache_spawn.rs; Cargo.toml test targets
- **Problem:** The stranded branches carry a native cache startup test that needs its own Cargo test target; it was not ported when the other branch tests landed, so cache spawn and startup on macOS have no witness on main.
- **Recommendation:** Port the test with its Cargo test target, prove it with one injected startup fault, then delete the stranded deslop branches.
- **Fix with:** deslop
- **Effort:** S

### VLT-5 · P3 · Secret retrieval latency has no representative measurement

- **Area:** Performance · retrieval
- **Where:** src/macos.rs:162, src/macos.rs:193, src/linux.rs:202, README.md:59
- **Problem:** Unproven regression risk: normal get and exec retrieval have no performance workload, so slower cache hits or unlocks can reach users unseen. macOS uses a socket cache or Secure Enclave and Linux uses a keyring or passphrase; authentication interaction must be separated from processing time.
- **Recommendation:** Measure verified retrieval on disposable stores for macOS cache hit and unlock and Linux keyring hit and passphrase unlock; record host, samples, baseline and completed results, and use platform profilers to attribute regressions.
- **Fix with:** bench-pyramid
- **Effort:** M

### VLT-6 · P3 · Store growth has no list or retrieval performance evidence

- **Area:** Performance · scaling
- **Where:** src/macos.rs:251, src/linux.rs:258, src/macos.rs:162, src/linux.rs:202
- **Problem:** Unproven regression risk: no representative list or get workload compares store sizes or secret sizes, so a scaling regression can ship without being noticed until users have larger stores.
- **Recommendation:** Measure successful list and get on disposable stores across representative entry counts and value sizes, verify names and values, and compare interleaved runs against a recorded baseline; use filesystem syscall counts and CPU sampling for attribution.
- **Fix with:** bench-pyramid
- **Effort:** M

### VLT-7 · P3 · CLI startup and distribution size have no ongoing performance comparison

- **Area:** Performance · startup
- **Where:** Makefile:23, Cargo.toml:26, docs/deslop-terminal-echo.md:44
- **Problem:** Unproven regression risk: a one-off release-profile size comparison is not an ongoing distribution-size or startup measurement, so changes can increase download footprint or delay every invocation unnoticed.
- **Recommendation:** Record distribution binary size and verified CLI startup latency for representative release builds on supported platforms, with host and baseline and interleaved timing; use process-level CPU sampling if startup regresses.
- **Fix with:** bench-pyramid
- **Effort:** S

