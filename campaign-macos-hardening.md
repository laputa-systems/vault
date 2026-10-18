# Campaign: macOS Keychain hardening for vault

Repository: https://github.com/laputa-systems/vault

Status: ready for execution; preflight only, campaign not started.

## Objective

Make vault store and retrieve secrets through an explicitly selected, OS-enforced macOS Keychain backend. Prove its access policy, migration behavior, signing requirements, and terminal use before claiming biometric protection. Preserve the CLI's direct child-process model and the repository's existing secret-handling invariants.

The execution starts from the latest repository state. The inspected preflight baseline was commit b0c1a59fc465f4e7afa919f90d1848253b84bff4; it is a reference, not a pin.

## Deliverables

1. A repeatable, isolated macOS security harness that establishes which Keychain backend is used, verifies authorization failures as well as successful access, and never queries production items.
2. A protected storage implementation with an explicit backend, validated access control, consistent SecItem queries, and an explicit migration path for existing current-service items.
3. CLI fixes for terminal input, child environment handling, destructive command arguments, and surfaced I/O failures.
4. A tested signing and packaging path, or a documented architecture blocker with no false security claim.
5. Updated README and tests describing the actual supported behavior and limits.

No CI, release workflow, sudo/PAM configuration, identities, profiles, notarization, installation, or publishing changes are in scope. Do not change the pinned Rust nightly. Do not add code comments. Prefer existing dependencies; if a new dependency is necessary, justify maintenance, license, transitive weight, build-time, and binary-size cost before adding it.

## Authorization and boundaries

The source campaign draft authorizes research, implementation, testing, documentation, and local Conventional Commits. It does not authorize pushing, publishing, or installing. Keep every worktree and scratch file under .work/. Ensure .work/ remains in .git/info/exclude. Use .work/wt/<lane> for worktrees, .work/tmp for scratch, and set TMPDIR to .work/tmp for commands that create large temporary files.

Do not access or alter the user's login Keychain items in campaign tests. Use a disposable test keychain where supported and unique test service/account identifiers. Test values must be dummy values; never print them, persist them to files, or include them in diagnostics. Cleanup exact test items/keychains on success and failure. No test may query the production service, even to check that an item is missing.

Keep the runtime a direct Rust CLI. Do not add a GUI app, daemon, SSH agent, setuid mode, privileged helper, or local IPC service that returns secrets. Investigate session reattachment only if tests show GUI-session namespace isolation is the cause; never use sudo/PAM authorization for vault access.

Preserve these repository invariants:

- New secrets use Generic Password items, are protected by user presence, and are device-only.
- Never read the legacy namespace dev.joshuarli.vault. Existing set, rm, and purge cleanup of that namespace remains.
- Exec parses -- between environment specs and the command. Only a nonempty NAME=VALUE containing exactly one equals sign is literal; other specs name Keychain items.
- Spawn without a shell, inherit environment and standard streams, and return the child status.
- Read set input without echo, restore terminal state, and reject invalid UTF-8.
- Never log or write secret values to disk.

All security claims require a negative test. A successful prompt or read alone is not proof of enforced access.

## Owner decision

2026-10-18 — Remove the public vault lock command and its docs/tests if an isolated test cannot demonstrate a supported authorization-revocation effect. The existing partition-list edit and its current success test do not prove that a protected read is denied afterward. Keep the command only if a test proves a useful, repeatable effect under the chosen backend and signing model, then document that exact effect. This is a CLI contract change; include it in the final campaign report.

## Baseline and verified facts

Host: macOS 27.0 arm64. Rust is pinned to nightly-2026-07-24; do not change it. The existing debug binary's Mach-O minimum version is macOS 11.0. Preserve that deployment floor unless an API requirement is demonstrated and surfaced as a product decision. The release workflow currently builds aarch64-apple-darwin on macOS; do not edit it.

Safe baseline checks, using TMPDIR=.work/tmp:

- cargo test --lib — passed, 15 tests, 2.16s real.
- cargo clippy --all-targets --all-features -- --deny warnings — passed, 1.01s real.
- cargo test --test integration exec_no_vars_runs_command — passed, 1 test, 27 filtered, 1.23s real.

The full integration suite was not run: existing cases query the real service or login Keychain for missing names. Isolate those tests before running the full default suite. No release build was run. Timings are initial observations, not performance claims. The current debug binary is 847,184 bytes.

Code inspection found:

- src/keychain.rs creates Generic Password items with userPresence and WhenUnlockedThisDeviceOnly but does not explicitly select the Data Protection Keychain. The actual backend and enforcement are unproven.
- Reads and lists do not select a backend or pass an LAContext. Updates change the value and may retain an item's pre-existing weaker access control.
- set removes a same-name item in the legacy namespace after writing. rm and purge also clean that namespace.
- vault lock invokes security set-generic-password-partition-list. Its integration test checks command success and later successful reading, not denied access.
- cmd_purge accepts no parameters but dispatch ignores extra arguments, so vault purge EXTRA currently purges.
- Terminal input falls back to ordinary echoed input if tcgetattr fails; termios write and restoration errors are ignored.
- Exec mutates the parent environment with setenv before spawning.
- README currently claims vault lock resets authorization and documents ad-hoc signing.

A disposable file-based Keychain experiment ran security set-generic-password-partition-list against a dummy item. The command succeeded and the same security executable could still read the item. This establishes no revocation; it does not test a userPresence item or a differently signed reader. Repeat the relevant experiment in the isolated harness.

## Architecture decisions to establish

### Backend and access policy

Apple documents that SecItem defaults to the file-based Keychain unless the Data Protection Keychain is requested. Entitlement access groups and signing requirements can affect whether a command-line executable can use the protected backend. Treat the packaging question as a gate, not an implementation detail. See Apple TN3137 and TN3125 in References.

Prototype explicit Data Protection Keychain selection for every create, read, update, delete, and list operation. Set synchronization explicitly to false. Use stable service/account attributes and an access control containing WhenUnlockedThisDeviceOnly and userPresence, after confirming the valid attribute combination against Apple documentation and the experiment.

Use the narrowest typed query boundary that makes backend choice explicit and prevents a query from silently omitting it. Do not add an untyped bag of optional query attributes or a fallback to the file-based backend. Do not simulate protection by calling evaluatePolicy before reading an unprotected item.

Use LAContext at the protected item access. The desired exec behavior is one authorization for multiple protected values in a single vault invocation. Test whether one fresh LAContext can authorize multiple SecItem reads while the OS enforces each item's policy. Reuse it only within that invocation, invalidate it at invocation end, and prove a later invocation requires fresh authorization. Use interactionNotAllowed for negative noninteractive tests; kSecUseAuthenticationUIFail is deprecated. Test cancellation, biometric lockout/unavailability, locked session, user switching, and password fallback where supported. Interactive tests must be explicitly opt-in; record hardware, macOS version, signing identity, and session type. If one authorization per invocation cannot be demonstrated safely, report the limitation rather than weakening item protection. Do not promise Touch ID, Apple Watch, or password fallback beyond what the supported policy actually demonstrates. Strict biometryAny/currentSet may be evaluated separately, but userPresence remains the default unless the owner approves a contract change.

A failed read must distinguish missing item, denied/cancelled authorization, and operational failure. Never retry against a weaker backend.

### Signing and packaging gate

Test the current standalone executable with ad-hoc signing, the existing local Vault Signing identity, and a developer identity only if already available. Then test the smallest app-like bundle/profile arrangement Apple requires. Do not create identities or profiles. Verify updates preserve the intended access identity, and verify invocation through the installed PATH entry or symlink.

TN3137/TN3125 indicate restricted access groups may require an app-like bundle and provisioning profile; a standalone executable cannot simply claim arbitrary entitlements. If the machine lacks an existing suitable identity/profile, record the exact missing prerequisite and park that packaging proof. Do not claim the protected backend works for ordinary standalone distribution or recommend ad-hoc re-signing unless experiments prove it.

If the needed entitlement requires a bundled executable, prototype the minimal package around the Rust CLI; do not build a GUI application. Update Makefile and README only after validating the package model. Do not modify release CI.

### Migration and destructive operations

Existing items under the current service dev.joshuarli.vault.secure may be in the file-based domain. Keep them separate from the forbidden legacy namespace dev.joshuarli.vault: migration may read only the current service in the explicitly selected source domain, never the legacy namespace.

Provide an explicit vault migrate operation if backend transition is required. Do not migrate implicitly in get or set. For each item, create a protected destination, read it back through authorization, and compare in memory. Retain the source item; migration never deletes its source. A retry must be idempotent: matching destinations count as already migrated; conflicts fail without overwriting. Report names and status only, never values. Partial failure returns nonzero, preserves every source item, and can be safely retried without a journal or secret-bearing state file.

After transition, get/list/exec read only the protected destination. If an item exists only in the source domain, explain how to run migration; never silently fall back. rm and explicit purge must target exact records in both current domains plus the legacy namespace cleanup required by the existing contract. Surface partial deletion failures.

### CLI behavior

- Reject extra arguments to purge before any Keychain operation.
- For set, fail closed if terminal settings cannot be read or echo cannot be disabled. Check restoration on every exit path, including interruption. Do not persist input if echo restoration fails. Test EOF, cancellation, invalid UTF-8, and signal behavior with a PTY and controlled syscall failures.
- For exec, construct the child's environment without mutating the parent process. Preserve inherited variables, the exact literal-versus-Keychain grammar, direct spawn, streams, and exit status.
- Surface write, termios, spawn, and cleanup errors. Never include secret values in errors.
- Handle partial writes and failed stdout writes; do not report success after output was truncated.
- Keep stdout behavior and list sorting stable unless a documented contract change is necessary.
- Review touched FFI boundaries: CoreFoundation ownership, SecItem dictionary construction, C strings, process environment/arguments, and terminal state. Replace unnecessary unsafe code with supported interfaces; do not broaden into unrelated rewrites.

## Execution model

Use lanes only for disjoint file ownership. Minimum width is two ready lanes when capacity permits; cap concurrency at the lesser of ready lanes and the current perf-gate-ready memory ceiling. The observed host reported a six-lane memory ceiling, but re-run perf-gate-ready -s before each wave and set PERF_GATE_LANE_GIB from measured peak lane usage. Do not add width when the gate reports constrained capacity. Keep verification lanes on disjoint worktrees and scratch data. Replace or resume a stopped lane in the same turn when useful; begin the next wave while parent integration proceeds.

The parent owns integration, conflict resolution, final review, and campaign verification. Each lane commits only its owned files with a Conventional Commit message (type(scope): imperative lowercase subject, at most 72 characters); put the reason in the body and the work item ID in the body. No lane pushes.

### P0 — prove platform behavior

Owner: macOS security harness lane; owns tests/security_macos/ and disposable experiments under .work/tmp only.

Build a repeatable harness for file-based versus Data Protection Keychain queries, userPresence enforcement, noninteractive denial, context use/reuse, update behavior, access under a second signing identity, bundle/profile requirements, and tmux/TTY prompt behavior. Use a unique test service, exact cleanup, and dummy values. Keep all experiments independent of vault's production service. Keep interactive biometric tests opt-in; default tests must never wait for GUI authentication. Verify development builds cannot impersonate the production signing identity or access its items.

Test current CLI behavior as well as the proposed explicit backend. Include a protected-item read from a separately signed executable where possible. Verify whether lock changes authorization for a protected item. Do not let the harness or test helpers accept an arbitrary production service through a loose command-line parameter.

Acceptance: recorded, reproducible outcomes identify the working backend and minimum signing/package model, or identify the exact unavailable external prerequisite. Negative reads fail as expected; positive reads succeed only after supported authorization. Verify multiple protected reads can share one authorization within a single exec invocation, and a separate invocation prompts again. Record interactive results with hardware, macOS version, signing identity, and session type. No production item is touched.

If the platform gate cannot be completed after three controlled hypotheses/attempts, record commands, errors, and the remaining external prerequisite, park only that gate, and continue independent CLI work. Do not infer success from a prompt or from a command exit status.

### P1 — harden CLI behavior in parallel

Owner: CLI lane; owns src/main.rs and tests/integration.rs plus a uniquely named terminal test file if needed. Do not edit keychain.rs or the security harness.

Implement the CLI behavior above. Keep tests independent of the production Keychain service. Add targeted behavior tests for purge argument rejection, parent environment preservation, terminal echo restoration/failure, invalid UTF-8, interrupt handling, stream inheritance, and exact child status. Preserve existing parser behavior with boundary cases for empty assignments, multiple equals signs, and missing --.

Acceptance: cargo test --lib; each touched integration/terminal test by name; clippy command from Baseline after changes. Full suite waits until Keychain integration tests are isolated.

### P2 — implement protected storage and migration

Owner: storage lane; starts after P0 establishes a usable query/signing model. Owns src/keychain.rs, Cargo.toml/Cargo.lock if needed, and tests/keychain_security.rs. Coordinate the exported CLI shape with the CLI lane without sharing files.

Implement one explicit query boundary for the protected backend. Replacing an existing item must not preserve weaker access control: verify the existing ACL and recreate/restrict it safely, or fail without overwriting if safe replacement cannot be guaranteed. Implement the explicit idempotent migration contract above. Keep access-group selection derived from the proven package, with no silent default.

Tests use only the isolated harness. Include noninteractive denial, wrong signing identity denial, update cannot weaken protection, source retention on interruption/failure, destination conflict, idempotent retry, exact cleanup, and no legacy-namespace reads. If required platform infrastructure is unavailable, implement no weaker fallback; keep the storage gate parked and continue docs describing the limitation.

Acceptance: targeted tests for every changed storage path; default tests never query production Keychain; cargo test --lib and clippy pass.

### P3 — packaging and user documentation

Owner: packaging/docs lane; starts after P0's model is known and coordinates the storage contract. Owns Makefile, README.md, and new packaging files only. No CI/workflow changes.

Document real prompt options, supported macOS floor, signing/profile prerequisites, explicit migration, cancellation/errors, Keychain cleanup, tmux and noninteractive limitations, and actual tested installation behavior. Remove inaccurate claims about lock if its supported effect is absent and document any resulting command removal. Preserve straightforward PATH invocation. Do not claim universal Touch ID or Apple Watch behavior.

Acceptance: documented commands match help and tests; clean local package build/install instructions work only where existing credentials suffice. Do not install into the user's home directory during campaign validation.

### P4 — integrate and close

Parent integrates lane commits and runs targeted checks on the merged result. Explicitly compare direct Data Protection Keychain storage, the minimum app-like package if required, and Secure Enclave envelope encryption; choose the simplest model whose security properties are proven, and reject the encryption layer absent demonstrated advantage. Then run the full local default test suite and clippy after all Keychain tests are isolated from production. Run ultrareview on campaign changes and resolve P1/P2 findings within this campaign's files; do not expand into Linux/age or CI.

Only after parity and security acceptance pass, consider optimization. This is not a performance campaign. Do not add a benchmark framework. If a change could materially affect startup/runtime, measure with perf-gate-ready exiting 0 immediately before and -1 immediately after; discard overlapped runs. Always compare binary size at close. No numeric project performance gates exist; report build-time and binary-size changes for any new dependency. A release build is final verification only, and should be reported before starting if it is expensive.

## Acceptance matrix

| Area | Required evidence |
| --- | --- |
| Backend | Every operation explicitly selects the same intended Data Protection Keychain domain; no default or weaker retry. |
| Authorization | Positive and denied/cancelled/noninteractive paths tested. Multiple reads share one authorization within an exec invocation if supported; a separate invocation requires new authorization. A second unauthorized identity cannot read. |
| Existing data | Migration reads only current-service source items, retains source, verifies destination, handles conflicts, and resumes safely. Legacy namespace is never read. |
| Updates | Replacing an item cannot leave a weaker ACL or partially destroy the old value. Failure preserves recoverability and is reported. |
| CLI | purge extras rejected; input remains silent and restored; child environment/streams/status and parser semantics preserved. |
| Signing | Actual working identity, bundle/profile, update, and PATH invocation requirements documented. No unsupported signing claim. |
| TTY | Terminal, iTerm, local tmux, detached tmux, tmux over SSH, remote session, and no-TTY behavior tested or explicitly marked unsupported. |
| Cleanup | rm/purge affect exact intended records and report partial errors; disposable test state is cleaned on all paths. |
| Docs | README/help reflect tested behavior, migration, signing requirements, and limitations. |
| Tooling | cargo test, clippy, targeted security tests, binary-size comparison, and final review pass. No CI changes. |

Do not run test cases that touch Keychain until they use isolated, unique test identities and exact cleanup. Run default unit/CLI tests against mocks or a safe harness so cargo test never performs an absence check against the user's real Keychain.

## Reference parity

Use the latest repository state at campaign start as the behavior oracle. Inventory --help, argument errors, stdout/stderr, list ordering, stdin/TTY input, set replacement, rm/purge, legacy namespace cleanup, exec parsing, inherited environment, streams, and child status before changing them. Preserve these unless a deliberate change above is required. Add the expected behavior test before fixing a demonstrated defect. Do not add a broad compatibility layer.

The isolated Keychain harness is the security oracle; existing tests that query production services are not. Apple documentation determines supported API/signing constraints. Secretive is a reference for mechanisms only, not a behavior oracle.

## Verification workflow

Start each lane with a clean worktree at the current campaign base. Keep ownership disjoint and communicate file contracts before changing shared interfaces. Reproduce each observed defect with a focused test, then fix its cause. If three controlled hypotheses fail, revisit the assumptions and source/API version before parking the issue. Do not weaken existing tests.

Use the narrowest hard check during iteration. Do not run formatters or Makefile lint, which formats and applies clippy fixes. Run the full local suite only after the production-Keychain queries are removed from default tests. Do not edit CI. Recheck the host gate before time-based measurement.

At close, inspect status and diff, ensure no secret/test artifacts remain, run the acceptance commands, inspect binary size, and confirm all changes are campaign-scoped. Keep commits local.

## References and investigation notes

Apple:

- TN3137, macOS Keychains: https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains
- TN3125, code signing and provisioning profiles: https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles
- Keychain item accessibility: https://developer.apple.com/documentation/security/restricting-keychain-item-accessibility
- Data Protection Keychain query attribute: https://developer.apple.com/documentation/security/ksecusedataprotectionkeychain
- Authentication context: https://developer.apple.com/documentation/security/ksecuseauthenticationcontext
- userPresence policy: https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/userpresence
- Secure Enclave P256 key agreement: https://developer.apple.com/documentation/cryptokit/secureenclave/p256/keyagreement/privatekey

Reference implementations:

- Secretive: https://github.com/maxgoedjen/secretive
- Local macOS setup script: https://github.com/joshuarli/usr/blob/main/macos/setup-macos
- pam_reattach: https://github.com/fabianishere/pam_reattach

The relevant Secretive reference is its current SecureEnclaveStore.swift: it stores non-exportable key references and uses Data Protection Keychain access controls. That model is not equivalent to storing exportable arbitrary vault tokens. Older file names in the original study list were not confirmed in the current source; inspect the current repository paths only if a specific mechanism remains relevant.

The local setup script configures pam_reattach and pam_tid for sudo. This is a PAM sudo path and does not establish that a Rust CLI can reuse GUI authentication. Do not edit /etc/pam.d/sudo_local, install PAM modules, use sudo auth, or describe pam_reattach as a vault solution.

Secure Enclave encryption of arbitrary exportable values is a feasibility study only. Implement no custom cryptography. Evaluate whether it adds a demonstrated security benefit over protected Keychain items, including its integrity, substitution/rollback, recovery, hardware replacement, biometric enrollment, and portability consequences. Do not add a daemon, SSH agent, secret-bearing cache, local credential socket, or broad Secretive architecture. Proceed with the Keychain design first; revisit Secure Enclave only if a demonstrated threat remains unaddressed and the native API provides a supportable solution.

## Decision and execution log

2026-10-18 — Owner selected removal of vault lock if the isolated protected-item experiment cannot prove a supported authorization-revocation effect.

2026-10-18 — Safe baseline checks passed as recorded above. Full integration suite withheld because tests query production Keychain state.

No campaign phase has run. At close, report the selected architecture, actual backend, auth and tmux outcomes, signing/profile requirements, migration guarantees, lock result, exact tests, macOS/hardware/session details, remaining limits, changed files, and local commit hashes. Do not claim interactive behavior that was not demonstrated.

## Launch instruction

Execute campaign-macos-hardening.md from the latest repository state. Follow its worktree, Keychain isolation, signing, ownership, and commit boundaries. Continue independent work when a platform gate is parked, and report only behavior established by tests.
