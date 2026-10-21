# Campaign: Linux age backend — security and completion follow-up

Repository: https://github.com/laputa-systems/vault
Audited baseline: a1eb442bf1fd7c33059a44c3b953ccdf1c3887bb (2026-10-21)
Companion: campaign-linux.md

## Status and mission

The Linux backend is implemented, but it is not yet accepted as security-complete. This follow-up is an implementation campaign. Audit the latest main before modifying it; preserve subsequent fixes and do not assume this baseline is current. Reproduce defects with tests, fix them, run supported builds, review the result, and commit completed code.

Preserve the intentionally minimal synchronous Rust CLI, Rust age 0.12.1 format compatibility, XDG layout, ordinary-age ciphertext files, and systemd/PAM/D-Bus-free operation. No daemon, network service, database, GUI, or sweeping rewrite. Changes to Linux and shared CLI code must not regress macOS. Do not claim runtime verification on an OS where it was not executed.

The campaign's old acceptance criteria require external age/rage interoperability and cross-platform regression evidence; the checkpoint explicitly says those were not run. Do not mark those criteria complete based solely on Rust age self-roundtrips.

## Confirmed code observations versus risks to test

### P0 — make the decrypted-identity cache an explicit, defensible security decision

In src/linux.rs the 15-minute cache stores the complete decrypted age X25519 identity as a Linux user key payload under KEY_SPEC_USER_SESSION_KEYRING (-5), with KEY_POS_READ permission. The user-session keyring is **per UID**, not a private session keyring. It may be accessible across that user's separate logins/terminals/SSH sessions. That is a deliberate security tradeoff, not a mere performance optimization. See man7 user-session-keyring(7), keyrings(7), KEYCTL_SETPERM(2const).

Tasks:
1. Prove the actual access scope with two independently launched same-UID sessions (not just child processes). Test retrieval with and without an inherited controlling tty, across a separate login session if the host supports it, and with a different UID where permitted.
2. Document clearly that any process possessing the reachable per-UID keyring may read the decrypted identity itself, not merely request vault to read a particular secret. Do not describe this cache as session-private or hardware protected.
3. Review KEYCTL permission masks, key type, expiration, error cases, key quota, session survival, stale keys, concurrent writers, and cleanup failure paths. Assert expected masks and TTL through real keyctl queries where available.
4. Consider whether a different kernel keyring is compatible with **independent CLI invocations** without a daemon. Do not casually switch to a process/thread keyring, which would break cross-invocation reuse. State whether per-UID cache is acceptable under the project's trust model; prefer to preserve the recent cache feature if so.
5. Add a clear cache revocation capability, e.g. a Linux-only §vault lock§ or §vault cache clear§, scoped to exactly vault's cached identity for the selected store/recipient. Do not conflate this with the deliberately removed, ineffective macOS Keychain §lock§ command. Report error honestly and do not claim guaranteed physical erasure of kernel memory.
6. Test expiration, refresh, explicit revocation, keyring disabled/unavailable, no controlling tty, concurrent access, and a cached identity after replacing the encrypted identity or public recipient. A change to the master passphrase **must not** be advertised as immediate revocation while old cached keys remain valid.
7. Make any cache policy or command changes a documented owner-visible decision, especially if they change the recent 15-minute behavior.

Acceptance: no misleading authentication guarantee; an auditable retention/revocation story; bounded credential lifetime; unsupported keyrings safely fall back to passphrase prompts; cache operation cannot leak the identity to logs, args, env, or files.

### P1 — restrict destructive automatic cleanup

src/linux.rs set_secret_at calls cleanup_staging_directories on every set. That routine scans the **whole XDG_DATA_HOME root** for directories whose names start with .vault-init- and remove_staging_directory deletes direct files and a staged secrets directory. The code does not prove that such a directory belongs to the current vault store or a dead initialization. cleanup_temporary_files similarly deletes any .tmp-* entries under the secrets directory.

This is a destructive-scope issue even if the prefix is unlikely to collide. Reproduce it using harmless sentinel files. Do not test with real user data.

Fix:
1. Bind temporary state to vault-owned directories and a strongly identified operation, or conservatively decline cleanup of ambiguous entries. Never recursively delete arbitrary similarly named sibling directories in XDG_DATA_HOME.
2. Scope cleanup to specific generated paths; validate ownership, mode, file type, and directory identity before deletion; use fd-relative nofollow operations throughout. Reject unexpected nested files/dirs instead of trying to clean unknown trees.
3. Make recovery safe following process crashes, stale temp files, and concurrent initializations. If uncertain, report the orphan and preserve it; a harmless orphan is preferable to silent data loss.
4. Keep original ciphertext intact until atomic publication. Add tests for name collisions, planted directories, symlinks, unexpected contents, crash before/after publish, rename races, and interrupted cleanup.

Acceptance: a vault set cannot delete any file or directory outside the exact operation-owned workspace; atomic initialization and overwrite remain recoverable.

### P1 — bound stdin and terminal secret input *while reading*

The Linux backend rejects values over MAX_SECRET_BYTES in set_secret_at, but src/main.rs read_secret uses read_to_end for piped stdin and byte-by-byte appending for terminal input **before** invoking that bound. A very large or unending input can allocate without bound.

Implement a shared incremental input limit aligned with the documented 16 MiB maximum on Linux. Read at most limit+1, then reject before storage; decide whether to drain or immediately close stdin and test downstream pipe behavior. Do not truncate and store an apparently successful secret. Bound terminal paste input similarly and restore echo on overflow.

Keep macOS behavior intentional: if introducing a common limit is a contract change, document it and cover it on both platforms. Use a length-bounded test stream that exposes unbounded behavior without allocating gigabytes. Verify invalid UTF-8, multi-line values, and exact-boundary reads.

### P1 — trusted filesystem anchors and path integrity

open_data_home currently uses create_dir_all on the supplied XDG path and opens it without NOFOLLOW. open_store and read_private_file chmod existing paths as a side effect, without verifying owner UID of the data home, directories, and opened entries. The global .vault.lock file also lives directly in the shared XDG root.

Threat model: arbitrary same-UID compromise cannot be solved with permissions alone; still prevent obvious path redirection, accidentally changing unrelated files, world/group-owned stores, and unsafe trust of preexisting filesystem objects.

Tasks:
1. Verify expected owner UID, directory/file mode, single-link checks where applicable, and no symlink traversal from trusted location to the vault root, including intermediate path components where practical.
2. For preexisting unexpected objects, fail closed with actionable diagnostics rather than blindly changing metadata outside a verified vault-owned scope. Keep ordinary XDG_DATA_HOME permissions compatible with standard Linux desktops; do not require the entire XDG hierarchy to be 0700.
3. Ensure the lock file cannot overwrite, chmod, or lock an unrelated object planted in the shared XDG root. Consider a vault-specific lock strategy that still serializes the first initialization.
4. Race-test and failure-test stage publication and atomic replacement. Preserve backups/restored stores; do not make normal use impossible on common filesystems.
5. Do not claim to defeat an attacker with full same-UID process/filesystem control. Describe that boundary precisely.

### P1 — external age/rage interoperability, GNU/musl coverage

Tests currently parse ciphertext with the same age crate and decrypt it internally. The original campaign requires independently verified format interoperability, and its checkpoint says external rage was unavailable.

Add a deterministic, dummy-only test vector or optional external-tool test with a pinned compatible rage executable. Verify both directions: vault ciphertext decryptable by rage, and rage X25519 ciphertext readable by vault. Verify the passphrase-encrypted identity opens with age/rage, and verify binary/non-armored format and expected failure cases. Never ship real credentials, real private identities, or sensitive passphrases in fixtures.

Current CI builds glibc x86_64 and aarch64 and macOS; local Alpine musl build was reported, but there is no musl release artifact in the matrix. Add a focused musl build/smoke CI step or justify why Alpine is validated another repeatable way. Validate an actually runnable binary, not just cross-compilation. Check dependency weight and that there is no Go, D-Bus, PAM, or systemd requirement.

### P2 — make the identity cache strictly best effort

get_secrets_at_with_warning propagates failures returned by report_cache_warning. Thus an unavailable keyring plus unwritable stderr can turn an otherwise decryptable read into an error. Warnings and cache writes should not become authorization or data-availability gates unless there is an explicit security-critical failure. Test ENOSYS/EPERM/ENOKEY, cache corruption, stderr write failures, and exhausted key quota. Surface warnings where possible without losing the successfully decrypted result.

### P2 — consistency, validation and memory lifetime

- Validate Linux secret names **before** consuming stdin or opening a terminal prompt. Currently command dispatch reads the whole value first, then validates in the backend.
- Compare Linux's strict environment-variable naming grammar with macOS's accepted special-character account names. Make an explicit compatibility decision, avoiding accidental behavior changes and filesystem-unsafe Linux names.
- Inspect zeroization boundaries after decryption, including the conversion from Zeroizing<String> to String, std::process::Command::envs, environment snapshots, error paths, and partial exec failures. Minimize copies without claiming complete zeroization of standard-library-owned buffers.
- Verify get with failed stdout, stopped children/signals, zero/large secrets, malformed age streams, oversized ciphertext, permission errors, symlink/hardlink substitution, purge partial failures, and write-after-purge.
- Consider optional conservative validation of the recipient before set. Cryptographically authenticating a replaced recipient requires unlocking trusted key material; the current passphrase-free set cannot guarantee protection from a same-UID writer who swaps the recipient. Do not invent a signature or claim this is solved by mode 0700; document the impossibility or make a deliberate policy change.
- Review data-home errors and unbounded directory enumeration on a malicious filesystem. Optimize only when a measured or demonstrated failure warrants it.

## Verification and execution order

1. Record latest main SHA and freeze a clean baseline. Inventory current Linux CLI, format, keyring behavior, and tests.
2. Write targeted failing tests for verified P1 defects. Fix destructive cleanup and unbounded input before more elaborate changes.
3. Characterize kernel keyring semantics with real API calls; implement the smallest defensible retention/revocation contract without a daemon.
4. Close filesystem trust, cache warning, data-validation, and memory-lifetime findings.
5. Add independent age/rage interop and runnable musl smoke coverage.
6. Run cargo fmt --all -- --check, cargo clippy --all-targets --all-features -- --deny warnings, cargo test, and representative dist/release checks on Linux. Cross-check macOS compile and available isolated tests. Do not run production macOS Keychain operations.
7. Run a final adversarial review and remove unnecessary layers. Update README, campaign-linux.md checkpoint, and this document with what was proven, failed, or intentionally excluded. Commit code and campaign completion notes.

Do not assert any tests actually ran unless you ran them. If a tool/environment is missing, identify exact blocked evidence and leave the relevant item open.

## Completion criteria

- Normal set/update cannot delete an unrelated XDG sibling or temp tree.
- Input size is bounded before allocation; oversized secret input fails without storing.
- Vault files and lock paths are safely scoped, verified, and resistant to obvious symlink/hardlink abuse.
- Cached private identity exposure, UID scope, TTL, and explicit revocation are validated and accurately documented.
- Keyring/cache warnings do not unexpectedly break an authorized retrieval.
- External age/rage interoperability is actually tested.
- GNU Linux and musl/Alpine have a repeatable runnable validation path.
- macOS CLI compilation and existing safe regressions remain intact.
- Every test uses isolated dummy values; no secret, identity, or passphrase is logged.
- The resulting code remains small, synchronous, and understandable; no daemon or session-management framework has appeared.

Final report: severity-ranked findings (confirmed vs risk), precise reproductions, implementation choices, changed files, test commands/results, unsupported checks, security tradeoffs, and commit SHA.
