# Campaign: Native Linux Backend for vault Using Rust age

Repository: https://github.com/joshuarli/vault

## Mission

Implement first-class Linux support for `vault` using the Rust `age` crate (https://github.com/str4d/rage), without compromising the existing macOS Keychain implementation.

The result should be a tiny, secure, self-contained, synchronous Rust CLI that works equally well on Alpine Linux, minimalist Linux installations, and ordinary desktop distributions.

This is an implementation campaign, not a design exercise. Inspect the current repository, implement the backend, test it rigorously, update documentation/builds/releases, and commit the completed work.

Work autonomously. Make sound engineering decisions without stopping for approval. Prefer the simplest correct implementation, but never sacrifice security or data integrity for brevity.

## 2026-10-21 follow-up audit

Status: implemented but **not security-accepted**. Read [campaign-linux-followup.md](campaign-linux-followup.md) and execute its P0/P1/P2 acceptance gates before declaring the campaign complete. The latest code includes a per-UID Linux kernel-keyring identity cache; its security implications and revocation are not yet fully tested. The original checklist's external age/rage interoperability criterion also remains unverified.

## Current checkpoint

The Linux age backend, documentation, installation, and release matrix are implemented. Linux reads cache the unlocked identity in the user-session kernel keyring with an inactivity timeout. Local Linux tests, Clippy, Alpine musl release build/install, and Linux GNU plus macOS compile checks pass. macOS runtime verification and an external `rage` CLI interoperability check were unavailable on this host. Same-user write access can replace the public recipient and redirect passphrase-free `set`. The README documents this boundary.

## 1. Nonnegotiable principles

- Rust only. Use the `age` crate directly, not the Go `age` executable or an external `rage` process.
- No systemd, D-Bus, PAM, GNOME Keyring, KWallet, Secret Service, or other session-service dependencies.
- No daemon, background process, agent, or socket.
- Cache only the unlocked identity in the Linux user-session kernel keyring, with an inactivity timeout.
- No Tokio or async runtime. Preserve the synchronous architecture.
- No database, configuration framework, CLI framework, or general-purpose secret-management abstraction.
- No custom cryptographic primitives or homemade encryption formats.
- No root privileges or system-wide installation requirement.
- No plaintext secrets, passphrases, or private keys written to persistent storage.
- No passphrases or secret values in process arguments, environment variables, logs, or error messages, except the explicitly requested child-process environment injection.
- Preserve all existing macOS behavior, particularly per-read Keychain user-presence authentication.
- No unnecessary traits, generics, abstraction layers, or modules.

Prefer existing Rust standard-library facilities and the repository's current dependencies where sufficient.

## 2. Understand the existing implementation

Before making changes, inspect:

- `README.md`
- `AGENTS.md`
- `Cargo.toml` and `Cargo.lock`
- `src/main.rs`
- `src/keychain.rs`
- `src/lib.rs`
- Existing integration tests
- `Makefile`
- GitHub Actions workflows

Understand the actual current code, not just the README. Preserve any behavior introduced since this prompt was written.

The CLI currently supports storing, retrieving, listing, and removing secrets, together with an exec mode:

```sh
vault set OPENAI_API_KEY
vault get OPENAI_API_KEY
vault ls
vault rm OPENAI_API_KEY

vault OPENAI_API_KEY DATABASE_URL -- cargo run
vault OPENAI_API_KEY PORT=8080 -- cargo run
```

Retain this interface exactly wherever possible.

Preserve the existing parsing semantics, literal environment assignments, child process behavior, stdio inheritance, exit-code propagation, and diagnostic conventions.

Do not introduce a generic platform abstraction if a small conditional module boundary suffices.

## 3. Cryptographic architecture

Use the current compatible `age` crate, initially targeting:

```toml
[target.'cfg(target_os = "linux")'.dependencies]
age = { version = "0.12.1", default-features = false }
```

Verify the real feature/dependency graph and stable APIs. Keep the dependency Linux-specific.

The core design is a **single passphrase-encrypted X25519 identity**, with individual secrets encrypted to its public recipient.

### Persistent layout

Follow the XDG Base Directory specification:

```text
$XDG_DATA_HOME/vault/
├── identity.age
├── recipient
└── secrets/
    ├── OPENAI_API_KEY.age
    └── DATABASE_URL.age
```

Default `$XDG_DATA_HOME` to `$HOME/.local/share` when unset. Follow the specification's handling of invalid or relative XDG paths.

Responsibilities:

**`identity.age`**

Contains one age X25519 private identity, encrypted using age's standard scrypt passphrase recipient.

Never persist this private identity in plaintext.

Prefer the canonical age identity encoding inside the encrypted payload, so the decrypted identity is interoperable with `rage-keygen` and `rage`.

**`recipient`**

Contains the corresponding public age recipient (`age1...`), in a standard textual representation.

This is public key material and does not need encryption, but it does need filesystem integrity protection.

**`secrets/NAME.age`**

Contains the secret value encrypted to the public recipient in standard binary age format.

Each secret is independently encrypted. No custom cryptographic envelope or serialization format.

Use age's supported `x25519::Identity`, `x25519::Recipient`, `scrypt`, `Encryptor`/`Decryptor`, or streamlined encryption/decryption APIs as appropriate.

Use vetted library defaults for scrypt rather than improvising KDF parameters. Bound resource consumption when processing malformed or hostile ciphertext.

### Important security distinction

The public recipient permits encryption without unlocking the private identity.

After initialization, `vault set` should therefore normally operate without requesting the master passphrase.

Reading a secret decrypts `identity.age`. On Linux, `vault get` and exec mode request the passphrase after the identity cache expires or becomes unavailable.

Never cache the master passphrase. Cache the unlocked identity only in the Linux user-session kernel keyring, and refresh its fixed inactivity timeout on successful reads.

Understand and document that this design provides cryptographic confidentiality at rest, not macOS-equivalent OS-enforced user presence or resistance to malicious processes already running as the user.

## 4. Initialization and lifecycle

Preserve the minimal CLI.

Prefer automatic initialization on the first Linux `vault set NAME`, rather than requiring a new setup command.

First use:

1. Determine the XDG storage location.
2. Check whether an initialized store already exists.
3. Prompt for a master passphrase and confirmation.
4. Reject an empty passphrase or mismatch.
5. Generate a fresh X25519 identity using the age library.
6. Encrypt the identity using the master passphrase.
7. Save the encrypted identity, public recipient, and initial secret securely.
8. Discard sensitive in-memory material as promptly as practical.

Use an atomic initialization strategy. A crash, concurrent initialization, or permission failure must not leave an apparently valid store with mismatched identity and recipient files.

**Never regenerate an identity automatically when an existing store is incomplete, damaged, or inaccessible.**

Such cases must fail with actionable diagnostics. Silently replacing the identity could render every previously stored secret permanently unreadable.

After initialization, subsequent `vault set` operations use the existing public recipient.

No login-time unlocking, background daemon, or system service is necessary.

## 5. Command behavior

### `vault set NAME`

- Read the secret using the existing stdin/TTY semantics.
- Initialize the store if this is its first use.
- Encrypt the value to the existing public recipient.
- Atomically create or replace the corresponding ciphertext.
- Never create an intermediate plaintext file.
- Preserve the existing secret if encryption or writing fails.
- Do not display the secret.
- Validate the name before accessing the filesystem.

Preserve sensible behavior for piped input, including:

```sh
printf '%s' 'secret' | vault set OPENAI_API_KEY
```

### `vault get NAME`

- Require an initialized store.
- Prompt for the master passphrase.
- Decrypt the private identity in memory.
- Decrypt the requested ciphertext.
- Write only the secret value to stdout, preserving existing newline semantics.
- Direct all prompts and diagnostics elsewhere.
- Never reveal the passphrase or key material.

Wrong passphrase, malformed identity, missing secret, or damaged ciphertext must fail clearly without leaking sensitive data.

Do not confuse authentication failure with missing-file errors.

### `vault ls`

- List secret names without decrypting their values.
- Do not request the passphrase.
- Never read secret contents merely to enumerate names.
- Ignore unrelated files, temporary files, and invalid entries.
- Preserve deterministic output behavior.

Secret names are intentionally not confidential in this storage format. Document that limitation.

### `vault rm NAME`

- Remove the corresponding ciphertext.
- Do not require the passphrase.
- Preserve existing missing-secret behavior.
- Never follow a symlink outside the store.

Removal is not a guarantee of secure erasure from SSDs, snapshots, or backups.

### Exec mode

```sh
vault OPENAI_API_KEY DATABASE_URL -- cargo run
```

- Parse all environment specifications as before.
- Prompt for the master passphrase at most once.
- Decrypt the identity once.
- Resolve all required secrets using that identity.
- Inject their values into the child environment.
- Preserve literal assignments.
- Spawn the child only after every required secret is resolved successfully.
- Inherit stdin, stdout, and stderr as before.
- Propagate the child's exit status as before.
- Never invoke a shell implicitly.

A command containing only literal assignments must not require vault initialization or a passphrase.

Do not introduce a mechanism that injects the passphrase itself into the child environment.

### Other existing commands

Preserve commands discovered in the actual CLI, including any purge or legacy-cleanup behavior.

Any destructive Linux operation must be scoped strictly to the Linux store and must not affect macOS Keychain data.

Do not casually add new subcommands or options.

## 6. Passphrase handling

Implement secure terminal interaction.

Requirements:

- Disable terminal echo for passphrase entry.
- Restore terminal attributes on success, error, and ordinary unwinding paths.
- Prompt via `/dev/tty`, not stdout.
- Support redirected stdout and piped stdin independently of passphrase prompting.
- Do not accidentally consume piped secret input as the passphrase.
- Never pass the passphrase through argv or environment variables.
- Avoid unnecessary copies and long-lived plaintext allocations.
- Use `secrecy` facilities exposed by age wherever appropriate.
- Zeroize owned sensitive buffers where practical; do not claim stronger guarantees than the implementation provides.

For example, this must work with a controlling terminal:

```sh
token=$(vault get OPENAI_API_KEY)
```

The prompt appears on the terminal, while stdout contains only the requested secret.

If no usable controlling terminal exists, fail explicitly. Do not add an insecure passphrase environment variable or command-line option as a convenience fallback.

Do not cache the passphrase or introduce an unattended unlock mode. Cache only the decrypted identity in the Linux user-session kernel keyring, with a fixed inactivity timeout.

## 7. Filesystem security and durability

Treat this as security-critical code.

### Permissions

- Store directories: `0700`
- Encrypted files and identity: `0600`
- Public recipient: restrict to `0600` for simplicity and integrity protection
- Never rely on the process's existing umask alone.
- Support typical Linux filesystems, including Alpine environments.

### File access

- Validate secret names. Use a conservative environment-variable naming grammar suitable for filenames, such as `[A-Za-z_][A-Za-z0-9_]*`.
- Reject path separators, traversal sequences, NUL bytes, and invalid names before filesystem access.
- Do not permit symlinks in vault-managed files or directories.
- Protect against obvious symlink substitution and TOCTOU attacks using suitable Unix/Linux primitives.
- Avoid treating special files as regular ciphertext files.
- Bound ciphertext sizes and malformed-input resource usage.
- Never allow ciphertext operations to escape the configured store.

Reuse `rustix` where helpful, rather than introducing low-level C wrappers gratuitously.

### Atomicity

For secret creation or replacement:

1. Encrypt fully in memory.
2. Create a securely permissioned temporary file within the destination filesystem.
3. Write ciphertext completely.
4. Flush and synchronize appropriately.
5. Atomically rename it over the destination.
6. Synchronize the containing directory where supported.
7. Clean up abandoned temporary files safely.

Handle interrupted operations, disk-full conditions, and short writes.

Initialization requires equally careful protection against partial state and concurrent first-use processes.

Never truncate an existing valid encrypted file before a successful replacement is ready.

Do not claim secure deletion or memory-forensic protection that the platform cannot guarantee.

## 8. Repository architecture

Keep the implementation extremely small.

A reasonable target:

```text
src/
  main.rs
  lib.rs
  keychain.rs       # macOS only
  linux.rs          # age-based storage
```

If necessary, split Linux-specific filesystem or terminal helpers into one additional module, but only when that meaningfully improves maintainability.

Use compile-time platform selection:

```rust
#[cfg(target_os = "macos")]
mod keychain;

#[cfg(target_os = "linux")]
mod linux;
```

The CLI should call a small set of platform storage functions.

Preserve simple error handling. Avoid constructing an extensible backend/plugin framework for exactly two compile-time implementations.

Keep `security-framework` and CoreFoundation dependencies confined to macOS.

Ensure Linux builds never attempt to link Apple frameworks.

Consider whether existing `rustix` terminal code can be shared rather than duplicated.

Avoid rewriting the CLI or modifying macOS functionality merely to achieve an aesthetically symmetrical architecture.

## 9. Testing strategy

Build a serious regression suite without bloating the runtime implementation.

Use isolated temporary XDG directories for tests. Never touch a developer's real vault.

### Cryptographic tests

- Generate, encrypt, unlock, decrypt round-trip.
- Multiple secrets under one identity.
- Overwrite an existing secret.
- Wrong master passphrase.
- Corrupt encrypted identity.
- Corrupt individual secret.
- Missing identity, recipient, or ciphertext.
- Recipient/identity mismatch detection during authenticated operations.
- Empty, multiline, and non-ASCII secret values, consistent with the CLI's supported input semantics.
- A passphrase containing Unicode and spaces.
- Empty and malformed ciphertext.

### Filesystem tests

- Permissions on every generated directory and file.
- Atomic replacement preserves old data on failure.
- Partial initialization does not destroy existing data.
- Concurrent first-use attempts cannot corrupt the store.
- Symlink and path traversal attacks fail safely.
- Invalid and hostile secret names are rejected.
- Incomplete store is never silently reinitialized.
- Listing never emits secret contents or temporary filenames.
- Operations do not escape their designated XDG directory.

### CLI and process tests

- Existing CLI parsing.
- Literal environment assignments.
- Multiple secret injection.
- Child exit-code propagation.
- Child spawn failure.
- Missing secret prevents child execution.
- Authentication requested only once per multi-secret invocation.
- No passphrase requested for `ls`, `rm`, or literal-only exec.
- Secret stdin handling and passphrase terminal handling remain independent.
- Stdout of `get` is clean.
- Errors never expose secret values.

Use test seams or a PTY-based harness to test interactive authentication. Do not add a release-build passphrase bypass merely to make tests convenient.

### Interoperability

Prove that vault-generated files use ordinary age format, not merely that the implementation can decrypt its own output.

When `rage` is available in the test environment:

1. Decrypt a vault-produced ciphertext using `rage` and the corresponding identity.
2. Encrypt a secret with `rage` to vault's recipient and read it with vault.
3. Verify that the passphrase-encrypted identity can be decrypted using standard age/rage tooling.

Keep these external-tool interoperability tests optional if the executable is absent, with a clear skip rather than making Go or rage a runtime dependency.

### Regression

Run all existing macOS tests where a macOS runner is available.

Where macOS tests cannot run, preserve the backend unchanged and use compile checks plus CI to establish coverage. Never claim that tests ran when they did not.

## 10. Linux build and distribution

Update `Cargo.toml`, `Makefile`, and CI as necessary.

Requirements:

- `cargo build --release` works natively on Linux.
- `make install` works on Linux without invoking `codesign`, `security`, or other macOS tools.
- Preserve macOS code-signing and installation behavior.
- Support x86_64 and aarch64 Linux.
- Prefer support for both glibc and musl, with particular attention to Alpine.
- No dynamically required desktop/keyring components.
- No Go toolchain, Go runtime, D-Bus daemon, systemd, or shell-installed encryption utility.

Inspect the release workflow and add sensible Linux artifacts without disrupting existing macOS releases.

Verify the actual dependency graph. In particular, check that no async executor or unrelated keyring stack was introduced.

Run:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
```

Adjust target-specific commands and CI matrices appropriately.

Avoid adding significant CI complexity solely for rarely used architectures.

## 11. Documentation

Update the README to describe both backends accurately.

### macOS

- Native Keychain
- Existing per-read OS authentication behavior
- Code-signing requirements
- No change to stored Keychain data

### Linux

- Pure Rust age-based backend
- Encrypted local storage
- Master-passphrase authentication
- No PAM, D-Bus, systemd, or desktop session requirement
- First-use initialization
- XDG storage location
- Normal set/get/exec examples
- Headless terminal requirements
- Restoration and backup procedures
- Recovery limitations

Explicitly explain that losing the master passphrase makes the encrypted identity unusable. Backups must preserve the encrypted identity and the matching encrypted secrets together.

Explain that changing the encryption key and changing the passphrase are different operations. Do not imply that simply reencrypting `identity.age` rotates the underlying private identity or invalidates old backups.

### Security model

Document the meaningful differences from macOS:

- Linux passphrase prompting is application-enforced, not protected by macOS Secure Enclave/Keychain access-control policies.
- An attacker with control of the running user's process or executable can potentially compromise secrets or capture the passphrase.
- Same-user filesystem write access may permit replacement of the public recipient; document the trust boundary and fail safely on detected mismatches.
- Child environment variables may be observable through process inspection or inherited by descendants.
- `vault get` intentionally exposes the secret through stdout.
- Swap, core dumps, shell history, backups, and hostile processes have separate implications.
- No guarantee of secure erasure.
- Secret names and recipient metadata are visible.

Do not present the Linux backend as equivalent to hardware-backed per-read authentication.

## 12. Scope discipline

Do not expand this campaign into:

- A generic password manager
- A keyring service
- A D-Bus compatibility layer
- A PAM module
- A daemon
- An unbounded unlocked session
- A synchronization protocol
- Cloud backup
- GUI integration
- A general-purpose encryption CLI
- Multiple encryption identities or arbitrary recipients
- Hardware-token or biometric support
- A major rewrite of the existing macOS backend

Passphrase rotation and cryptographic identity rotation are potentially useful future additions. Do not implement a half-finished or unsafe version as part of this campaign.

Implement the smallest complete version that safely meets the specified requirements.

## 13. Definition of done

The campaign is complete only when:

1. A Linux user can install vault without any desktop, PAM, D-Bus, Go, or systemd dependency.
2. First-use setup creates a valid encrypted identity and recipient.
3. Secrets are stored as standard age-encrypted files.
4. `get` authenticates and decrypts correctly.
5. Exec mode authenticates exactly once and injects multiple secrets correctly.
6. Existing CLI behavior remains intact.
7. Sensitive values are never persisted in plaintext or emitted unintentionally.
8. Interrupted and concurrent writes cannot silently destroy a working store.
9. Rust age/rage interoperability is verified.
10. Linux builds and automated tests pass.
11. macOS Keychain behavior and its build remain intact.
12. Documentation accurately describes security boundaries and recovery.
13. No unnecessary architectural or dependency complexity has been introduced.

Before finishing, perform a focused security review of your own implementation. Challenge the design from the perspective of an attacker who can manipulate vault's on-disk files but cannot read the user's passphrase.

Identify and address concrete attack paths, rather than merely checking that encryption is enabled.

Finally, inspect the complete diff for unnecessary complexity, duplicated logic, and behavioral drift. Simplify aggressively where safety permits.

Commit the completed implementation with a clear commit message.

Report the architecture, files changed, tests actually executed, release/build coverage, any remaining security limitations, and the resulting commit hash.

**Target outcome: the Linux equivalent of the existing macOS vault experience, using interoperable age encryption, without inheriting the complexity of Linux's desktop keyring ecosystem.**
