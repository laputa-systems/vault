# vault

`vault` stores secrets and supplies them to child commands. macOS uses an
age-encrypted local store with a Secure Enclave protected identity; Linux uses
the same age format with a passphrase-unlocked identity.

## Build and install

Build with `cargo build`. Run `make install` to build and install the binary at
`$(HOME)/usr/bin/vault` by default. Set `PREFIX` to change the install prefix.

On macOS, installation signs the binary ad hoc by default. Set `SIGN_ID` to a
code-signing identity to use a different signature. The Secure Enclave design
does not require an Apple Developer identity, provisioning profile, app bundle,
or Keychain entitlement. Building it requires the macOS Command Line Tools and
Swift.

Linux installation is native and does not use macOS signing tools.

## Store and retrieve secrets

```sh
vault set API_KEY
printf '%s' 'secret' | vault isset API_KEY
vault get API_KEY
vault ls
vault rm API_KEY
vault purge
```

`set` reads from a masked terminal prompt, or from stdin when stdin is not a
terminal. `isset` reads stdin without a prompt or echo. `get` writes the value
followed by a newline. `ls` prints stored names in sorted order. `rm` deletes
one name. `purge` deletes all secrets managed by the current platform backend.

## Run commands with secrets

Pass environment specifications before `--` and the command after it:

```sh
vault API_KEY DATABASE_URL RUST_LOG=debug -- cargo run
```

`vault` treats a specification as a literal `NAME=VALUE` only when its name is
nonempty and it contains exactly one equals sign. Every other specification
names a stored secret. It starts the command directly, without a shell. The
child inherits the current environment and standard streams, and `vault`
returns the child's exit status.

## macOS Secure Enclave store

New secrets are encrypted with age to a single X25519 identity. A Swift bridge
uses CryptoKit to wrap that identity with a Secure Enclave P-256 key protected
by device-owner authentication. The private P-256 key is not exported. The
bridge uses CryptoKit instead of persistent Security.framework Keychain items,
so it needs no provisioning profile or Keychain entitlement. Secure Enclave
operations require macOS 10.15 or later and supported Secure Enclave hardware.

The first `vault set` initializes the store and asks for a strong recovery
passphrase and confirmation. `isset` still reads the secret silently, but
first-use store creation asks for that recovery passphrase. Later `set`
operations encrypt with the public age recipient. A `get` or `exec` unwraps
the identity once per invocation, then reads all requested age ciphertexts.
macOS device-owner
authentication may use Touch ID or the Mac login password; `vault` does not
claim Touch ID exclusively. Cancellation, unavailable hardware, malformed
sidecars, and authentication failures stop the operation.

The recovery identity is separately encrypted with age and stored as
`identity.age` beside the Secure Enclave sidecar. Keep a copy of the complete
store and its recovery passphrase somewhere safe. On this or a replacement Mac,
`vault recover` uses that passphrase to create a new device-bound Secure Enclave
key. The opaque `identity.se` sidecar alone is not portable.

The store is under `$XDG_DATA_HOME/vault` when `XDG_DATA_HOME` is absolute;
otherwise it is under `~/Library/Application Support/vault`. It contains
`identity.age`, `identity.se`, `recipient`, and encrypted files in `secrets/`.
New store names may contain any nonempty UTF-8 string up to 125 bytes. Secret
values stored in the age store are limited to 16 MiB. Secret names and the
public recipient are visible in the store layout.

Existing current-service file-Keychain items remain as compatibility entries.
`get` and `exec` can read those entries when no age store exists. With an age
store present, the Secure Enclave identity must first unlock successfully;
only a name absent from the age store can then be read from the current
Keychain service. A corrupt age ciphertext or failed Secure Enclave unlock
never falls back to Keychain. The compatibility items' `userPresence`
enforcement is unverified: the isolated harness read a dummy file-Keychain item
with interaction disabled. `ls` lists both stores. Re-entering a value with
`vault set NAME` writes the age ciphertext first, then removes the same-name
Keychain entry. Other Keychain entries remain available until replaced or
removed. The legacy `dev.joshuarli.vault` namespace is never read; `set`, `rm`,
and `purge` retain its existing cleanup behavior.

The Secure Enclave sidecar is an opaque file, not an app-identity access
control. Another process running as the same macOS user can copy it and request
its own device-owner authentication. After a successful unlock, the age
identity exists briefly in the `vault` process. A compromised same-user
process may inspect memory or capture requested secrets. This design protects
stored ciphertext from offline reading and requires OS-mediated device-owner
authentication for each new-store read; it does not isolate vault from other
processes owned by the same user.

## Linux age store

Linux uses the Rust age implementation and ordinary age ciphertext files. It
does not need PAM, D-Bus, systemd, a desktop keyring, or a background service.
The first `vault set NAME` initializes the store: `vault` asks for a master
passphrase and confirmation, creates an age identity, and encrypts that
identity with the passphrase. It then encrypts each secret to the identity's
public recipient. Later `set` and `isset` operations use the public recipient
and do not need the passphrase. The first `get` or exec read asks for the
passphrase. After a successful unlock, `vault` caches the decrypted identity in
the Linux per-user session keyring. The cache expires after 15 minutes of
inactivity. Successful reads refresh it when kernel keyring access is
available. `ls`, `rm`, and `purge` do not unlock the identity.

The store is under `$XDG_DATA_HOME/vault` when `XDG_DATA_HOME` is an absolute
path. Otherwise it uses `$HOME/.local/share/vault`. It contains
`identity.age`, `recipient`, and one encrypted file per secret in `secrets/`.
Secret values are limited to 16 MiB. Secret names and the public recipient are
visible in this layout.

Passphrase entry uses a controlling terminal with echo disabled. This works
when stdout is redirected, for example `token=$(vault get API_KEY)`. A cached
identity can be used without a terminal until it expires. Without a usable
cache, a fully headless invocation cannot prompt. `vault` has no passphrase
environment variable or command-line option. If the kernel keyring is disabled
or unavailable, reads still work but ask for the passphrase each time.

### Backup and recovery

Back up the complete `vault` directory, including `identity.age`, `recipient`,
and all files in `secrets/`. Keep the encrypted identity and its matching
ciphertexts together. Restore the directory to the same XDG location (or set
`XDG_DATA_HOME` to its parent) and preserve its restrictive file permissions.
Test that a backup can unlock and decrypt a secret before relying on it.

If the master passphrase is lost, the encrypted identity cannot be unlocked,
and the secrets cannot be recovered from that store. There is no password
recovery mechanism. Changing the passphrase means re-encrypting the same
private identity. Rotating the encryption identity means generating a new
private identity and re-encrypting every secret to its new recipient; merely
changing the passphrase does not do that, and old backups still contain the
old identity and ciphertexts. `vault` does not currently provide a rotation
command.

### Security limits

On Linux, `vault` prompts for the master passphrase. The prompt does not use
Secure Enclave or macOS Keychain access controls. A process that controls
`vault` or already runs as the same user may capture the passphrase, cached
identity, or secrets. Other processes with access to the user-session keyring
can use the cached identity until it expires. Store permissions protect
against other local users. A process with write access to the XDG data
directory can replace the public recipient. Later reads detect a mismatch
with the encrypted identity and fail without rebuilding the store. Because
`set` does not unlock the identity, it can encrypt a new secret to a replaced
recipient. Treat same-user write access as trusted.

Secret names and recipient metadata are not encrypted. `vault get` intentionally
reveals a secret on stdout. Exec mode places requested secrets in child
environment variables, which may be visible through process inspection or
inherited by descendants. Shell history can retain commands or literal
assignments typed at a shell prompt. Swap, core dumps, backups, and hostile
same-user processes have their own exposure risks. Removing a file is not
secure erasure, and `vault` cannot guarantee that sensitive data is removed
from memory or storage media.

Run `vault --help` for the command summary.
