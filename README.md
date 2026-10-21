# vault

`vault` stores secrets and supplies them to child commands. It uses the native
Keychain on macOS and an age-encrypted local store on Linux.

## Build and install

Build with `cargo build`. Run `make install` to build and install the binary at
`$(HOME)/usr/bin/vault` by default. Set `PREFIX` to change the install prefix.

On macOS, installation signs the binary with `SIGN_ID` (default:
`Vault Signing`). Set `SIGN_ID` to an available code-signing identity. Linux
installation is native and does not use macOS signing tools.

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

## macOS Keychain

On macOS, secrets remain Generic Password items in the existing file-based
Keychain namespace, and each read continues to use the existing Keychain
request. New items request `userPresence` and
`WhenUnlockedThisDeviceOnly`. The tested host could read a dummy item with
interaction disabled, so actual per-read user-presence enforcement remains
unverified. The tested signing setup could not add an item to the Data
Protection Keychain. Updates change an existing item's value without replacing
its access control, so an existing item's policy may be weaker. `vault` does
not migrate or rewrite existing Keychain data as part of Linux support.

## Linux age store

Linux uses the Rust age implementation and ordinary age ciphertext files. It
does not need PAM, D-Bus, systemd, a desktop keyring, or a background service.
The first `vault set NAME` initializes the store: `vault` asks for a master
passphrase and confirmation, creates an age identity, and encrypts that
identity with the passphrase. It then encrypts each secret to the identity's
public recipient. Later `set` and `isset` operations use the public recipient
and do not need the passphrase. `get` and exec mode ask for the passphrase to
unlock the identity; `ls`, `rm`, and `purge` do not.

The store is under `$XDG_DATA_HOME/vault` when `XDG_DATA_HOME` is an absolute
path. Otherwise it uses `$HOME/.local/share/vault`. It contains
`identity.age`, `recipient`, and one encrypted file per secret in `secrets/`.
Secret values are limited to 16 MiB. Secret names and the public recipient are
visible in this layout.

Passphrase entry uses a controlling terminal with echo disabled. This works
when stdout is redirected, for example `token=$(vault get API_KEY)`, but
unlocking requires a usable terminal. A fully headless invocation without a
controlling terminal cannot prompt; no passphrase environment variable or
command-line option is provided.

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

Linux passphrase entry is enforced by `vault`; it is not backed by the Secure
Enclave or macOS Keychain access-control policies. A process that can control
the running user's executable or already runs as that user may capture the
passphrase or secrets. Store permissions protect against other local users. A
process with write access to the XDG data directory can replace the public
recipient. Later authenticated reads detect a mismatch with the encrypted
identity and fail without rebuilding the store, but `set` does not unlock the
identity and can encrypt a new secret to a replaced recipient. Treat same-user
write access as trusted.

Secret names and recipient metadata are not encrypted. `vault get` intentionally
reveals a secret on stdout. Exec mode places requested secrets in child
environment variables, which may be visible through process inspection or
inherited by descendants. Shell history can retain commands or literal
assignments typed at a shell prompt. Swap, core dumps, backups, and hostile
same-user processes have their own exposure risks. Removing a file is not
secure erasure, and `vault` cannot guarantee that sensitive data is removed
from memory or storage media.

Run `vault --help` for the command summary.
