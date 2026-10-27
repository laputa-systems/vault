# vault

`vault` stores secrets on macOS and Linux and can pass them to child commands.

## Install

Download a prerelease from
[GitHub Releases](https://github.com/laputa-systems/vault/releases). The tag is
`release-<commit>`. The assets are `vault-aarch64-apple-darwin.zip`,
`vault-aarch64-unknown-linux-musl.zip`, `vault-x86_64-unknown-linux-musl.zip`,
and `SHA256SUMS`. Unzip the archive for your machine, check it against
`SHA256SUMS`, and put the executable on your `PATH`. The file inside the zip
has the same name as the archive. Linux executables are static musl binaries.

## Store and retrieve secrets

```sh
vault set API_KEY
printf '%s' 'secret' | vault isset API_KEY
vault get API_KEY
vault ls
vault rm API_KEY
vault purge
```

`set` reads a hidden terminal prompt or stdin. `isset` reads stdin without a
prompt or echo. `get` prints the value with a trailing newline. `ls` lists names,
`rm` deletes one secret, and `purge` deletes all secrets managed by vault.

## Run a command with secrets

List secret names or literal environment assignments before `--`, then give
the command and its arguments:

```sh
vault API_KEY DATABASE_URL RUST_LOG=debug -- cargo run
```

`vault` starts the command without a shell. The child inherits the current
environment and standard streams, and vault returns the child's exit status.

## macOS storage and recovery

Secrets use age encryption with an X25519 identity wrapped by a Secure
Enclave P-256 key. Secure Enclave operations require macOS 10.15 or later and
supported Secure Enclave hardware. Device-owner authentication may use Touch ID
or the Mac login password.

The first stored secret creates a recovery identity and asks for a separate
recovery passphrase. Back up the complete store and keep that passphrase safe.
The default store is `~/Library/Application Support/vault`, or
`$XDG_DATA_HOME/vault` when `XDG_DATA_HOME` is absolute. The opaque Secure
Enclave identity file cannot be used on another Mac by itself. Run
`vault recover` with the recovery passphrase to create a new device-bound key.
Vault no longer reads or writes Keychain items; macOS secrets are available only
from the age store.

The first read asks for device-owner authentication. After unlocking, vault
caches the decrypted identity in a per-store background daemon. The cache
expires after 15 minutes of inactivity. `vault lock` clears this store's cached
identity.

## Linux storage and recovery

Linux encrypts secrets with age and protects the identity with a master
passphrase. The first stored secret asks you to create and confirm the
passphrase. The first read asks for it. After unlocking, vault caches the
identity in the Linux user-session keyring. The cache expires after 15 minutes
of inactivity. Losing the passphrase makes that store unrecoverable.

The default store is `$HOME/.local/share/vault`, or `$XDG_DATA_HOME/vault` when
`XDG_DATA_HOME` is absolute. Back up the complete directory and retain the
passphrase separately. `vault lock` removes this store's cached identity from
the user-session keyring. Replacing or rewrapping `identity.age` does not
revoke an identity already in the cache.

## Limits

Secret values are limited to 16 MiB and must be valid UTF-8. Secret names and
public recipient metadata are visible. On macOS, another same-user process can
copy the opaque sidecar and request its own device-owner authentication. Within
15 minutes of a read, it can also read the cached identity from the daemon
without authenticating. On Linux, the user-session keyring is shared across
independent sessions for the same UID. A process with access can read and
retain the complete decrypted identity beyond its 15-minute keyring timeout.
`vault lock` removes the store's cached identity but cannot erase copies
already made or guarantee physical erasure. A same-user process with write
access to the store can replace the public recipient. A later write uses a cached
identity only when its public key is that recipient. Otherwise it asks for the
master passphrase on Linux, or for device-owner authentication on macOS, and
fails without writing a secret or replacing the recipient when the unlocked
identity does not match. Reads fail until the recipient matches the identity
again. Removing a
secret does not securely erase storage media. `get` prints secrets to stdout.
Exec mode places them in child environment variables, which other same-user
processes may be able to inspect.

## License

This repository does not declare a license.
