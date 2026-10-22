# vault

`vault` stores secrets on macOS and Linux and can pass them to child commands.

## Install

Run `make install` from a repository checkout. It uses the pinned Rust nightly
and `rust-src`. The default path is `~/usr/bin/vault`; set `PREFIX` to change
it. macOS also requires the Command Line Tools and Swift. Installation signs
the binary ad hoc by default; set `SIGN_ID` to use another signing identity.

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

New secrets use age encryption with an X25519 identity wrapped by a Secure
Enclave P-256 key. Secure Enclave operations require macOS 10.15 or later and
supported Secure Enclave hardware. Device-owner authentication may use Touch ID
or the Mac login password.

The first stored secret creates a recovery identity and asks for a separate
recovery passphrase. Back up the complete store and keep that passphrase safe.
The default store is `~/Library/Application Support/vault`, or
`$XDG_DATA_HOME/vault` when `XDG_DATA_HOME` is absolute. The opaque Secure
Enclave identity file cannot be used on another Mac by itself. Run
`vault recover` with the recovery passphrase to create a new device-bound key.

Existing Keychain items remain in compatibility mode. Backups of the age store
do not include those Keychain items. If an age store exists,
the Secure Enclave identity must first unlock successfully before vault can
read a missing age name from Keychain. The compatibility items' `userPresence`
enforcement is unverified; the isolated harness read a disposable file-Keychain
item without interaction. `vault set NAME` replaces a same-name compatibility
item after storing the new encrypted value. On macOS, `ls` includes names from
both stores.

## Linux storage and recovery

Linux encrypts secrets with age and protects the identity with a master
passphrase. The first stored secret asks you to create and confirm the
passphrase. The first read asks for it. After unlocking, vault caches the
identity in the Linux user-session keyring. The cache expires after 15 minutes
of inactivity. Losing the passphrase makes that store unrecoverable.

The default store is `$HOME/.local/share/vault`, or `$XDG_DATA_HOME/vault` when
`XDG_DATA_HOME` is absolute. Back up the complete directory and retain the
passphrase separately.

## Limits

Secret values are limited to 16 MiB. Secret names and public recipient metadata
are visible. On macOS, another same-user process can copy the opaque sidecar and
request its own device-owner authentication. After unlock, the age identity
exists briefly in vault's memory. On Linux, a process that can read the
per-user keyring can use the cached identity until it expires. Removing a
secret does not securely erase storage media. `get` prints secrets to stdout;
exec mode places them in child environment variables, which other same-user
processes may be able to inspect.

Run `vault --help` for the command summary.

## License

This repository does not declare a license.
