# vault

`vault` stores secrets in the macOS login Keychain and injects them into commands.

## Install

When an Apple silicon release is published, download its `vault` binary from [Releases](https://github.com/laputa-systems/vault/releases).
Remove quarantine, sign the binary, and install it in a directory on your `PATH`:

```sh
xattr -d com.apple.quarantine vault
codesign --sign - --force --timestamp=none vault
mkdir -p ~/usr/bin
install -m 755 vault ~/usr/bin/vault
```

The ad-hoc signature identifies this exact build. A new binary may need Keychain authorization again.

## Manage secrets

```sh
vault set API_KEY
```

Enter the value at the hidden prompt, or pipe it in:

```sh
pbpaste | vault set API_KEY
```

- `vault isset NAME` stores a value read from stdin without a prompt.
- `vault get NAME` prints only the value and may request Touch ID or your login password.
- `vault ls` lists stored names.
- `vault lock` resets authorization for vault secrets without deleting them.
- `vault rm NAME` deletes one secret.
- `vault purge` deletes all secrets managed by vault.

macOS may request your login Keychain password during `vault lock`; the next access may ask to authorize vault again.

Secrets saved by older versions are not read. Re-save them with `vault set NAME`; `vault rm NAME` and `vault purge` also remove entries from the legacy namespace.

## Run commands

```sh
vault API_KEY DATABASE_URL RUST_LOG=debug -- cargo run
```

An environment spec is a Keychain name unless it contains exactly one `=` after a nonempty name; that form passes a literal value. vault runs the command directly, without a shell.

Run `vault --help` for the command summary.
