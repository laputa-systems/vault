# vault

`vault` is a macOS command-line tool that stores secrets in Keychain and passes them to child commands.

## Build

Run `cargo build` to compile the CLI. A supported signing and installation path for Data Protection Keychain use has not been established.

## Keychain behavior

The current code uses macOS's default file-based Keychain. It does not explicitly select the Data Protection Keychain.

New Generic Password items request `userPresence` and `WhenUnlockedThisDeviceOnly`. The isolated file-Keychain test still read a dummy item with interaction disabled, so enforced user presence is not established. Updates change an item's value without replacing its access control, so an existing item's policy may be weaker.

An ad-hoc-signed harness could not add an item to the Data Protection Keychain and returned `errSecMissingEntitlement`. The tested host had no valid signing identity or standard provisioning profile, so the app-like signing path was not tested.

The detached tmux harness ran without SSH, with stdin attached to a TTY, and exited 0. It reported the same readable file-Keychain item and `errSecMissingEntitlement` result. A separate attached, non-TTY run used local tmux. The opt-in TTY run reported Touch ID or owner authentication available, but item creation failed before a prompt. Keychain authorization and reuse across reads remain unproven.

The `vault lock` command was removed because an isolated file-Keychain `userPresence` item remained readable with interaction disabled after a partition-list change.

## Store and retrieve secrets

Run `vault set NAME` to enter a value at a masked terminal prompt. If stdin is not a terminal, `set` reads stdin without a prompt. Run `vault isset NAME` to read stdin without a prompt or echo.

Terminal input fails on invalid UTF-8 or if `vault` cannot disable or restore terminal echo. Press Ctrl-C during terminal input to cancel. `vault` restores the terminal and exits without storing the input. Press Ctrl-Z to suspend `vault`; it restores the terminal while stopped and resumes masked input when continued.

```sh
vault set API_KEY
pbpaste | vault isset API_KEY
vault get API_KEY
vault ls
vault rm API_KEY
vault purge
```

`get` prints the value followed by a newline. `ls` prints stored names in sorted order. `rm` deletes one name and its matching legacy entry.

`purge` takes no arguments and deletes every managed secret, including legacy entries. `set` removes a matching legacy entry after it stores the new value. `vault` never retrieves secret values from the legacy namespace.

There is no migration command for moving items into the Data Protection Keychain. Existing items remain in the current file-based Keychain domain.

## Run commands with secrets

Pass environment specifications before `--` and the command after it:

```sh
vault API_KEY DATABASE_URL RUST_LOG=debug -- cargo run
```

`vault` treats a specification as literal `NAME=VALUE` only when its name is nonempty and it contains exactly one equals sign. Every other specification names a Keychain item. For example, `NAME=` is a literal empty value. `=VALUE` has an empty name, so it names a Keychain item. `NAME=one=two` has multiple equals signs, so it also names a Keychain item.

`vault` starts the command directly, without a shell. The child inherits the current environment and standard streams. `vault` returns the child's exit status.

Run `vault --help` for the command summary.
