# VLT-1: Existing-store writes trust the recipient file

Status: accepted

## Summary

`vault set` on an existing store encrypts to the `recipient` file. It does not check that file against the age identity. A same-user writer can replace the recipient. The next write succeeds with no prompt, and the planted identity can decrypt the new secret. Reads then fail until the recipient matches the identity again.

## Motivation

The macOS store is protected by a Secure Enclave unwrap on read. That check does not run on write. Linux avoids a passphrase prompt on write by trusting the same file, and [README.md](../../README.md) states that limit. The macOS write was the same behavior without that statement.

`set_secret_at` in `src/macos.rs` reads the recipient, checks that `identity.age` is an scrypt age file, checks the sidecar framing, and encrypts. It does not call `unwrap_identity`. `set_secret_at` in `src/linux.rs` reads the recipient and encrypts. The Linux test `cache_clear_is_store_scoped_and_recipient_replacement_does_not_hide_stale_cache` expects a replaced recipient to receive the next secret without a prompt.

A macOS probe built a store under a temporary `XDG_DATA_HOME` with a scrypt `identity.age`, a framed `identity.se`, and a recipient from a new age identity. `vault set TOKEN` read the secret from stdin, exited 0, and wrote `secrets/544f4b454e.age`. Decrypting that file with the planted identity returned the stdin value. Standard error was empty.

## Design

For an existing store, pick the identity before encrypting.

1. If the cache holds an identity whose public key is the recipient file, use it.
2. Otherwise unlock. Linux asks for the master passphrase. macOS unwraps the Secure Enclave sidecar with `Interaction::MayPrompt`.
3. If that identity's public key is not the recipient file, return an error and write nothing. Do not replace `recipient`.
4. Encrypt the secret to that identity and publish it with the existing atomic replace.

A warm cache whose recipient still matches does not prompt. A cold cache prompts. `validate_identity_recipient` on read stays as it is.

## Alternatives considered

Document the macOS hole and leave both write paths unchanged. Writes stay prompt-free, including the silent planted-recipient write.

Change only the macOS path. Linux would still accept a planted recipient for later secrets, which is what its test records today.

## Open questions

Should a cold cache prompt on write, or should the write fail until a read or another command has unlocked the store?

Should a mismatched recipient fail the write, or should vault rewrite `recipient` from the unlocked identity and then store the secret?

## Decision

Existing-store writes use the cached identity when its public key is the recipient file. Otherwise they unlock: Linux asks for the master passphrase, and macOS unwraps the Secure Enclave sidecar with `Interaction::MayPrompt`. If that identity's public key is not the recipient file, the write returns an error and leaves the store unchanged, including `recipient`. A warm cache whose recipient still matches does not prompt. A cold cache prompts. Read validation is unchanged.
