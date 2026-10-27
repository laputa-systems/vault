Prefix: VLT
Next: 2

### VLT-1 · P2 · Existing-store writes trust the recipient file

- **Area:** Security
- **Where:** `src/macos.rs:114`, `src/linux.rs:170`, `src/linux.rs:1458`
- **Problem:** On an existing store, `set` encrypts to the `recipient` file and does not compare it to the age identity. A same-user process that can write the store can replace that file. The next `vault set` exits 0 without a passphrase prompt and without device-owner authentication, and the planted identity decrypts the new secret. Reads of existing secrets then fail `validate_identity_recipient` until the original recipient is restored. Linux documents the write and locks it in with `cache_clear_is_store_scoped_and_recipient_replacement_does_not_hide_stale_cache`. macOS takes the same path in `set_secret_at` and does not call `unwrap_identity`. Proven on macOS: a temporary store with an scrypt `identity.age`, a framed `identity.se`, and an attacker recipient accepted `vault set TOKEN` from stdin (exit 0, empty stderr), and `age::decrypt` with the planted identity returned the submitted value. Priority assumed.
- **Recommendation:** On an existing store, encrypt only to an unlocked identity. Use the cache when it matches the recipient file. Otherwise prompt (Linux passphrase or macOS Secure Enclave unwrap). If the recipient file does not match, fail the write and do not change the recipient file. Replace the Linux test that requires a planted recipient to receive the write. Update the write rule in `README.md` and `AGENTS.md` in the same change.
- **Fix with:** none
- **Effort:** M
- **Design:** [docs/rfc/VLT-1-recipient-write.md](docs/rfc/VLT-1-recipient-write.md)
