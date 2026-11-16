# Linux keyring checks

Run these checks on a Linux login session with the user-session keyring
available. The test store and identity are disposable; production secrets
are not used. A container that denies keyring syscalls cannot establish
these contracts.

Ensure `.work/` is ignored and create `.work/tmp`, then run:

```sh
TMPDIR="$PWD/.work/tmp" cargo test --bin vault linux::tests::identity_cache_permissions_expiry_refresh_and_revocation_are_enforced -- --exact --show-output
TMPDIR="$PWD/.work/tmp" cargo test --bin vault linux::tests::cache_clear_is_store_scoped_and_recipient_replacement_does_not_hide_stale_cache -- --exact --show-output
```

Each command must report one passing test with no `skipped keyring
assertions`, `skipped key timeout query`, or `skipped cache scope assertions`
message. A successful test exit with any of those messages leaves the
corresponding check unverified. Record the host, kernel, revision and
complete output. The checks cover identity permissions, timeout refresh,
revocation, store separation and stale-cache behavior after recipient
replacement.

The default Docker profile on the development Mac denies these syscalls;
its two visible skips are not keyring acceptance. CI's required rage
interoperability test is independent of keyring availability and fails
when the pinned tool is missing or has the wrong version.
