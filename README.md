# vault

Store secrets in the macOS Keychain and inject them into commands.

## Install

### From source

```bash
make install
```

This builds the `dist` profile, code-signs the binary, and installs to `~/usr/bin/vault`.

Before your first build, create a self-signed code-signing identity (one-time setup):

```bash
/usr/bin/openssl req -x509 -newkey rsa:2048 \
  -keyout /tmp/vault-key.pem -out /tmp/vault-cert.pem \
  -days 3650 -nodes \
  -subj "/CN=Vault Signing" \
  -addext "basicConstraints=critical,CA:false" \
  -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=codeSigning"
/usr/bin/openssl pkcs12 -export \
  -out /tmp/vault-cert.p12 \
  -inkey /tmp/vault-key.pem -in /tmp/vault-cert.pem \
  -passout pass:vault
security import /tmp/vault-cert.p12 \
  -k ~/Library/Keychains/login.keychain-db \
  -P vault -T /usr/bin/codesign -A
rm /tmp/vault-key.pem /tmp/vault-cert.pem /tmp/vault-cert.p12
```

Code-signing gives vault a stable application identity; it does not bypass the authentication required for secret values.

### Prebuilt binary

Download the `vault` binary for your architecture, then:

```bash
# Remove the quarantine flag (macOS Gatekeeper)
xattr -d com.apple.quarantine vault

# Ad-hoc sign it. This gives the binary a stable application identity.
codesign --sign - --force --timestamp=none vault

# Move it somewhere on your PATH
mv vault ~/usr/bin/vault
```

The ad-hoc signature (`--sign -`) ties the identity to this exact binary — it won't survive updates, but you won't rebuild either. Secret reads still require Touch ID or the login password.

### Store a secret

```bash
vault set OPENAI_API_KEY
```

Prompts securely (echo disabled). Or pipe it in:

```bash
pbpaste | vault set OPENAI_API_KEY
```

### Retrieve a secret

```bash
vault get OPENAI_API_KEY
```

Prompts for Touch ID or the login password, then prints the value and nothing else. Safe for `$(...)`.

Secrets saved by older versions are intentionally not read by the protected namespace. Re-save each existing secret with `vault set NAME`; `vault rm NAME` and `vault purge` also clean up entries from the legacy namespace.

### Delete a secret

```bash
vault rm OPENAI_API_KEY
```

### List stored names

```bash
vault ls
```

Names only, never values.

### Reset authorization

```bash
vault lock
```

Resets the application partition authorization for every protected secret without deleting the values. macOS may ask once for the login Keychain password. The next access can ask for `vault` authorization again. This does not lock the login Keychain. Use `vault purge` to delete the secrets.

### Run a command with secrets

```bash
vault OPENAI_API_KEY DATABASE_URL -- cargo run
```

Authenticates before looking up `OPENAI_API_KEY` and `DATABASE_URL` in the Keychain, then injects them as environment variables.

Mix with literal values:

```bash
vault OPENAI_API_KEY RUST_LOG=debug PORT=8080 -- cargo run
```

No `--`, no exec:

```bash
vault OPENAI_API_KEY cargo run   # error: expected '--' before command
```
