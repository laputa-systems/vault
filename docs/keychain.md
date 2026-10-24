# Keychain

vault does not use the macOS Keychain. Tested file-based Keychain items stayed
readable with interaction disabled, so user-presence enforcement could not be
verified, and the Data Protection Keychain needed entitlements that were never
provisioned. macOS secrets live only in the age store described in
[README.md](../README.md); the retired Keychain services are listed in
[AGENTS.md](../AGENTS.md).
