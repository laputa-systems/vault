use age::secrecy::{ExposeSecret, SecretString};
use age::{Decryptor, Encryptor};
use std::io::{Read, Write};
use std::str::FromStr;
use zeroize::{Zeroize, Zeroizing};

pub(crate) const MAX_SECRET_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_SECRET_CIPHERTEXT: usize = MAX_SECRET_BYTES + 1024 * 1024;
pub(crate) const MAX_IDENTITY_CIPHERTEXT: usize = 1024 * 1024;
pub(crate) const MAX_IDENTITY_PLAINTEXT: usize = 1024;
pub(crate) const MAX_RECIPIENT_BYTES: usize = 256;

pub(crate) fn encrypt_secret(
    recipient: &age::x25519::Recipient,
    value: &[u8],
) -> Result<Vec<u8>, String> {
    age::encrypt(recipient, value).map_err(|_| "age encryption failed".to_owned())
}

pub(crate) fn decrypt_secret(
    identity: &age::x25519::Identity,
    encrypted: &[u8],
) -> Result<Zeroizing<String>, String> {
    let decryptor = Decryptor::new_buffered(encrypted)
        .map_err(|_| "invalid age ciphertext".to_owned())?;
    let reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|_| "no matching recipient".to_owned())?;
    let mut plaintext = Zeroizing::new(Vec::new());
    reader
        .take(MAX_SECRET_BYTES as u64 + 1)
        .read_to_end(&mut plaintext)
        .map_err(|_| "age ciphertext authentication failed".to_owned())?;
    if plaintext.len() > MAX_SECRET_BYTES {
        return Err("decrypted secret exceeds the size limit".to_owned());
    }
    match String::from_utf8(std::mem::take(&mut *plaintext)) {
        Ok(value) => Ok(Zeroizing::new(value)),
        Err(error) => {
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            Err("decrypted secret is not valid UTF-8".to_owned())
        }
    }
}

pub(crate) fn encrypt_identity(
    plaintext: &[u8],
    passphrase: SecretString,
) -> Result<Vec<u8>, String> {
    let encryptor = Encryptor::with_user_passphrase(passphrase);
    let mut ciphertext = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut ciphertext)
        .map_err(|source| format!("vault: encrypt private identity failed: {source}"))?;
    writer
        .write_all(plaintext)
        .map_err(|source| format!("vault: encrypt private identity failed: {source}"))?;
    writer
        .finish()
        .map_err(|source| format!("vault: finish encrypted identity failed: {source}"))?;
    Ok(ciphertext)
}

pub(crate) fn decrypt_identity(
    encrypted: &[u8],
    passphrase: SecretString,
) -> Result<age::x25519::Identity, String> {
    let decryptor = Decryptor::new_buffered(encrypted)
        .map_err(|_| "vault: encrypted identity is malformed".to_owned())?;
    let identity = age::scrypt::Identity::new(passphrase);
    let reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|_| {
            "vault: passphrase is incorrect or the encrypted identity is damaged"
                .to_owned()
        })?;
    let mut plaintext = Zeroizing::new(Vec::new());
    reader
        .take(MAX_IDENTITY_PLAINTEXT as u64 + 1)
        .read_to_end(&mut plaintext)
        .map_err(|_| "vault: encrypted identity is damaged".to_owned())?;
    if plaintext.len() > MAX_IDENTITY_PLAINTEXT {
        return Err("vault: decrypted identity exceeds the maximum size".to_owned());
    }
    let identity_text = match String::from_utf8(std::mem::take(&mut *plaintext)) {
        Ok(text) => SecretString::from(text),
        Err(error) => {
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            return Err("vault: decrypted identity is not valid UTF-8".to_owned());
        }
    };
    let line = identity_text
        .expose_secret()
        .strip_suffix('\n')
        .unwrap_or(identity_text.expose_secret());
    if line.contains('\n') || line.contains('\r') {
        return Err("vault: decrypted identity has an invalid format".to_owned());
    }
    age::x25519::Identity::from_str(line)
        .map_err(|_| "vault: decrypted identity is not a valid age X25519 identity".to_owned())
}

pub(crate) fn parse_recipient(bytes: &[u8]) -> Result<age::x25519::Recipient, String> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| "vault: public recipient is not valid UTF-8".to_owned())?;
    let address = text.strip_suffix('\n').unwrap_or(text);
    if address.is_empty() || address.contains('\n') || address.contains('\r') {
        return Err("vault: public recipient is malformed".to_owned());
    }
    let recipient = age::x25519::Recipient::from_str(address)
        .map_err(|_| "vault: public recipient is not a valid age X25519 recipient".to_owned())?;
    if recipient.to_string() != address {
        return Err("vault: public recipient is not in canonical form".to_owned());
    }
    Ok(recipient)
}

pub(crate) fn validate_identity_recipient(
    identity: &age::x25519::Identity,
    recipient: &age::x25519::Recipient,
) -> Result<(), String> {
    if identity.to_public().to_string() != recipient.to_string() {
        return Err("vault: recipient does not match the encrypted identity".to_owned());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn validate_name(name: &str) -> Result<(), String> {
    let bytes = name.as_bytes();
    let Some(first) = bytes.first() else {
        return Err("vault: empty name not allowed".to_owned());
    };
    if !(first.is_ascii_alphabetic() || *first == b'_')
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    {
        return Err(format!("vault: invalid secret name {name:?}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        decrypt_identity, decrypt_secret, encrypt_identity, encrypt_secret,
        validate_identity_recipient,
    };
    use age::secrecy::{ExposeSecret, SecretString};

    #[test]
    fn encrypted_identity_and_secret_preserve_age_format() {
        let identity = age::x25519::Identity::generate();
        let recipient = identity.to_public();
        let secret = b"disposable test value";
        let encrypted_secret = encrypt_secret(&recipient, secret).unwrap();
        assert_eq!(decrypt_secret(&identity, &encrypted_secret).unwrap().as_bytes(), secret);

        let private_key = identity.to_string();
        let mut recovery_plaintext = zeroize::Zeroizing::new(private_key.expose_secret().as_bytes().to_vec());
        recovery_plaintext.push(b'\n');
        let recovery_passphrase = SecretString::from("disposable recovery passphrase".to_owned());
        let encrypted_identity = encrypt_identity(&recovery_plaintext, recovery_passphrase).unwrap();
        let restored = decrypt_identity(
            &encrypted_identity,
            SecretString::from("disposable recovery passphrase".to_owned()),
        )
        .unwrap();
        validate_identity_recipient(&restored, &recipient).unwrap();
        assert_eq!(restored.to_public().to_string(), recipient.to_string());
    }

    #[test]
    fn encrypted_secret_rejects_tampering() {
        let identity = age::x25519::Identity::generate();
        let mut ciphertext = encrypt_secret(&identity.to_public(), b"disposable").unwrap();
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 1;
        assert!(decrypt_secret(&identity, &ciphertext).is_err());
    }
}
