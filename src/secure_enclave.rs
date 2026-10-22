use std::error::Error;
use std::ffi::c_int;
use std::fmt;
use std::slice;

use zeroize::Zeroizing;

const MAX_NATIVE_BUFFER: usize = 1 << 20;

#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Interaction {
    MayPrompt = 0,
    #[cfg(test)]
    Disallowed = 1,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum SecureEnclaveError {
    Cancelled,
    Unavailable(String),
    LockedOut(String),
    CorruptSidecar(String),
    Failed(String),
}

impl fmt::Display for SecureEnclaveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("Secure Enclave authentication was cancelled"),
            Self::Unavailable(message) => write!(formatter, "Secure Enclave is unavailable: {message}"),
            Self::LockedOut(message) => write!(formatter, "Secure Enclave authentication is locked out: {message}"),
            Self::CorruptSidecar(message) => write!(formatter, "Secure Enclave sidecar is corrupt: {message}"),
            Self::Failed(message) => write!(formatter, "Secure Enclave operation failed: {message}"),
        }
    }
}

impl Error for SecureEnclaveError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
enum Status {
    Ok = 0,
    Cancelled = 1,
    Unavailable = 2,
    LockedOut = 3,
    CorruptSidecar = 4,
    Failed = 5,
}

impl Status {
    fn from_raw(value: c_int) -> Option<Self> {
        match value {
            0 => Some(Self::Ok),
            1 => Some(Self::Cancelled),
            2 => Some(Self::Unavailable),
            3 => Some(Self::LockedOut),
            4 => Some(Self::CorruptSidecar),
            5 => Some(Self::Failed),
            _ => None,
        }
    }

    fn error(self, message: String) -> Option<SecureEnclaveError> {
        match self {
            Self::Ok => None,
            Self::Cancelled => Some(SecureEnclaveError::Cancelled),
            Self::Unavailable => Some(SecureEnclaveError::Unavailable(message)),
            Self::LockedOut => Some(SecureEnclaveError::LockedOut(message)),
            Self::CorruptSidecar => Some(SecureEnclaveError::CorruptSidecar(message)),
            Self::Failed => Some(SecureEnclaveError::Failed(message)),
        }
    }
}

unsafe extern "C" {
    fn vault_se_wrap_identity(
        identity_pointer: *const u8,
        identity_length: usize,
        binding_pointer: *const u8,
        binding_length: usize,
        output_pointer: *mut *mut u8,
        output_length: *mut usize,
        error_pointer: *mut *mut u8,
        error_length: *mut usize,
    ) -> c_int;

    fn vault_se_unwrap_identity(
        sidecar_pointer: *const u8,
        sidecar_length: usize,
        binding_pointer: *const u8,
        binding_length: usize,
        interaction: c_int,
        output_pointer: *mut *mut u8,
        output_length: *mut usize,
        error_pointer: *mut *mut u8,
        error_length: *mut usize,
    ) -> c_int;

    fn vault_se_validate_sidecar(
        sidecar_pointer: *const u8,
        sidecar_length: usize,
        error_pointer: *mut *mut u8,
        error_length: *mut usize,
    ) -> c_int;

    fn vault_se_free(pointer: *mut u8, length: usize);
}

struct NativeBuffer {
    pointer: *mut u8,
    length: usize,
}

impl NativeBuffer {
    fn empty() -> Self {
        Self { pointer: std::ptr::null_mut(), length: 0 }
    }

    fn copy(&self) -> Result<Vec<u8>, SecureEnclaveError> {
        if self.pointer.is_null() || self.length == 0 || self.length > MAX_NATIVE_BUFFER {
            return Err(SecureEnclaveError::Failed("native bridge returned an invalid output buffer".into()));
        }
        // SAFETY: Swift returned a live, aligned allocation with `length` initialized bytes; this owner is its only reader until `vault_se_free`.
        let bytes = unsafe { slice::from_raw_parts(self.pointer, self.length) };
        Ok(bytes.to_vec())
    }

    fn message(&self) -> String {
        if self.pointer.is_null() || self.length == 0 || self.length > MAX_NATIVE_BUFFER {
            return "native bridge returned no error detail".into();
        }
        // SAFETY: Swift returned a live, aligned allocation with `length` initialized bytes; this owner is its only reader until `vault_se_free`.
        let bytes = unsafe { slice::from_raw_parts(self.pointer, self.length) };
        String::from_utf8_lossy(bytes).into_owned()
    }
}

impl Drop for NativeBuffer {
    fn drop(&mut self) {
        if !self.pointer.is_null() {
            // SAFETY: Swift returned this live malloc allocation and its exact length; this owner frees it once after all reads.
            unsafe { vault_se_free(self.pointer, self.length) };
            self.pointer = std::ptr::null_mut();
            self.length = 0;
        }
    }
}

pub(crate) fn wrap_identity(identity: &[u8], binding: &[u8]) -> Result<Vec<u8>, SecureEnclaveError> {
    if identity.is_empty() || binding.is_empty() {
        return Err(SecureEnclaveError::Failed("identity and binding must be non-empty".into()));
    }
    let mut output = NativeBuffer::empty();
    let mut error = NativeBuffer::empty();
    // SAFETY: Input slices are initialized and valid for their lengths during the call; output handles are aligned initialized locals, and Swift does not retain input pointers or unwind across C.
    let status = unsafe {
        vault_se_wrap_identity(
            identity.as_ptr(),
            identity.len(),
            binding.as_ptr(),
            binding.len(),
            &mut output.pointer,
            &mut output.length,
            &mut error.pointer,
            &mut error.length,
        )
    };
    finish(status, output, error)
}

pub(crate) fn unwrap_identity(
    sidecar: &[u8],
    binding: &[u8],
    interaction: Interaction,
) -> Result<Zeroizing<Vec<u8>>, SecureEnclaveError> {
    if binding.is_empty() {
        return Err(SecureEnclaveError::Failed("binding must be non-empty".into()));
    }
    validate_sidecar(sidecar)?;
    let mut output = NativeBuffer::empty();
    let mut error = NativeBuffer::empty();
    // SAFETY: Input slices are initialized and valid for their lengths during the call; output handles are aligned initialized locals, and Swift does not retain input pointers or unwind across C.
    let status = unsafe {
        vault_se_unwrap_identity(
            sidecar.as_ptr(),
            sidecar.len(),
            binding.as_ptr(),
            binding.len(),
            interaction as c_int,
            &mut output.pointer,
            &mut output.length,
            &mut error.pointer,
            &mut error.length,
        )
    };
    finish(status, output, error).map(Zeroizing::new)
}

pub(crate) fn validate_sidecar(sidecar: &[u8]) -> Result<(), SecureEnclaveError> {
    if sidecar.is_empty() || sidecar.len() > MAX_NATIVE_BUFFER {
        return Err(SecureEnclaveError::CorruptSidecar("sidecar length is invalid".into()));
    }
    let mut error = NativeBuffer::empty();
    // SAFETY: The input slice is initialized and valid for its length during the call; output handles are aligned initialized locals, and Swift does not retain the input pointer or unwind across C.
    let status = unsafe {
        vault_se_validate_sidecar(
            sidecar.as_ptr(),
            sidecar.len(),
            &mut error.pointer,
            &mut error.length,
        )
    };
    let Some(status) = Status::from_raw(status) else {
        return Err(SecureEnclaveError::Failed(format!("native bridge returned unknown status {status}")));
    };
    match status.error(error.message()) {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn finish(status: c_int, output: NativeBuffer, error: NativeBuffer) -> Result<Vec<u8>, SecureEnclaveError> {
    let Some(status) = Status::from_raw(status) else {
        return Err(SecureEnclaveError::Failed(format!("native bridge returned unknown status {status}")));
    };
    if let Some(error) = status.error(error.message()) {
        return Err(error);
    }
    output.copy()
}

#[cfg(test)]
mod tests {
    use super::{Interaction, SecureEnclaveError, Status, unwrap_identity, validate_sidecar, wrap_identity};
    use crate::store::{decrypt_secret, encrypt_secret};
    use age::secrecy::ExposeSecret;
    use std::str::FromStr;

    #[test]
    fn interaction_values_match_the_swift_abi() {
        assert_eq!(Interaction::MayPrompt as i32, 0);
        assert_eq!(Interaction::Disallowed as i32, 1);
    }

    #[test]
    fn native_statuses_preserve_failure_categories() {
        assert_eq!(Status::from_raw(0), Some(Status::Ok));
        assert_eq!(Status::from_raw(1).and_then(|status| status.error(String::new())), Some(SecureEnclaveError::Cancelled));
        assert_eq!(Status::from_raw(2).and_then(|status| status.error("hardware absent".into())), Some(SecureEnclaveError::Unavailable("hardware absent".into())));
        assert_eq!(Status::from_raw(3).and_then(|status| status.error("locked".into())), Some(SecureEnclaveError::LockedOut("locked".into())));
        assert_eq!(Status::from_raw(4).and_then(|status| status.error("bad format".into())), Some(SecureEnclaveError::CorruptSidecar("bad format".into())));
        assert_eq!(Status::from_raw(5).and_then(|status| status.error("internal failure".into())), Some(SecureEnclaveError::Failed("internal failure".into())));
        assert_eq!(Status::from_raw(99), None);
    }

    #[test]
    fn sidecar_validator_rejects_unknown_versions_without_authentication() {
        let error = validate_sidecar(b"VLTSE\x02").unwrap_err();
        assert!(matches!(error, SecureEnclaveError::CorruptSidecar(_)));
    }

    #[test]
    fn sidecar_validator_rejects_invalid_lengths_without_authentication() {
        let mut sidecar = b"VLTSE\x01".to_vec();
        sidecar.extend([0; 12]);
        let error = validate_sidecar(&sidecar).unwrap_err();
        assert!(matches!(error, SecureEnclaveError::CorruptSidecar(_)));
    }

    #[test]
    #[ignore = "requires Secure Enclave hardware and interactive device-owner authentication"]
    fn secure_enclave_wrap_denies_noninteractive_access_and_unlocks_age_identity() {
        let identity = age::x25519::Identity::generate();
        let recipient = identity.to_public();
        let private_key = identity.to_string();
        let recipient_binding = recipient.to_string();
        let mut binding = b"dev.joshuarli.vault\0age-x25519\0".to_vec();
        binding.extend_from_slice(recipient_binding.as_bytes());
        let ciphertext = encrypt_secret(&recipient, b"disposable Secure Enclave test value").unwrap();
        let sidecar = wrap_identity(private_key.expose_secret().as_bytes(), &binding).unwrap();

        let denied = unwrap_identity(&sidecar, &binding, Interaction::Disallowed).unwrap_err();
        assert!(matches!(denied, SecureEnclaveError::Unavailable(_)));

        let restored = unwrap_identity(&sidecar, &binding, Interaction::MayPrompt).unwrap();
        assert_eq!(restored.as_slice(), private_key.expose_secret().as_bytes());
        let restored_text = std::str::from_utf8(&restored).unwrap();
        let restored_identity = age::x25519::Identity::from_str(restored_text).unwrap();
        let plaintext = decrypt_secret(&restored_identity, &ciphertext).unwrap();
        assert_eq!(plaintext.as_str(), "disposable Secure Enclave test value");

        let denied_after_unlock = unwrap_identity(&sidecar, &binding, Interaction::Disallowed).unwrap_err();
        assert!(matches!(denied_after_unlock, SecureEnclaveError::Unavailable(_)));
    }
}
