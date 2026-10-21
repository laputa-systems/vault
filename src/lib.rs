#[cfg(target_os = "macos")]
pub mod keychain;

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
compile_error!("vault supports macOS and Linux");
