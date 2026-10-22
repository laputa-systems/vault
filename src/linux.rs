use age::secrecy::{ExposeSecret, SecretString};
use age::Decryptor;
use crate::store::{
    MAX_IDENTITY_CIPHERTEXT, MAX_IDENTITY_PLAINTEXT, MAX_RECIPIENT_BYTES,
    MAX_SECRET_CIPHERTEXT, MAX_SECRET_BYTES,
    decrypt_identity, decrypt_secret, encrypt_identity, encrypt_secret, parse_recipient,
    validate_identity_recipient, validate_name,
};
use rustix::fs::{
    AtFlags, CWD, Dir, FileType, FlockOperation, Mode, OFlags, RenameFlags, fchmod, flock,
    fsync, fstat, mkdirat, openat, renameat_with, statat, unlinkat,
};
use rustix::io::Errno;
use std::ffi::{CString, OsString};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use zeroize::Zeroizing;

const STORE_NAME: &str = "vault";
const SECRETS_NAME: &str = "secrets";
const LOCK_NAME: &str = ".vault.lock";
const IDENTITY_NAME: &str = "identity.age";
const RECIPIENT_NAME: &str = "recipient";
const INIT_PREFIX: &str = ".vault-init-";
const TEMP_PREFIX: &str = ".tmp-";
const PRIVATE_FILE_MODE: u32 = 0o600;
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const IDENTITY_CACHE_TTL: Duration = Duration::from_secs(15 * 60);
const USER_SESSION_KEYRING: libc::c_int = -5;
const KEYCTL_SETPERM: libc::c_long = 5;
const KEYCTL_UNLINK: libc::c_long = 9;
const KEYCTL_SEARCH: libc::c_long = 10;
const KEYCTL_READ: libc::c_long = 11;
const KEYCTL_SET_TIMEOUT: libc::c_long = 15;
const KEY_POS_READ: libc::c_uint = 0x0200_0000;
const KEY_POS_WRITE: libc::c_uint = 0x0400_0000;
const KEY_POS_SEARCH: libc::c_uint = 0x0800_0000;
const KEY_POS_SETATTR: libc::c_uint = 0x2000_0000;
const CACHE_KEY_POSSESSOR_PERMISSIONS: libc::c_uint =
    KEY_POS_READ | KEY_POS_WRITE | KEY_POS_SEARCH | KEY_POS_SETATTR;
const CACHE_KEYRING_POSSESSOR_PERMISSIONS: libc::c_uint =
    KEY_POS_WRITE | KEY_POS_SEARCH | KEY_POS_SETATTR;

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

pub(crate) enum PassphrasePrompt {
    Create,
    Confirm,
    Unlock,
}

impl PassphrasePrompt {
    pub(crate) fn prompt(&self) -> &'static str {
        match self {
            Self::Create => "Create master passphrase: ",
            Self::Confirm => "Confirm master passphrase: ",
            Self::Unlock => "Master passphrase: ",
        }
    }
}

struct Store {
    root: File,
    secrets: File,
}

pub(crate) fn set_secret(
    name: &str,
    value: &[u8],
    mut prompt: impl FnMut(PassphrasePrompt) -> Result<SecretString, String>,
) -> Result<(), String> {
    let data_home = data_home()?;
    set_secret_at(&data_home, name, value, &mut prompt)
}

pub(crate) fn get_secret(
    name: &str,
    prompt: impl FnOnce(PassphrasePrompt) -> Result<SecretString, String>,
    cache_warning: impl FnMut(&str) -> io::Result<()>,
) -> Result<String, String> {
    let mut values = get_secrets(&[name], prompt, cache_warning)?;
    Ok(values.remove(0))
}

pub(crate) fn get_secrets(
    names: &[&str],
    prompt: impl FnOnce(PassphrasePrompt) -> Result<SecretString, String>,
    cache_warning: impl FnMut(&str) -> io::Result<()>,
) -> Result<Vec<String>, String> {
    if names.is_empty() {
        return Ok(Vec::new());
    }
    for name in names {
        validate_name(name)?;
    }
    let data_home = data_home()?;
    get_secrets_at_with_warning(&data_home, names, prompt, cache_warning)
}

pub(crate) fn delete_secret(name: &str) -> Result<(), String> {
    validate_name(name)?;
    let data_home = data_home()?;
    delete_secret_at(&data_home, name)
}

pub(crate) fn list_secrets() -> Result<Vec<String>, String> {
    let data_home = data_home()?;
    list_secrets_at(&data_home)
}

pub(crate) fn purge_secrets() -> Result<usize, String> {
    let data_home = data_home()?;
    purge_secrets_at(&data_home)
}

fn data_home() -> Result<PathBuf, String> {
    data_home_from(std::env::var_os("XDG_DATA_HOME"), std::env::var_os("HOME"))
}

fn data_home_from(xdg_data_home: Option<OsString>, home: Option<OsString>) -> Result<PathBuf, String> {
    if let Some(path) = xdg_data_home.filter(|path| !path.is_empty()) {
        let path = PathBuf::from(path);
        if path.is_absolute() {
            return Ok(path);
        }
    }
    let home = home.ok_or_else(|| "vault: HOME is not set and XDG_DATA_HOME is not absolute".to_owned())?;
    let home = PathBuf::from(home);
    if !home.is_absolute() {
        return Err("vault: HOME must be an absolute path".to_owned());
    }
    Ok(home.join(".local/share"))
}

fn set_secret_at(
    data_home: &Path,
    name: &str,
    value: &[u8],
    prompt: &mut impl FnMut(PassphrasePrompt) -> Result<SecretString, String>,
) -> Result<(), String> {
    validate_name(name)?;
    if value.len() > MAX_SECRET_BYTES {
        return Err(format!("vault: {name}: secret exceeds the {} MiB limit", MAX_SECRET_BYTES / (1024 * 1024)));
    }
    let data = open_data_home(data_home, true)?.expect("data home was created");
    let lock = open_lock_file(&data)?;
    flock(&lock, FlockOperation::LockExclusive)
        .map_err(|source| io_error("lock Linux store", source))?;
    cleanup_staging_directories(&data)?;

    if let Some(store) = open_store(&data)? {
        let recipient = validate_store_for_write(&store)?;
        cleanup_temporary_files(&store.secrets)?;
        let ciphertext = encrypt_secret(&recipient, value)
            .map_err(|_| format!("vault: {name}: encryption failed"))?;
        if ciphertext.len() > MAX_SECRET_CIPHERTEXT {
            return Err(format!("vault: {name}: encrypted secret exceeds the storage limit"));
        }
        return atomic_write(&store.secrets, &secret_filename(name), &ciphertext);
    }

    let passphrase = prompt(PassphrasePrompt::Create)?;
    if passphrase.expose_secret().is_empty() {
        return Err("vault: master passphrase must not be empty".to_owned());
    }
    let confirmation = prompt(PassphrasePrompt::Confirm)?;
    if passphrase.expose_secret() != confirmation.expose_secret() {
        return Err("vault: master passphrases do not match".to_owned());
    }
    initialize_store(&data, name, value, passphrase)
}

#[cfg(test)]
fn get_secrets_at(
    data_home: &Path,
    names: &[&str],
    prompt: impl FnOnce(PassphrasePrompt) -> Result<SecretString, String>,
) -> Result<Vec<String>, String> {
    get_secrets_at_with_warning(data_home, names, prompt, |_| Ok(()))
}

fn get_secrets_at_with_warning(
    data_home: &Path,
    names: &[&str],
    prompt: impl FnOnce(PassphrasePrompt) -> Result<SecretString, String>,
    mut cache_warning: impl FnMut(&str) -> io::Result<()>,
) -> Result<Vec<String>, String> {
    let data = open_data_home(data_home, false)?
        .ok_or_else(|| "vault: Linux store is not initialized; run vault set NAME".to_owned())?;
    let store = open_store(&data)?
        .ok_or_else(|| "vault: Linux store is not initialized; run vault set NAME".to_owned())?;
    let ciphertexts = names
        .iter()
        .map(|name| read_private_file(&store.secrets, &secret_filename(name), MAX_SECRET_CIPHERTEXT))
        .collect::<Result<Vec<_>, _>>()?;
    let encrypted_identity = read_private_file(&store.root, IDENTITY_NAME, MAX_IDENTITY_CIPHERTEXT)
        .map_err(|error| format!("vault: cannot read encrypted identity: {error}"))?;
    let recipient = read_recipient(&store.root)?;
    let identity = match read_cached_identity(&recipient) {
        Ok(Some(identity)) => identity,
        Ok(None) => decrypt_identity(&encrypted_identity, prompt(PassphrasePrompt::Unlock)?)?,
        Err(error) => {
            report_cache_warning(&mut cache_warning, &error)?;
            decrypt_identity(&encrypted_identity, prompt(PassphrasePrompt::Unlock)?)?
        }
    };
    validate_identity_recipient(&identity, &recipient)?;

    let mut values = Vec::with_capacity(ciphertexts.len());
    for (name, ciphertext) in names.iter().zip(ciphertexts) {
        values.push(decrypt_secret(&identity, &ciphertext).map_err(|error| {
            format!("vault: {name}: encrypted secret is damaged or cannot be decrypted: {error}")
        })?);
    }
    if let Err(error) = cache_identity(&identity, &recipient) {
        report_cache_warning(&mut cache_warning, &error)?;
    }
    Ok(values.into_iter().map(|mut value| std::mem::take(&mut *value)).collect())
}

fn delete_secret_at(data_home: &Path, name: &str) -> Result<(), String> {
    let Some(data) = open_data_home(data_home, false)? else {
        return Err(format!("vault: {name}: not found"));
    };
    let lock = open_lock_file(&data)?;
    flock(&lock, FlockOperation::LockExclusive)
        .map_err(|source| io_error("lock Linux store", source))?;
    let Some(store) = open_store(&data)? else {
        return Err(format!("vault: {name}: not found"));
    };
    let filename = secret_filename(name);
    match unlinkat(&store.secrets, filename.as_str(), AtFlags::empty()) {
        Ok(()) => fsync(&store.secrets).map_err(|source| io_error("sync secrets directory", source)),
        Err(Errno::NOENT) => Err(format!("vault: {name}: not found")),
        Err(source) => Err(io_error(&format!("remove secret {name}"), source)),
    }
}

fn list_secrets_at(data_home: &Path) -> Result<Vec<String>, String> {
    let Some(data) = open_data_home(data_home, false)? else {
        return Ok(Vec::new());
    };
    let Some(store) = open_store(&data)? else {
        return Ok(Vec::new());
    };
    managed_names(&store.secrets, false)
}

fn purge_secrets_at(data_home: &Path) -> Result<usize, String> {
    let Some(data) = open_data_home(data_home, false)? else {
        return Ok(0);
    };
    let lock = open_lock_file(&data)?;
    flock(&lock, FlockOperation::LockExclusive)
        .map_err(|source| io_error("lock Linux store", source))?;
    let Some(store) = open_store(&data)? else {
        return Ok(0);
    };
    let names = managed_names(&store.secrets, true)?;
    let mut removed = 0;
    for name in names {
        match unlinkat(&store.secrets, secret_filename(&name).as_str(), AtFlags::empty()) {
            Ok(()) => removed += 1,
            Err(Errno::NOENT) => {}
            Err(source) => return Err(io_error(&format!("remove secret {name}"), source)),
        }
    }
    fsync(&store.secrets).map_err(|source| io_error("sync secrets directory", source))?;
    Ok(removed)
}

fn open_data_home(path: &Path, create: bool) -> Result<Option<File>, String> {
    if !path.is_absolute() {
        return Err("vault: XDG data directory must be absolute".to_owned());
    }
    if create {
        fs::create_dir_all(path).map_err(|source| io_error("create XDG data directory", source))?;
    }
    let dir = match openat(
        CWD,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => File::from(fd),
        Err(Errno::NOENT) if !create => return Ok(None),
        Err(source) => return Err(io_error("open XDG data directory", source)),
    };
    let metadata = fstat(&dir).map_err(|source| io_error("inspect XDG data directory", source))?;
    if !FileType::from_raw_mode(metadata.st_mode).is_dir() {
        return Err("vault: XDG data path is not a directory".to_owned());
    }
    Ok(Some(dir))
}

fn open_lock_file(data: &File) -> Result<File, String> {
    let fd = openat(
        data,
        LOCK_NAME,
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        mode(PRIVATE_FILE_MODE),
    )
    .map_err(|source| io_error("open Linux store lock", source))?;
    let file = File::from(fd);
    ensure_regular_file(&file, "Linux store lock")?;
    set_file_mode(&file, PRIVATE_FILE_MODE, "Linux store lock")?;
    Ok(file)
}

fn open_store(data: &File) -> Result<Option<Store>, String> {
    let stat = match statat(data, STORE_NAME, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(Errno::NOENT) => return Ok(None),
        Err(source) => return Err(io_error("inspect Linux store directory", source)),
    };
    if !FileType::from_raw_mode(stat.st_mode).is_dir() {
        return Err("vault: Linux store path is not a directory".to_owned());
    }
    let root = open_directory_at(data, STORE_NAME, "Linux store directory")?;
    set_directory_mode(&root, PRIVATE_DIRECTORY_MODE, "Linux store directory")?;
    let secrets = open_directory_at(&root, SECRETS_NAME, "secrets directory")
        .map_err(|error| format!("vault: Linux store is incomplete: {error}"))?;
    set_directory_mode(&secrets, PRIVATE_DIRECTORY_MODE, "secrets directory")?;
    Ok(Some(Store { root, secrets }))
}

fn open_directory_at(parent: &File, name: &str, label: &str) -> Result<File, String> {
    let fd = openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| io_error(&format!("open {label}"), source))?;
    let dir = File::from(fd);
    let metadata = fstat(&dir).map_err(|source| io_error(&format!("inspect {label}"), source))?;
    if !FileType::from_raw_mode(metadata.st_mode).is_dir() {
        return Err(format!("vault: {label} is not a directory"));
    }
    Ok(dir)
}

fn set_directory_mode(dir: &File, expected: u32, label: &str) -> Result<(), String> {
    fchmod(dir, mode(expected)).map_err(|source| io_error(&format!("set permissions on {label}"), source))?;
    let metadata = fstat(dir).map_err(|source| io_error(&format!("inspect {label}"), source))?;
    if metadata.st_mode & 0o7777 != expected {
        return Err(format!("vault: {label} permissions must be {expected:04o}"));
    }
    Ok(())
}

fn ensure_regular_file(file: &File, label: &str) -> Result<(), String> {
    let metadata = fstat(file).map_err(|source| io_error(&format!("inspect {label}"), source))?;
    if !FileType::from_raw_mode(metadata.st_mode).is_file() {
        return Err(format!("vault: {label} is not a regular file"));
    }
    if metadata.st_nlink != 1 {
        return Err(format!("vault: {label} has an unexpected hard link"));
    }
    Ok(())
}

fn set_file_mode(file: &File, expected: u32, label: &str) -> Result<(), String> {
    fchmod(file, mode(expected)).map_err(|source| io_error(&format!("set permissions on {label}"), source))?;
    let metadata = fstat(file).map_err(|source| io_error(&format!("inspect {label}"), source))?;
    if metadata.st_mode & 0o7777 != expected {
        return Err(format!("vault: {label} permissions must be {expected:04o}"));
    }
    Ok(())
}

fn validate_store_for_write(store: &Store) -> Result<age::x25519::Recipient, String> {
    let identity_file = read_private_file(&store.root, IDENTITY_NAME, MAX_IDENTITY_CIPHERTEXT)
        .map_err(|error| format!("vault: Linux store is incomplete or damaged: {error}"))?;
    Decryptor::new_buffered(&identity_file[..])
        .map_err(|_| "vault: encrypted identity is malformed".to_owned())?;
    read_recipient(&store.root)
}

fn read_recipient(root: &File) -> Result<age::x25519::Recipient, String> {
    let bytes = read_private_file(root, RECIPIENT_NAME, MAX_RECIPIENT_BYTES)
        .map_err(|error| format!("vault: cannot read public recipient: {error}"))?;
    parse_recipient(&bytes)
}

fn report_cache_warning(
    cache_warning: &mut impl FnMut(&str) -> io::Result<()>,
    warning: impl std::fmt::Display,
) -> Result<(), String> {
    cache_warning(&format!("Linux identity cache unavailable: {warning}"))
        .map_err(|source| io_error("write identity cache warning", source))
}

fn read_cached_identity(
    recipient: &age::x25519::Recipient,
) -> Result<Option<age::x25519::Identity>, io::Error> {
    let Some(keyring) = identity_cache_keyring(recipient, false)? else {
        return Ok(None);
    };
    let Some(key) = search_keyring(keyring, c"user", c"identity")? else {
        return Ok(None);
    };

    let mut payload = Zeroizing::new(vec![0u8; MAX_IDENTITY_PLAINTEXT]);
    // SAFETY: The key ID is returned by KEYCTL_SEARCH and the buffer is writable for its declared length.
    let result = unsafe {
        libc::syscall(
            libc::SYS_keyctl,
            KEYCTL_READ,
            key,
            payload.as_mut_ptr(),
            payload.len(),
            0 as libc::c_long,
        )
    };
    let length = match keyring_syscall_result(result) {
        Ok(length) => usize::try_from(length)
            .map_err(|_| io::Error::other("kernel returned an invalid identity cache length"))?,
        Err(source) if cache_key_missing(&source) => return Ok(None),
        Err(source) => return Err(source),
    };
    if length > payload.len() {
        return Ok(None);
    }
    payload.truncate(length);
    let Ok(text) = std::str::from_utf8(&payload) else {
        return Ok(None);
    };
    let Ok(identity) = age::x25519::Identity::from_str(text) else {
        return Ok(None);
    };
    if identity.to_public().to_string() != recipient.to_string() {
        return Ok(None);
    }
    let canonical = identity.to_string();
    if canonical.expose_secret().as_bytes() != payload.as_slice() {
        return Ok(None);
    }
    Ok(Some(identity))
}

fn cache_identity(
    identity: &age::x25519::Identity,
    recipient: &age::x25519::Recipient,
) -> Result<(), String> {
    let keyring = identity_cache_keyring(recipient, true)
        .map_err(|source| io_error("open identity cache keyring", source))?
        .expect("cache keyring was created");
    if let Err(source) = set_cache_permissions(keyring, CACHE_KEYRING_POSSESSOR_PERMISSIONS) {
        return Err(cleanup_identity_cache_keyring(
            keyring,
            io_error("restrict identity cache keyring permissions", source),
        ));
    }
    if let Err(source) = set_identity_cache_timeout(keyring) {
        return Err(cleanup_identity_cache_keyring(
            keyring,
            io_error("set identity cache expiry", source),
        ));
    }

    let payload = identity.to_string();
    // SAFETY: The identity description is NUL-terminated and the payload slice remains live until the syscall copies it.
    let result = unsafe {
        libc::syscall(
            libc::SYS_add_key,
            c"user".as_ptr(),
            c"identity".as_ptr(),
            payload.expose_secret().as_ptr(),
            payload.expose_secret().len(),
            keyring,
        )
    };
    let key = keyring_syscall_result(result)
        .map_err(|source| io_error("cache unlocked identity in kernel", source))?;
    let key = libc::c_int::try_from(key)
        .map_err(|_| "vault: kernel returned an invalid identity cache key".to_owned())?;
    if let Err(source) = set_cache_permissions(key, CACHE_KEY_POSSESSOR_PERMISSIONS) {
        return Err(cleanup_identity_cache_key(
            key,
            keyring,
            io_error("restrict identity cache permissions", source),
        ));
    }
    Ok(())
}

fn identity_cache_description(
    recipient: &age::x25519::Recipient,
) -> Result<std::ffi::CString, io::Error> {
    std::ffi::CString::new(format!("vault:age:{}", recipient))
        .map_err(|_| io::Error::other("age recipient produced an invalid cache description"))
}

fn identity_cache_keyring(
    recipient: &age::x25519::Recipient,
    create: bool,
) -> Result<Option<libc::c_int>, io::Error> {
    let description = identity_cache_description(recipient)?;
    if let Some(keyring) = search_keyring(USER_SESSION_KEYRING, c"keyring", &description)? {
        return Ok(Some(keyring));
    }
    if !create {
        return Ok(None);
    }

    // SAFETY: The description is NUL-terminated; a keyring key requires a null payload of length zero.
    let result = unsafe {
        libc::syscall(
            libc::SYS_add_key,
            c"keyring".as_ptr(),
            description.as_ptr(),
            std::ptr::null::<libc::c_void>(),
            0usize,
            USER_SESSION_KEYRING,
        )
    };
    let keyring = keyring_syscall_result(result)?;
    libc::c_int::try_from(keyring)
        .map(Some)
        .map_err(|_| io::Error::other("kernel returned an invalid identity cache keyring"))
}

fn search_keyring(
    keyring: libc::c_int,
    key_type: &std::ffi::CStr,
    description: &std::ffi::CStr,
) -> Result<Option<libc::c_int>, io::Error> {
    // SAFETY: The type and description strings stay live for the syscall, and a zero destination prevents SEARCH from linking the result.
    let result = unsafe {
        libc::syscall(
            libc::SYS_keyctl,
            KEYCTL_SEARCH,
            keyring,
            key_type.as_ptr(),
            description.as_ptr(),
            0 as libc::c_long,
        )
    };
    let key = match keyring_syscall_result(result) {
        Ok(key) => key,
        Err(source) if cache_key_missing(&source) => return Ok(None),
        Err(source) => return Err(source),
    };
    libc::c_int::try_from(key)
        .map(Some)
        .map_err(|_| io::Error::other("kernel returned an invalid identity cache key"))
}

fn set_cache_permissions(key: libc::c_int, permissions: libc::c_uint) -> Result<(), io::Error> {
    // SAFETY: SETPERM receives scalar key and permission values; its unused arguments are zero.
    let result = unsafe {
        libc::syscall(
            libc::SYS_keyctl,
            KEYCTL_SETPERM,
            key,
            permissions,
            0 as libc::c_long,
            0 as libc::c_long,
        )
    };
    keyring_syscall_result(result).map(|_| ())
}

fn set_identity_cache_timeout(key: libc::c_int) -> Result<(), io::Error> {
    let timeout = libc::c_uint::try_from(IDENTITY_CACHE_TTL.as_secs())
        .map_err(|_| io::Error::other("identity cache timeout exceeds the kernel limit"))?;
    // SAFETY: SET_TIMEOUT receives a scalar key and bounded timeout; its unused arguments are zero.
    let result = unsafe {
        libc::syscall(
            libc::SYS_keyctl,
            KEYCTL_SET_TIMEOUT,
            key,
            timeout,
            0 as libc::c_long,
            0 as libc::c_long,
        )
    };
    keyring_syscall_result(result).map(|_| ())
}

fn cleanup_identity_cache_keyring(keyring: libc::c_int, primary: String) -> String {
    match keyring_unlink(keyring, USER_SESSION_KEYRING) {
        Ok(()) => primary,
        Err(cleanup) => format!("{primary}; identity cache cleanup failed: {cleanup}"),
    }
}

fn cleanup_identity_cache_key(
    key: libc::c_int,
    keyring: libc::c_int,
    primary: String,
) -> String {
    match keyring_unlink(key, keyring) {
        Ok(()) => primary,
        Err(cleanup) => format!("{primary}; identity cache cleanup failed: {cleanup}"),
    }
}

fn keyring_unlink(key: libc::c_int, keyring: libc::c_int) -> Result<(), io::Error> {
    // SAFETY: UNLINK receives scalar key IDs; its unused arguments are zero.
    let result = unsafe {
        libc::syscall(
            libc::SYS_keyctl,
            KEYCTL_UNLINK,
            key,
            keyring,
            0 as libc::c_long,
            0 as libc::c_long,
        )
    };
    keyring_syscall_result(result).map(|_| ())
}

#[cfg(test)]
fn remove_cached_identity(recipient: &age::x25519::Recipient) -> Result<(), io::Error> {
    let Some(keyring) = identity_cache_keyring(recipient, false)? else {
        return Ok(());
    };
    keyring_unlink(keyring, USER_SESSION_KEYRING)
}

fn keyring_syscall_result(result: libc::c_long) -> Result<libc::c_long, io::Error> {
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

fn cache_key_missing(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::ENOKEY) | Some(libc::ENOENT) | Some(libc::EKEYEXPIRED)
    )
}

fn read_private_file(dir: &File, name: &str, max_size: usize) -> Result<Vec<u8>, String> {
    let fd = openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|source| {
        if source == Errno::NOENT {
            format!("vault: {name}: not found")
        } else {
            io_error(&format!("open {name}"), source)
        }
    })?;
    let file = File::from(fd);
    ensure_regular_file(&file, name)?;
    set_file_mode(&file, PRIVATE_FILE_MODE, name)?;
    let metadata = fstat(&file).map_err(|source| io_error(&format!("inspect {name}"), source))?;
    if metadata.st_size < 0 || metadata.st_size as u64 > max_size as u64 {
        return Err(format!("vault: {name} exceeds the maximum file size"));
    }
    let mut contents = Vec::with_capacity((metadata.st_size as usize).min(max_size));
    file.take(max_size as u64 + 1)
        .read_to_end(&mut contents)
        .map_err(|source| io_error(&format!("read {name}"), source))?;
    if contents.len() > max_size {
        return Err(format!("vault: {name} exceeds the maximum file size"));
    }
    Ok(contents)
}

fn initialize_store(
    data: &File,
    name: &str,
    value: &[u8],
    passphrase: SecretString,
) -> Result<(), String> {
    let (stage_name, stage) = create_staging_directory(data)?;
    let result = populate_staging_directory(&stage, name, value, passphrase);
    if let Err(primary) = result {
        drop(stage);
        return Err(cleanup_failure(data, &stage_name, primary));
    }
    if let Err(source) = renameat_with(data, &stage_name, data, STORE_NAME, RenameFlags::NOREPLACE) {
        drop(stage);
        return Err(cleanup_failure(
            data,
            &stage_name,
            io_error("publish initialized Linux store", source),
        ));
    }
    fsync(data).map_err(|source| io_error("sync XDG data directory", source))?;
    drop(stage);
    Ok(())
}

fn populate_staging_directory(
    stage: &File,
    name: &str,
    value: &[u8],
    passphrase: SecretString,
) -> Result<(), String> {
    let identity = age::x25519::Identity::generate();
    let private_key = identity.to_string();
    let mut identity_plaintext = Zeroizing::new(private_key.expose_secret().as_bytes().to_vec());
    identity_plaintext.push(b'\n');
    let encrypted_identity = encrypt_identity(identity_plaintext.as_slice(), passphrase)?;
    atomic_write(stage, IDENTITY_NAME, &encrypted_identity)?;
    let recipient = identity.to_public();
    let recipient_text = format!("{recipient}\n");
    atomic_write(stage, RECIPIENT_NAME, recipient_text.as_bytes())?;

    mkdirat(stage, SECRETS_NAME, mode(PRIVATE_DIRECTORY_MODE))
        .map_err(|source| io_error("create secrets directory", source))?;
    let secrets = open_directory_at(stage, SECRETS_NAME, "secrets directory")?;
    set_directory_mode(&secrets, PRIVATE_DIRECTORY_MODE, "secrets directory")?;
    let ciphertext = encrypt_secret(&recipient, value)
        .map_err(|_| format!("vault: {name}: encryption failed"))?;
    atomic_write(&secrets, &secret_filename(name), &ciphertext)?;
    fsync(&secrets).map_err(|source| io_error("sync secrets directory", source))?;
    fsync(stage).map_err(|source| io_error("sync initialized store", source))
}

fn create_staging_directory(data: &File) -> Result<(String, File), String> {
    for _ in 0..32 {
        let name = next_temp_name(INIT_PREFIX);
        match mkdirat(data, name.as_str(), mode(PRIVATE_DIRECTORY_MODE)) {
            Ok(()) => {
                let result = open_directory_at(data, &name, "initialization directory")
                    .and_then(|dir| {
                        set_directory_mode(&dir, PRIVATE_DIRECTORY_MODE, "initialization directory")?;
                        Ok(dir)
                    });
                return match result {
                    Ok(dir) => Ok((name, dir)),
                    Err(primary) => Err(cleanup_failure(data, &name, primary)),
                };
            }
            Err(Errno::EXIST) => continue,
            Err(source) => return Err(io_error("create initialization directory", source)),
        }
    }
    Err("vault: could not allocate an initialization directory".to_owned())
}

fn cleanup_failure(data: &File, name: &str, primary: String) -> String {
    match remove_staging_directory(data, name) {
        Ok(()) => primary,
        Err(cleanup) => format!("{primary}; initialization cleanup failed: {cleanup}"),
    }
}

fn cleanup_staging_directories(data: &File) -> Result<(), String> {
    let names = directory_names(data)?;
    for name in names {
        if !name.to_bytes().starts_with(INIT_PREFIX.as_bytes()) {
            continue;
        }
        let stat = match statat(data, &name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(Errno::NOENT) => continue,
            Err(source) => return Err(io_error("inspect abandoned initialization", source)),
        };
        if FileType::from_raw_mode(stat.st_mode).is_dir() {
            remove_staging_directory(data, name.to_str().map_err(|_| "vault: invalid initialization path".to_owned())?)?;
        }
    }
    Ok(())
}

fn remove_staging_directory(data: &File, name: &str) -> Result<(), String> {
    match statat(data, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) if FileType::from_raw_mode(stat.st_mode).is_dir() => {}
        Ok(_) => return Err("vault: initialization path is not a directory".to_owned()),
        Err(Errno::NOENT) => return Ok(()),
        Err(source) => return Err(io_error("inspect initialization directory", source)),
    }
    let stage = open_directory_at(data, name, "abandoned initialization directory")?;
    let secrets = match statat(&stage, SECRETS_NAME, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) if FileType::from_raw_mode(stat.st_mode).is_dir() => {
            Some(open_directory_at(&stage, SECRETS_NAME, "staged secrets directory")?)
        }
        Ok(_) => {
            unlinkat(&stage, SECRETS_NAME, AtFlags::empty())
                .map_err(|source| io_error("remove staged secrets entry", source))?;
            None
        }
        Err(Errno::NOENT) => None,
        Err(source) => return Err(io_error("inspect staged secrets entry", source)),
    };
    if let Some(secrets) = secrets {
        remove_directory_entries(&secrets, "staged secret")?;
        drop(secrets);
        unlinkat(&stage, SECRETS_NAME, AtFlags::REMOVEDIR)
            .map_err(|source| io_error("remove staged secrets directory", source))?;
    }
    remove_directory_entries(&stage, "staged initialization file")?;
    drop(stage);
    unlinkat(data, name, AtFlags::REMOVEDIR)
        .map_err(|source| io_error("remove initialization directory", source))
}

fn remove_directory_entries(dir: &File, label: &str) -> Result<(), String> {
    let names = directory_names(dir)?;
    for name in names {
        let stat = statat(dir, &name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|source| io_error(&format!("inspect {label}"), source))?;
        if FileType::from_raw_mode(stat.st_mode).is_dir() {
            return Err(format!("vault: unexpected nested directory in {label}"));
        }
        unlinkat(dir, &name, AtFlags::empty())
            .map_err(|source| io_error(&format!("remove {label}"), source))?;
    }
    Ok(())
}

fn cleanup_temporary_files(secrets: &File) -> Result<(), String> {
    let names = directory_names(secrets)?;
    for name in names {
        if name.to_bytes().starts_with(TEMP_PREFIX.as_bytes()) {
            let stat = statat(secrets, &name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|source| io_error("inspect abandoned temporary file", source))?;
            if FileType::from_raw_mode(stat.st_mode).is_dir() {
                return Err("vault: unexpected directory in secrets store".to_owned());
            }
            unlinkat(secrets, &name, AtFlags::empty())
                .map_err(|source| io_error("remove abandoned temporary file", source))?;
        }
    }
    Ok(())
}

fn atomic_write(dir: &File, destination: &str, contents: &[u8]) -> Result<(), String> {
    validate_filename(destination)?;
    match statat(dir, destination, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) if !FileType::from_raw_mode(stat.st_mode).is_file() => {
            return Err(format!("vault: {destination} is not a regular file"));
        }
        Ok(stat) if stat.st_nlink != 1 => {
            return Err(format!("vault: {destination} has an unexpected hard link"));
        }
        Ok(_) | Err(Errno::NOENT) => {}
        Err(source) => return Err(io_error(&format!("inspect {destination}"), source)),
    }
    let (temporary, file) = create_temporary_file(dir)?;
    let write_result = (|| {
        ensure_regular_file(&file, &temporary)?;
        set_file_mode(&file, PRIVATE_FILE_MODE, &temporary)?;
        let mut file = &file;
        file.write_all(contents)
            .map_err(|source| io_error(&format!("write {destination}"), source))?;
        fsync(file).map_err(|source| io_error(&format!("sync {destination}"), source))
    })();
    drop(file);
    if let Err(primary) = write_result {
        return Err(cleanup_temporary_file(dir, &temporary, primary));
    }
    if let Err(source) = renameat_with(dir, temporary.as_str(), dir, destination, RenameFlags::empty()) {
        return Err(cleanup_temporary_file(
            dir,
            &temporary,
            io_error(&format!("replace {destination}"), source),
        ));
    }
    fsync(dir).map_err(|source| io_error("sync containing directory", source))
}

fn create_temporary_file(dir: &File) -> Result<(String, File), String> {
    for _ in 0..32 {
        let name = next_temp_name(TEMP_PREFIX);
        match openat(
            dir,
            name.as_str(),
            OFlags::WRONLY
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::CLOEXEC,
            mode(PRIVATE_FILE_MODE),
        ) {
            Ok(fd) => return Ok((name, File::from(fd))),
            Err(Errno::EXIST) => continue,
            Err(source) => return Err(io_error("create temporary encrypted file", source)),
        }
    }
    Err("vault: could not allocate a temporary encrypted file".to_owned())
}

fn cleanup_temporary_file(dir: &File, name: &str, primary: String) -> String {
    match unlinkat(dir, name, AtFlags::empty()) {
        Ok(()) => primary,
        Err(Errno::NOENT) => primary,
        Err(cleanup) => format!("{primary}; temporary file cleanup failed: {cleanup}"),
    }
}

fn managed_names(dir: &File, include_symlinks: bool) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    for entry in directory_names(dir)? {
        let Ok(filename) = entry.to_str() else {
            continue;
        };
        let Some(name) = filename.strip_suffix(".age") else {
            continue;
        };
        if validate_name(name).is_err() {
            continue;
        }
        let stat = match statat(dir, &entry, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(Errno::NOENT) => continue,
            Err(source) => return Err(io_error("inspect secrets directory entry", source)),
        };
        let kind = FileType::from_raw_mode(stat.st_mode);
        if kind.is_file() || (include_symlinks && kind.is_symlink()) {
            names.push(name.to_owned());
        }
    }
    names.sort_unstable();
    Ok(names)
}

fn directory_names(dir: &File) -> Result<Vec<CString>, String> {
    let mut entries = Dir::read_from(dir).map_err(|source| io_error("read directory", source))?;
    let mut names = Vec::new();
    while let Some(entry) = entries.read() {
        let entry = entry.map_err(|source| io_error("read directory entry", source))?;
        let name = entry.file_name();
        if name.to_bytes() != b"." && name.to_bytes() != b".." {
            names.push(name.to_owned());
        }
    }
    Ok(names)
}

fn validate_filename(filename: &str) -> Result<(), String> {
    if filename.is_empty() || filename.contains('/') || filename.contains('\0') || filename == "." || filename == ".." {
        return Err("vault: invalid internal file name".to_owned());
    }
    Ok(())
}

fn secret_filename(name: &str) -> String {
    format!("{name}.age")
}

fn next_temp_name(prefix: &str) -> String {
    format!("{prefix}{}-{}", std::process::id(), NEXT_TEMP.fetch_add(1, Ordering::Relaxed))
}

fn mode(bits: u32) -> Mode {
    Mode::from_raw_mode(bits as _)
}

fn io_error(operation: &str, source: impl std::fmt::Display) -> String {
    format!("vault: {operation} failed: {source}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::sync::{Arc, Barrier};
    use std::thread;

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "vault-test-{}-{}",
                std::process::id(),
                NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE)).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            if let Ok(Some(data)) = open_data_home(&self.0, false)
                && let Ok(Some(store)) = open_store(&data)
                && let Ok(recipient) = read_recipient(&store.root)
            {
                let _ = remove_cached_identity(&recipient);
            }
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn passphrase(value: &str) -> SecretString {
        SecretString::from(value.to_owned())
    }

    fn initialize(dir: &Path) {
        let mut prompted = Vec::new();
        set_secret_at(dir, "TOKEN", b"first", &mut |kind| {
            prompted.push(kind.prompt());
            Ok(passphrase("a passphrase with spaces"))
        })
        .unwrap();
        assert_eq!(prompted, ["Create master passphrase: ", "Confirm master passphrase: "]);
    }

    fn unlock(value: &'static str) -> impl FnOnce(PassphrasePrompt) -> Result<SecretString, String> {
        move |kind| {
            assert!(matches!(kind, PassphrasePrompt::Unlock));
            Ok(passphrase(value))
        }
    }

    #[test]
    fn data_home_uses_absolute_xdg_and_ignores_relative_values() {
        assert_eq!(
            data_home_from(Some(OsString::from("/data/vault")), Some(OsString::from("/home/u")))
                .unwrap(),
            PathBuf::from("/data/vault")
        );
        assert_eq!(
            data_home_from(Some(OsString::from("relative")), Some(OsString::from("/home/u")))
                .unwrap(),
            PathBuf::from("/home/u/.local/share")
        );
        assert_eq!(
            data_home_from(None, Some(OsString::from("/home/u"))).unwrap(),
            PathBuf::from("/home/u/.local/share")
        );
        assert!(data_home_from(None, Some(OsString::from("relative"))).is_err());
    }

    #[test]
    fn first_set_encrypts_standard_age_files_and_later_sets_do_not_prompt() {
        let temp = TestDir::new();
        initialize(temp.path());
        set_secret_at(temp.path(), "TOKEN", b"second", &mut |_| {
            panic!("initialized writes do not request the passphrase")
        })
        .unwrap();
        set_secret_at(temp.path(), "DATABASE_URL", b"postgres://user:secret@db", &mut |_| {
            panic!("initialized writes do not request the passphrase")
        })
        .unwrap();

        let store = open_store(&open_data_home(temp.path(), false).unwrap().unwrap())
            .unwrap()
            .unwrap();
        let token = read_private_file(&store.secrets, "TOKEN.age", MAX_SECRET_CIPHERTEXT).unwrap();
        assert!(Decryptor::new_buffered(&token[..]).is_ok());
        let recipient = read_recipient(&store.root).unwrap();
        let encrypted_identity = read_private_file(&store.root, IDENTITY_NAME, MAX_IDENTITY_CIPHERTEXT).unwrap();
        let identity = decrypt_identity(&encrypted_identity, passphrase("a passphrase with spaces")).unwrap();
        assert_eq!(age::decrypt(&identity, &token).unwrap(), b"second");
        assert!(recipient.to_string().starts_with("age1"));
        assert_eq!(get_secrets_at(temp.path(), &["TOKEN", "DATABASE_URL"], unlock("a passphrase with spaces")).unwrap(), ["second", "postgres://user:secret@db"]);
    }

    #[test]
    fn unlocked_identity_is_reused_without_another_passphrase_prompt() {
        let temp = TestDir::new();
        initialize(temp.path());
        let data = open_data_home(temp.path(), false).unwrap().unwrap();
        let store = open_store(&data).unwrap().unwrap();
        let recipient = read_recipient(&store.root).unwrap();

        assert_eq!(
            get_secrets_at(temp.path(), &["TOKEN"], unlock("a passphrase with spaces")).unwrap(),
            ["first"]
        );

        let expect_prompt = !matches!(read_cached_identity(&recipient), Ok(Some(_)));
        let mut prompted = false;
        assert_eq!(
            get_secrets_at(temp.path(), &["TOKEN"], |_| {
                prompted = true;
                Ok(passphrase("a passphrase with spaces"))
            })
            .unwrap(),
            ["first"]
        );
        assert_eq!(prompted, expect_prompt);
    }

    #[test]
    fn documented_identity_cache_timeout_matches_linux_policy() {
        let documented = include_str!("../README.md")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        let minutes = IDENTITY_CACHE_TTL.as_secs() / 60;
        assert!(
            documented.contains(&format!("expires after {minutes} minutes of inactivity")),
            "README must document the Linux identity cache timeout"
        );
    }

    #[test]
    fn empty_multiline_and_unicode_secrets_round_trip() {
        let temp = TestDir::new();
        initialize(temp.path());
        for (name, value) in [
            ("EMPTY", ""),
            ("MULTILINE", "first line\nsecond line"),
            ("UNICODE", "café 🔐"),
        ] {
            set_secret_at(temp.path(), name, value.as_bytes(), &mut |_| {
                panic!("initialized writes do not request the passphrase")
            })
            .unwrap();
        }

        assert_eq!(
            get_secrets_at(
                temp.path(),
                &["EMPTY", "MULTILINE", "UNICODE"],
                unlock("a passphrase with spaces"),
            )
            .unwrap(),
            ["", "first line\nsecond line", "café 🔐"]
        );
    }

    #[test]
    fn wrong_passphrase_fails_without_reinitializing() {
        let temp = TestDir::new();
        initialize(temp.path());
        let error = get_secrets_at(temp.path(), &["TOKEN"], unlock("wrong")).unwrap_err();
        assert!(error.contains("incorrect or the encrypted identity is damaged"));
        let mut prompted = false;
        let error = set_secret_at(temp.path(), "TOKEN", b"replacement", &mut |_| {
            prompted = true;
            Ok(passphrase("wrong"))
        });
        assert!(error.is_ok());
        assert!(!prompted);
    }

    #[test]
    fn identity_and_recipient_mismatch_fails_authenticated_reads() {
        let first = TestDir::new();
        let second = TestDir::new();
        initialize(first.path());
        initialize(second.path());
        let first_data = open_data_home(first.path(), false).unwrap().unwrap();
        let second_data = open_data_home(second.path(), false).unwrap().unwrap();
        let first_store = open_store(&first_data).unwrap().unwrap();
        let second_store = open_store(&second_data).unwrap().unwrap();
        let other_recipient = read_private_file(&second_store.root, RECIPIENT_NAME, MAX_RECIPIENT_BYTES).unwrap();
        atomic_write(&first_store.root, RECIPIENT_NAME, &other_recipient).unwrap();
        let error = get_secrets_at(first.path(), &["TOKEN"], unlock("a passphrase with spaces")).unwrap_err();
        assert!(error.contains("does not match the encrypted identity"));
    }

    #[test]
    fn corrupt_and_missing_files_fail_without_reinitializing() {
        let temp = TestDir::new();
        initialize(temp.path());
        let data = open_data_home(temp.path(), false).unwrap().unwrap();
        let store = open_store(&data).unwrap().unwrap();
        atomic_write(&store.root, IDENTITY_NAME, b"damaged identity").unwrap();
        let error = set_secret_at(temp.path(), "OTHER", b"value", &mut |_| {
            panic!("damaged stores do not prompt for a replacement identity")
        })
        .unwrap_err();
        assert!(error.contains("encrypted identity is malformed"));
        assert!(get_secrets_at(temp.path(), &["TOKEN"], unlock("a passphrase with spaces")).is_err());
    }

    #[test]
    fn missing_identity_recipient_and_secret_fail_before_prompting() {
        let temp = TestDir::new();
        initialize(temp.path());
        let data = open_data_home(temp.path(), false).unwrap().unwrap();
        let store = open_store(&data).unwrap().unwrap();
        for (directory, filename, max_size) in [
            (&store.secrets, "TOKEN.age", MAX_SECRET_CIPHERTEXT),
            (&store.root, IDENTITY_NAME, MAX_IDENTITY_CIPHERTEXT),
            (&store.root, RECIPIENT_NAME, MAX_RECIPIENT_BYTES),
        ] {
            let contents = read_private_file(directory, filename, max_size).unwrap();
            unlinkat(directory, filename, AtFlags::empty()).unwrap();
            let error = get_secrets_at(temp.path(), &["TOKEN"], |_| {
                panic!("missing store files must fail before prompting")
            })
            .unwrap_err();
            assert!(error.contains("not found"), "{filename}: {error}");
            atomic_write(directory, filename, &contents).unwrap();
        }
    }

    #[test]
    fn damaged_secret_does_not_leak_contents_and_listing_does_not_decrypt() {
        let temp = TestDir::new();
        initialize(temp.path());
        let data = open_data_home(temp.path(), false).unwrap().unwrap();
        let store = open_store(&data).unwrap().unwrap();
        atomic_write(&store.secrets, "TOKEN.age", b"not age ciphertext").unwrap();
        atomic_write(&store.secrets, "unrelated", b"secret plaintext").unwrap();
        atomic_write(&store.secrets, ".tmp-abandoned", b"ciphertext").unwrap();
        atomic_write(&store.secrets, "INVALID-NAME.age", b"ciphertext").unwrap();
        assert_eq!(list_secrets_at(temp.path()).unwrap(), ["TOKEN"]);
        let error = get_secrets_at(temp.path(), &["TOKEN"], unlock("a passphrase with spaces")).unwrap_err();
        assert!(error.contains("damaged or cannot be decrypted"));
        assert!(!error.contains("secret plaintext"));
    }

    #[test]
    fn failed_set_preserves_existing_ciphertext() {
        let temp = TestDir::new();
        initialize(temp.path());
        let secret_path = temp.path().join(STORE_NAME).join(SECRETS_NAME).join("TOKEN.age");
        let original = fs::read(&secret_path).unwrap();
        fs::hard_link(&secret_path, temp.path().join("TOKEN-hardlink")).unwrap();
        let error = set_secret_at(temp.path(), "TOKEN", b"replacement", &mut |_| {
            panic!("initialized writes do not prompt")
        })
        .unwrap_err();
        assert!(error.contains("unexpected hard link"));
        assert_eq!(fs::read(secret_path).unwrap(), original);
    }

    #[test]
    fn permissions_are_private_for_every_managed_directory_and_file() {
        let temp = TestDir::new();
        initialize(temp.path());
        let root = temp.path().join(STORE_NAME);
        let secrets = root.join(SECRETS_NAME);
        for directory in [&root, &secrets] {
            assert_eq!(fs::metadata(directory).unwrap().permissions().mode() & 0o777, PRIVATE_DIRECTORY_MODE);
        }
        for file in [
            temp.path().join(LOCK_NAME),
            root.join(IDENTITY_NAME),
            root.join(RECIPIENT_NAME),
            secrets.join("TOKEN.age"),
        ] {
            assert_eq!(fs::metadata(file).unwrap().permissions().mode() & 0o777, PRIVATE_FILE_MODE);
        }
    }

    #[test]
    fn symlink_secret_is_not_read_or_followed_and_rm_unlinks_only_the_link() {
        let temp = TestDir::new();
        initialize(temp.path());
        let outside = temp.path().join("outside");
        fs::write(&outside, b"outside data").unwrap();
        let secret = temp.path().join(STORE_NAME).join(SECRETS_NAME).join("LINK.age");
        symlink(&outside, &secret).unwrap();
        let error = get_secrets_at(temp.path(), &["LINK"], unlock("a passphrase with spaces")).unwrap_err();
        assert!(error.contains("open LINK.age"));
        delete_secret_at(temp.path(), "LINK").unwrap();
        assert_eq!(fs::read(outside).unwrap(), b"outside data");
    }

    #[test]
    fn symlink_store_directory_is_rejected() {
        let temp = TestDir::new();
        let outside = TestDir::new();
        symlink(outside.path(), temp.path().join(STORE_NAME)).unwrap();
        assert!(list_secrets_at(temp.path()).is_err());
    }

    #[test]
    fn invalid_names_are_rejected_before_filesystem_operations() {
        let temp = TestDir::new();
        for name in ["", "../TOKEN", "A/B", "A-B", "A.B", "1TOKEN", "A\0B"] {
            assert!(validate_name(name).is_err(), "{name:?}");
        }
        assert!(set_secret_at(temp.path(), "../TOKEN", b"x", &mut |_| {
            panic!("invalid names are rejected before prompting")
        })
        .is_err());
        assert!(!temp.path().join("TOKEN.age").exists());
    }

    #[test]
    fn incomplete_store_is_never_initialized_over() {
        let temp = TestDir::new();
        fs::create_dir(temp.path().join(STORE_NAME)).unwrap();
        fs::set_permissions(
            temp.path().join(STORE_NAME),
            fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE),
        )
        .unwrap();
        let error = set_secret_at(temp.path(), "TOKEN", b"x", &mut |_| {
            panic!("incomplete stores do not prompt for new identity material")
        })
        .unwrap_err();
        assert!(error.contains("incomplete"));
        assert!(!temp.path().join(STORE_NAME).join(IDENTITY_NAME).exists());
    }

    #[test]
    fn concurrent_initialization_publishes_one_consistent_store() {
        let temp = TestDir::new();
        let barrier = Arc::new(Barrier::new(2));
        let prompt_count = Arc::new(AtomicU64::new(0));
        thread::scope(|scope| {
            for name in ["FIRST", "SECOND"] {
                let barrier = Arc::clone(&barrier);
                let prompt_count = Arc::clone(&prompt_count);
                let path = temp.path().to_owned();
                scope.spawn(move || {
                    barrier.wait();
                    set_secret_at(&path, name, name.as_bytes(), &mut |kind| {
                        prompt_count.fetch_add(1, Ordering::SeqCst);
                        assert!(matches!(kind, PassphrasePrompt::Create | PassphrasePrompt::Confirm));
                        Ok(passphrase("concurrent passphrase"))
                    })
                    .unwrap();
                });
            }
        });
        assert_eq!(prompt_count.load(Ordering::SeqCst), 2);
        assert_eq!(
            get_secrets_at(temp.path(), &["FIRST", "SECOND"], unlock("concurrent passphrase")).unwrap(),
            ["FIRST", "SECOND"]
        );
    }

    #[test]
    fn purge_removes_valid_secrets_but_keeps_identity() {
        let temp = TestDir::new();
        initialize(temp.path());
        set_secret_at(temp.path(), "SECOND", b"two", &mut |_| panic!("no prompt")).unwrap();
        assert_eq!(purge_secrets_at(temp.path()).unwrap(), 2);
        assert!(list_secrets_at(temp.path()).unwrap().is_empty());
        assert!(temp.path().join(STORE_NAME).join(IDENTITY_NAME).is_file());
        assert_eq!(purge_secrets_at(temp.path()).unwrap(), 0);
    }

    #[test]
    fn mismatched_confirmation_and_empty_passphrase_do_not_publish_store() {
        let temp = TestDir::new();
        let mut count = 0;
        let error = set_secret_at(temp.path(), "TOKEN", b"x", &mut |kind| {
            count += 1;
            Ok(match kind {
                PassphrasePrompt::Create => passphrase("first"),
                PassphrasePrompt::Confirm => passphrase("second"),
                PassphrasePrompt::Unlock => unreachable!(),
            })
        })
        .unwrap_err();
        assert!(error.contains("do not match"));
        assert_eq!(count, 2);
        assert!(!temp.path().join(STORE_NAME).exists());

        let error = set_secret_at(temp.path(), "TOKEN", b"x", &mut |_| Ok(passphrase(""))).unwrap_err();
        assert!(error.contains("must not be empty"));
        assert!(!temp.path().join(STORE_NAME).exists());
    }
}
