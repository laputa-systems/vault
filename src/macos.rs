use age::secrecy::{ExposeSecret, SecretString};
use crate::secure_enclave::{
    Interaction, SecureEnclaveError, unwrap_identity, validate_sidecar, wrap_identity,
};
use crate::store::{
    MAX_IDENTITY_CIPHERTEXT, MAX_RECIPIENT_BYTES, MAX_SECRET_CIPHERTEXT, MAX_SECRET_BYTES,
    decrypt_identity, decrypt_secret, encrypt_identity, encrypt_secret, parse_recipient,
    validate_identity_recipient,
};
use rustix::fs::{
    AtFlags, CWD, Dir, FileType, FlockOperation, Mode, OFlags, RenameFlags, fchmod, flock,
    fsync, fstat, mkdirat, openat, renameat_with, statat, unlinkat,
};
use rustix::io::Errno;
use std::ffi::{CString, OsString};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use zeroize::{Zeroize, Zeroizing};
use rustix::process::geteuid;

const STORE_NAME: &str = "vault";
const SECRETS_NAME: &str = "secrets";
const LOCK_NAME: &str = ".vault.lock";
const IDENTITY_NAME: &str = "identity.age";
const SECURE_ENCLAVE_NAME: &str = "identity.se";
const RECIPIENT_NAME: &str = "recipient";
const INIT_PREFIX: &str = ".vault-init-";
const TEMP_PREFIX: &str = ".tmp-";
const PRIVATE_FILE_MODE: u32 = 0o600;
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const MAX_NAME_BYTES: usize = 125;
const MAX_SECURE_ENCLAVE_SIDECAR: usize = 1 << 20;
const IDENTITY_BINDING_PREFIX: &[u8] = b"dev.joshuarli.vault\0age-x25519\0";

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

pub(crate) enum RecoveryPrompt {
    Create,
    Confirm,
    Unlock,
}

impl RecoveryPrompt {
    pub(crate) fn prompt(&self) -> &'static str {
        match self {
            Self::Create => "Create recovery passphrase: ",
            Self::Confirm => "Confirm recovery passphrase: ",
            Self::Unlock => "Recovery passphrase: ",
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
    prompt: impl FnMut(RecoveryPrompt) -> Result<SecretString, String>,
) -> Result<(), String> {
    let data_home = data_home()?;
    set_secret_at(&data_home, name, value, prompt)
}

fn set_secret_at(
    data_home: &Path,
    name: &str,
    value: &[u8],
    mut prompt: impl FnMut(RecoveryPrompt) -> Result<SecretString, String>,
) -> Result<(), String> {
    validate_store_name(name)?;
    if value.len() > MAX_SECRET_BYTES {
        return Err(format!(
            "vault: {name}: secret exceeds the {} MiB limit",
            MAX_SECRET_BYTES / (1024 * 1024)
        ));
    }
    let data = open_data_home(data_home, true)?.expect("data home was created");
    let lock = open_lock_file(&data)?;
    flock(&lock, FlockOperation::LockExclusive)
        .map_err(|source| io_error("lock macOS store", source))?;

    if let Some(store) = open_store(&data)? {
        let recipient = read_recipient(&store.root)?;
        validate_recovery_identity(&store.root)?;
        read_secure_enclave_sidecar(&store.root)?;
        let ciphertext = encrypt_secret(&recipient, value)
            .map_err(|_| format!("vault: {name}: encryption failed"))?;
        if ciphertext.len() > MAX_SECRET_CIPHERTEXT {
            return Err(format!("vault: {name}: encrypted secret exceeds the storage limit"));
        }
        atomic_write(&store.secrets, &secret_filename(name)?, &ciphertext)
    } else {
        let passphrase = prompt(RecoveryPrompt::Create)?;
        if passphrase.expose_secret().is_empty() {
            return Err("vault: recovery passphrase must not be empty".to_owned());
        }
        let confirmation = prompt(RecoveryPrompt::Confirm)?;
        if passphrase.expose_secret() != confirmation.expose_secret() {
            return Err("vault: recovery passphrases do not match".to_owned());
        }
        initialize_store(&data, name, value, passphrase)
    }
}

pub(crate) fn get_secret(name: &str) -> Result<String, String> {
    let mut values = get_secrets(&[name])?;
    Ok(values.remove(0))
}

pub(crate) fn get_secrets(names: &[&str]) -> Result<Vec<String>, String> {
    if names.is_empty() {
        return Ok(Vec::new());
    }
    for name in names {
        validate_name(name)?;
    }
    let data_home = data_home()?;
    let data = open_data_home(&data_home, false)?
        .ok_or_else(|| "vault: Secure Enclave store is not initialized".to_owned())?;
    let lock = open_lock_file(&data)?;
    flock(&lock, FlockOperation::LockShared)
        .map_err(|source| io_error("lock macOS store", source))?;
    let store = open_store(&data)?
        .ok_or_else(|| "vault: Secure Enclave store is not initialized".to_owned())?;

    Ok(release_values(read_age_values(&store, names)?))
}

fn read_age_values(
    store: &Store,
    names: &[&str],
) -> Result<Vec<Zeroizing<String>>, String> {
    let recipient = read_recipient(&store.root)?;
    let sidecar = read_secure_enclave_sidecar(&store.root)?;
    let wrapped_identity = unwrap_identity(
        &sidecar,
        &identity_binding(&recipient),
        Interaction::MayPrompt,
    )
    .map_err(format_secure_enclave_error)?;
    let identity = identity_from_bytes(wrapped_identity)?;
    validate_identity_recipient(&identity, &recipient)?;

    let mut values = Vec::with_capacity(names.len());
    for name in names {
        let filename = secret_filename(name)?;
        let ciphertext = read_private_file(&store.secrets, &filename, MAX_SECRET_CIPHERTEXT)?;
        let value = decrypt_secret(&identity, &ciphertext).map_err(|error| {
            format!("vault: {name}: encrypted secret is damaged or cannot be decrypted: {error}")
        })?;
        values.push(value);
    }
    Ok(values)
}

fn release_values(values: Vec<Zeroizing<String>>) -> Vec<String> {
    values
        .into_iter()
        .map(|mut value| std::mem::take(&mut *value))
        .collect()
}

pub(crate) fn delete_secret(name: &str) -> Result<(), String> {
    validate_store_name(name)?;
    let data_home = data_home()?;
    let data = open_data_home(&data_home, false)?
        .ok_or_else(|| format!("vault: {name}: not found"))?;
    let lock = open_lock_file(&data)?;
    flock(&lock, FlockOperation::LockExclusive)
        .map_err(|source| io_error("lock macOS store", source))?;
    let store = open_store(&data)?.ok_or_else(|| format!("vault: {name}: not found"))?;
    unlinkat(&store.secrets, secret_filename(name)?.as_str(), AtFlags::empty())
        .map_err(|source| {
            if source == Errno::NOENT {
                format!("vault: {name}: not found")
            } else {
                io_error(&format!("remove secret {name}"), source)
            }
        })?;
    fsync(&store.secrets).map_err(|source| io_error("sync secrets directory", source))
}

pub(crate) fn list_secrets() -> Result<Vec<String>, String> {
    let data_home = data_home()?;
    let Some(data) = open_data_home(&data_home, false)? else {
        return Ok(Vec::new());
    };
    let Some(store) = open_store(&data)? else {
        return Ok(Vec::new());
    };
    managed_names(&store.secrets, false)
}

pub(crate) fn purge_secrets() -> Result<usize, String> {
    let data_home = data_home()?;
    let mut removed_from_store = 0;
    if let Some(data) = open_data_home(&data_home, false)? {
        let lock = open_lock_file(&data)?;
        flock(&lock, FlockOperation::LockExclusive)
            .map_err(|source| io_error("lock macOS store", source))?;
        if let Some(store) = open_store(&data)? {
            let names = managed_names(&store.secrets, true)?;
            for name in names {
                match unlinkat(&store.secrets, secret_filename(&name)?.as_str(), AtFlags::empty()) {
                    Ok(()) => removed_from_store += 1,
                    Err(Errno::NOENT) => {}
                    Err(source) => return Err(io_error(&format!("remove secret {name}"), source)),
                }
            }
            fsync(&store.secrets).map_err(|source| io_error("sync secrets directory", source))?;
        }
    }
    Ok(removed_from_store)
}

pub(crate) fn recover(
    prompt: impl FnOnce(RecoveryPrompt) -> Result<SecretString, String>,
) -> Result<(), String> {
    let data_home = data_home()?;
    recover_at(&data_home, prompt)
}

fn recover_at(
    data_home: &Path,
    prompt: impl FnOnce(RecoveryPrompt) -> Result<SecretString, String>,
) -> Result<(), String> {
    let data = open_data_home(data_home, false)?
        .ok_or_else(|| "vault: Secure Enclave store is not initialized".to_owned())?;
    let lock = open_lock_file(&data)?;
    flock(&lock, FlockOperation::LockExclusive)
        .map_err(|source| io_error("lock macOS store", source))?;
    let store = open_store(&data)?
        .ok_or_else(|| "vault: Secure Enclave store is not initialized".to_owned())?;
    let encrypted_identity = read_private_file(
        &store.root,
        IDENTITY_NAME,
        MAX_IDENTITY_CIPHERTEXT,
    )?;
    let recipient = read_recipient(&store.root)?;
    let identity = decrypt_identity(&encrypted_identity, prompt(RecoveryPrompt::Unlock)?)?;
    validate_identity_recipient(&identity, &recipient)?;
    let private_key = identity.to_string();
    let identity_bytes = Zeroizing::new(private_key.expose_secret().as_bytes().to_vec());
    let sidecar = wrap_identity(&identity_bytes, &identity_binding(&recipient))
        .map_err(format_secure_enclave_error)?;
    validate_sidecar(&sidecar).map_err(format_secure_enclave_error)?;
    atomic_write(&store.root, SECURE_ENCLAVE_NAME, &sidecar)
}

fn initialize_store(
    data: &File,
    name: &str,
    value: &[u8],
    passphrase: SecretString,
) -> Result<(), String> {
    let (stage_name, stage) = create_staging_directory(data)?;
    let result = populate_staging_directory(&stage, &[(name.to_owned(), Zeroizing::new(
        String::from_utf8(value.to_vec()).map_err(|error| {
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            "vault: secret is not valid UTF-8".to_owned()
        })?,
    ))], passphrase);
    publish_staging_directory(data, &stage_name, stage, result)
}

fn populate_staging_directory(
    stage: &File,
    source: &[(String, Zeroizing<String>)],
    passphrase: SecretString,
) -> Result<(), String> {
    let identity = age::x25519::Identity::generate();
    let private_key = identity.to_string();
    let private_key_bytes = Zeroizing::new(private_key.expose_secret().as_bytes().to_vec());
    let mut recovery_bytes = Zeroizing::new(private_key_bytes.to_vec());
    recovery_bytes.push(b'\n');
    let encrypted_identity = encrypt_identity(recovery_bytes.as_slice(), passphrase)?;
    atomic_write(stage, IDENTITY_NAME, &encrypted_identity)?;

    let recipient = identity.to_public();
    let recipient_text = format!("{recipient}\n");
    atomic_write(stage, RECIPIENT_NAME, recipient_text.as_bytes())?;
    let sidecar = wrap_identity(&private_key_bytes, &identity_binding(&recipient))
        .map_err(format_secure_enclave_error)?;
    atomic_write(stage, SECURE_ENCLAVE_NAME, &sidecar)?;

    mkdirat(stage, SECRETS_NAME, mode(PRIVATE_DIRECTORY_MODE))
        .map_err(|source| io_error("create secrets directory", source))?;
    let secrets = open_directory_at(stage, SECRETS_NAME, "secrets directory")?;
    set_directory_mode(&secrets, PRIVATE_DIRECTORY_MODE, "secrets directory")?;
    for (name, value) in source {
        let ciphertext = encrypt_secret(&recipient, value.as_bytes())
            .map_err(|_| format!("vault: {name}: encryption failed"))?;
        let verified = decrypt_secret(&identity, &ciphertext)
            .map_err(|error| format!("vault: {name}: encrypted-store verification failed: {error}"))?;
        if verified.as_str() != value.as_str() {
            return Err(format!("vault: encrypted-store verification failed for {name}"));
        }
        atomic_write(&secrets, &secret_filename(name)?, &ciphertext)?;
    }
    fsync(&secrets).map_err(|source| io_error("sync secrets directory", source))?;
    fsync(stage).map_err(|source| io_error("sync initialized store", source))
}

fn publish_staging_directory(
    data: &File,
    stage_name: &str,
    stage: File,
    result: Result<(), String>,
) -> Result<(), String> {
    if let Err(primary) = result {
        drop(stage);
        return Err(cleanup_failure(data, stage_name, primary));
    }
    if let Err(source) = renameat_with(data, stage_name, data, STORE_NAME, RenameFlags::NOREPLACE) {
        drop(stage);
        return Err(cleanup_failure(
            data,
            stage_name,
            io_error("publish initialized macOS store", source),
        ));
    }
    fsync(data).map_err(|source| io_error("sync application support directory", source))?;
    drop(stage);
    Ok(())
}

fn data_home() -> Result<PathBuf, String> {
    data_home_from(
        std::env::var_os("XDG_DATA_HOME"),
        std::env::var_os("HOME"),
    )
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
    Ok(home.join("Library/Application Support"))
}

fn open_data_home(path: &Path, create: bool) -> Result<Option<File>, String> {
    if !path.is_absolute() {
        return Err("vault: application support directory must be absolute".to_owned());
    }
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => components.push(name),
            Component::ParentDir | Component::Prefix(_) => {
                return Err("vault: application support path contains an unsafe component".to_owned());
            }
        }
    }
    let Some((last, parents)) = components.split_last() else {
        return Err("vault: application support directory cannot be the filesystem root".to_owned());
    };
    let flags = OFlags::RDONLY
        | OFlags::DIRECTORY
        | OFlags::NOFOLLOW
        | OFlags::NONBLOCK
        | OFlags::CLOEXEC;
    let root = openat(CWD, "/", flags, Mode::empty())
        .map_err(|source| io_error("open filesystem root", source))?;
    let mut dir = File::from(root);
    ensure_trusted_parent(&dir, "filesystem root")?;

    for (index, component) in parents
        .iter()
        .copied()
        .chain(std::iter::once(*last))
        .enumerate()
    {
        let next = match openat(&dir, component, flags, Mode::empty()) {
            Ok(fd) => fd,
            Err(Errno::NOENT) if create => {
                match mkdirat(&dir, component, mode(0o755)) {
                    Ok(()) | Err(Errno::EXIST) => {}
                    Err(source) => return Err(io_error("create application support directory", source)),
                }
                openat(&dir, component, flags, Mode::empty())
                    .map_err(|source| io_error("open application support directory", source))?
            }
            Err(Errno::NOENT) => return Ok(None),
            Err(source) => return Err(io_error("open application support directory", source)),
        };
        let next = File::from(next);
        let metadata = fstat(&next)
            .map_err(|source| io_error("inspect application support directory", source))?;
        if !FileType::from_raw_mode(metadata.st_mode).is_dir() {
            return Err("vault: application support path is not a directory".to_owned());
        }
        if index + 1 == components.len() {
            ensure_owned_data_home(&metadata)?;
        } else {
            ensure_trusted_directory(&metadata, "application support parent")?;
        }
        dir = next;
    }
    Ok(Some(dir))
}

fn ensure_trusted_parent(dir: &File, label: &str) -> Result<(), String> {
    let metadata = fstat(dir).map_err(|source| io_error(&format!("inspect {label}"), source))?;
    ensure_trusted_directory(&metadata, label)
}

fn ensure_trusted_directory(metadata: &rustix::fs::Stat, label: &str) -> Result<(), String> {
    let owner = geteuid().as_raw();
    let mode = u32::from(metadata.st_mode & 0o7777);
    if metadata.st_uid != 0 && metadata.st_uid != owner {
        return Err(format!("vault: {label} has an unexpected owner"));
    }
    if mode & 0o022 != 0 && !(metadata.st_uid == 0 && mode & 0o1000 != 0) {
        return Err(format!("vault: {label} is writable by other users"));
    }
    Ok(())
}

fn ensure_owned_data_home(metadata: &rustix::fs::Stat) -> Result<(), String> {
    if metadata.st_uid != geteuid().as_raw() {
        return Err("vault: application support directory is not owned by the current user".to_owned());
    }
    if u32::from(metadata.st_mode & 0o0022) != 0 {
        return Err("vault: application support directory is writable by other users".to_owned());
    }
    Ok(())
}

fn open_lock_file(data: &File) -> Result<File, String> {
    let fd = openat(
        data,
        LOCK_NAME,
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        mode(PRIVATE_FILE_MODE),
    )
    .map_err(|source| io_error("open macOS store lock", source))?;
    let file = File::from(fd);
    ensure_regular_file(&file, "macOS store lock")?;
    set_file_mode(&file, PRIVATE_FILE_MODE, "macOS store lock")?;
    Ok(file)
}

fn open_store(data: &File) -> Result<Option<Store>, String> {
    let stat = match statat(data, STORE_NAME, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(Errno::NOENT) => return Ok(None),
        Err(source) => return Err(io_error("inspect macOS store directory", source)),
    };
    if !FileType::from_raw_mode(stat.st_mode).is_dir() {
        return Err("vault: macOS store path is not a directory".to_owned());
    }
    let root = open_directory_at(data, STORE_NAME, "macOS store directory")?;
    set_directory_mode(&root, PRIVATE_DIRECTORY_MODE, "macOS store directory")?;
    let secrets = open_directory_at(&root, SECRETS_NAME, "secrets directory")
        .map_err(|error| format!("vault: macOS store is incomplete: {error}"))?;
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
    if metadata.st_uid != geteuid().as_raw() {
        return Err(format!("vault: {label} is not owned by the current user"));
    }
    Ok(dir)
}

fn set_directory_mode(dir: &File, expected: u32, label: &str) -> Result<(), String> {
    let before = fstat(dir).map_err(|source| io_error(&format!("inspect {label}"), source))?;
    if !FileType::from_raw_mode(before.st_mode).is_dir() || before.st_uid != geteuid().as_raw() {
        return Err(format!("vault: {label} is not an owned directory"));
    }
    fchmod(dir, mode(expected)).map_err(|source| io_error(&format!("set permissions on {label}"), source))?;
    let metadata = fstat(dir).map_err(|source| io_error(&format!("inspect {label}"), source))?;
    if u32::from(metadata.st_mode & 0o7777) != expected {
        return Err(format!("vault: {label} permissions must be {expected:04o}"));
    }
    Ok(())
}

fn ensure_regular_file(file: &File, label: &str) -> Result<(), String> {
    let metadata = fstat(file).map_err(|source| io_error(&format!("inspect {label}"), source))?;
    if !FileType::from_raw_mode(metadata.st_mode).is_file() {
        return Err(format!("vault: {label} is not a regular file"));
    }
    if metadata.st_uid != geteuid().as_raw() {
        return Err(format!("vault: {label} is not owned by the current user"));
    }
    if metadata.st_nlink != 1 {
        return Err(format!("vault: {label} has an unexpected hard link"));
    }
    Ok(())
}

fn set_file_mode(file: &File, expected: u32, label: &str) -> Result<(), String> {
    ensure_regular_file(file, label)?;
    fchmod(file, mode(expected)).map_err(|source| io_error(&format!("set permissions on {label}"), source))?;
    let metadata = fstat(file).map_err(|source| io_error(&format!("inspect {label}"), source))?;
    if u32::from(metadata.st_mode & 0o7777) != expected {
        return Err(format!("vault: {label} permissions must be {expected:04o}"));
    }
    Ok(())
}

fn read_recipient(root: &File) -> Result<age::x25519::Recipient, String> {
    let bytes = read_private_file(root, RECIPIENT_NAME, MAX_RECIPIENT_BYTES)
        .map_err(|error| format!("vault: cannot read public recipient: {error}"))?;
    parse_recipient(&bytes)
}

fn read_secure_enclave_sidecar(root: &File) -> Result<Vec<u8>, String> {
    let sidecar = read_private_file(root, SECURE_ENCLAVE_NAME, MAX_SECURE_ENCLAVE_SIDECAR)
        .map_err(|error| format!("vault: cannot read Secure Enclave identity: {error}"))?;
    validate_sidecar(&sidecar).map_err(format_secure_enclave_error)?;
    Ok(sidecar)
}

fn validate_recovery_identity(root: &File) -> Result<(), String> {
    let encrypted = read_private_file(root, IDENTITY_NAME, MAX_IDENTITY_CIPHERTEXT)
        .map_err(|error| format!("vault: cannot read recovery identity: {error}"))?;
    crate::store::validate_encrypted_identity(&encrypted)
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

fn identity_binding(recipient: &age::x25519::Recipient) -> Vec<u8> {
    let recipient = recipient.to_string();
    let mut binding = Vec::with_capacity(IDENTITY_BINDING_PREFIX.len() + recipient.len());
    binding.extend_from_slice(IDENTITY_BINDING_PREFIX);
    binding.extend_from_slice(recipient.as_bytes());
    binding
}

fn identity_from_bytes(mut bytes: Zeroizing<Vec<u8>>) -> Result<age::x25519::Identity, String> {
    let text = String::from_utf8(std::mem::take(&mut *bytes))
        .map_err(|error| {
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            "vault: Secure Enclave returned an invalid age identity".to_owned()
        })?;
    let secret = SecretString::from(text);
    if secret.expose_secret().contains('\n') || secret.expose_secret().contains('\r') {
        return Err("vault: Secure Enclave returned an invalid age identity".to_owned());
    }
    age::x25519::Identity::from_str(secret.expose_secret())
        .map_err(|_| "vault: Secure Enclave returned an invalid age identity".to_owned())
}

fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("vault: empty name not allowed".to_owned());
    }
    if name.contains('\0') {
        return Err("vault: secret name contains a null character".to_owned());
    }
    Ok(())
}

fn validate_store_name(name: &str) -> Result<(), String> {
    validate_name(name)?;
    if name.len() > MAX_NAME_BYTES {
        return Err(format!("vault: secret name exceeds {MAX_NAME_BYTES} UTF-8 bytes"));
    }
    Ok(())
}

fn secret_filename(name: &str) -> Result<String, String> {
    validate_store_name(name)?;
    let mut filename = String::with_capacity(name.len() * 2 + 4);
    for byte in name.as_bytes() {
        use std::fmt::Write as _;
        write!(&mut filename, "{byte:02x}").expect("writing to a string cannot fail");
    }
    filename.push_str(".age");
    Ok(filename)
}

fn decode_secret_filename(filename: &str) -> Option<String> {
    let stem = filename.strip_suffix(".age")?;
    if stem.is_empty() || stem.len() % 2 != 0 || stem.len() > MAX_NAME_BYTES * 2 {
        return None;
    }
    let mut bytes = Vec::with_capacity(stem.len() / 2);
    for pair in stem.as_bytes().as_chunks::<2>().0 {
        let high = hex_digit(pair[0])?;
        let low = hex_digit(pair[1])?;
        bytes.push((high << 4) | low);
    }
    let name = String::from_utf8(bytes).ok()?;
    if validate_store_name(&name).is_err() || secret_filename(&name).ok()?.as_str() != filename {
        return None;
    }
    Some(name)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn format_secure_enclave_error(error: SecureEnclaveError) -> String {
    format!("vault: {error}")
}

fn create_staging_directory(data: &File) -> Result<(String, File), String> {
    for _ in 0..32 {
        let name = next_temp_name(INIT_PREFIX);
        match mkdirat(data, name.as_str(), mode(PRIVATE_DIRECTORY_MODE)) {
            Ok(()) => {
                let dir = match open_directory_at(data, &name, "initialization directory") {
                    Ok(dir) => dir,
                    Err(primary) => return Err(cleanup_failure(data, &name, primary)),
                };
                if let Err(primary) = set_directory_mode(&dir, PRIVATE_DIRECTORY_MODE, "initialization directory") {
                    drop(dir);
                    return Err(cleanup_failure(data, &name, primary));
                }
                return Ok((name, dir));
            }
            Err(Errno::EXIST) => continue,
            Err(source) => return Err(io_error("create initialization directory", source)),
        }
    }
    Err("vault: could not allocate an initialization directory".to_owned())
}

fn remove_staging_directory(data: &File, name: &str) -> Result<(), String> {
    let stage = open_directory_at(data, name, "staged initialization directory")?;
    let secrets_stat = match statat(&stage, SECRETS_NAME, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => Some(stat),
        Err(Errno::NOENT) => None,
        Err(source) => return Err(io_error("inspect staged secrets directory", source)),
    };
    if let Some(stat) = secrets_stat {
        if !FileType::from_raw_mode(stat.st_mode).is_dir() {
            return Err("vault: staged secrets path is not a directory".to_owned());
        }
        let secrets = open_directory_at(&stage, SECRETS_NAME, "staged secrets directory")?;
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
    for name in directory_names(dir)? {
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

fn atomic_write(dir: &File, destination: &str, contents: &[u8]) -> Result<(), String> {
    validate_filename(destination)?;
    match statat(dir, destination, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) if !FileType::from_raw_mode(stat.st_mode).is_file() => {
            return Err(format!("vault: {destination} is not a regular file"));
        }
        Ok(stat) if stat.st_nlink != 1 => {
            return Err(format!("vault: {destination} has an unexpected hard link"));
        }
        Ok(stat) if stat.st_uid != geteuid().as_raw() => {
            return Err(format!("vault: {destination} is not owned by the current user"));
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
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
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
        Ok(()) | Err(Errno::NOENT) => primary,
        Err(cleanup) => format!("{primary}; temporary file cleanup failed: {cleanup}"),
    }
}

fn managed_names(dir: &File, include_symlinks: bool) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    for entry in directory_names(dir)? {
        let Ok(filename) = entry.to_str() else {
            continue;
        };
        let Some(name) = decode_secret_filename(filename) else {
            continue;
        };
        let stat = match statat(dir, &entry, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(Errno::NOENT) => continue,
            Err(source) => return Err(io_error("inspect secrets directory entry", source)),
        };
        let kind = FileType::from_raw_mode(stat.st_mode);
        if kind.is_file() || (include_symlinks && kind.is_symlink()) {
            names.push(name);
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

fn cleanup_failure(data: &File, name: &str, primary: String) -> String {
    match remove_staging_directory(data, name) {
        Ok(()) => primary,
        Err(cleanup) => format!("{primary}; initialization cleanup failed: {cleanup}"),
    }
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
    use super::{
        MAX_NAME_BYTES, SECURE_ENCLAVE_NAME, STORE_NAME, cleanup_failure,
        create_staging_directory, data_home_from, decode_secret_filename, initialize_store,
        open_data_home, open_store, read_age_values, recover_at,
        secret_filename, set_secret_at, validate_store_name,
        PRIVATE_DIRECTORY_MODE, validate_recovery_identity,
    };
    use age::secrecy::SecretString;
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let path = std::env::current_dir()
                .unwrap()
                .join(".work/tmp")
                .join(format!(
                    "vault-macos-test-{}-{}",
                    std::process::id(),
                    NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed)
                ));
            fs::create_dir_all(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE)).unwrap();
            Self(path)
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            if let Err(error) = fs::remove_dir_all(&self.0) {
                let message = format!("failed to remove test store {}: {error}", self.0.display());
                if std::thread::panicking() {
                    eprintln!("{message}");
                } else {
                    panic!("{message}");
                }
            }
        }
    }

    #[test]
    fn application_support_path_uses_xdg_or_macos_default() {
        assert_eq!(
            data_home_from(Some(OsString::from("/custom/data")), Some(OsString::from("/home/user")))
                .unwrap(),
            std::path::PathBuf::from("/custom/data")
        );
        assert_eq!(
            data_home_from(Some(OsString::from("relative")), Some(OsString::from("/home/user")))
                .unwrap(),
            std::path::PathBuf::from("/home/user/Library/Application Support")
        );
    }

    #[test]
    fn secret_name_filename_encoding_is_canonical_and_path_safe() {
        for name in ["TOKEN", "one.two", "slash/name", "é" ] {
            let filename = secret_filename(name).unwrap();
            assert_eq!(decode_secret_filename(&filename).as_deref(), Some(name));
            assert!(!filename.contains('/'));
        }
        assert!(validate_store_name(&"x".repeat(MAX_NAME_BYTES + 1)).is_err());
        assert_eq!(decode_secret_filename("4142.age").as_deref(), Some("AB"));
    }

    #[test]
    fn failed_initialization_cleanup_preserves_unrelated_prefixed_directories() {
        let test_dir = TestDir::new();
        let data = open_data_home(test_dir.path(), false).unwrap().unwrap();
        let unrelated = test_dir.path().join(".vault-init-unrelated");
        fs::create_dir(&unrelated).unwrap();
        fs::write(unrelated.join("sentinel"), b"preserve").unwrap();
        let (stage_name, stage) = create_staging_directory(&data).unwrap();
        drop(stage);

        assert_eq!(cleanup_failure(&data, &stage_name, "failed operation".to_owned()), "failed operation");
        assert_eq!(fs::read(unrelated.join("sentinel")).unwrap(), b"preserve");
    }

    #[test]
    fn application_support_rejects_symlink_components_and_writable_directories() {
        let test_dir = TestDir::new();
        let target = test_dir.path().join("target");
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE)).unwrap();
        let link = test_dir.path().join("linked");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(open_data_home(&link, false).is_err());

        fs::set_permissions(test_dir.path(), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(open_data_home(test_dir.path(), false).is_err());
    }

    #[test]
    #[ignore = "requires Secure Enclave hardware and interactive device-owner authentication"]
    fn secure_enclave_store_roundtrips_age_secret_from_private_files() {
        let test_dir = TestDir::new();
        let sidecar_path = test_dir.path().join(STORE_NAME).join(SECURE_ENCLAVE_NAME);
        let data = open_data_home(test_dir.path(), true).unwrap().unwrap();
        initialize_store(
            &data,
            "DUMMY",
            b"disposable file-backed Secure Enclave value",
            SecretString::from("disposable recovery passphrase".to_owned()),
        )
        .unwrap();
        drop(data);
        let old_sidecar = fs::read(&sidecar_path).unwrap();
        assert!(recover_at(test_dir.path(), |_| {
            Ok(SecretString::from("incorrect recovery passphrase".to_owned()))
        })
        .is_err());
        assert_eq!(fs::read(&sidecar_path).unwrap(), old_sidecar);
        recover_at(test_dir.path(), |_| {
            Ok(SecretString::from("disposable recovery passphrase".to_owned()))
        })
        .unwrap();
        let new_sidecar = fs::read(&sidecar_path).unwrap();
        assert_ne!(new_sidecar, old_sidecar);
        let data = open_data_home(test_dir.path(), false).unwrap().unwrap();
        let store = open_store(&data).unwrap().unwrap();
        let values = read_age_values(&store, &["DUMMY"]).unwrap();
        assert_eq!(values[0].as_str(), "disposable file-backed Secure Enclave value");
    }

    #[test]
    fn recovery_identity_must_exist_and_have_a_valid_age_header() {
        let test_dir = TestDir::new();
        let data = open_data_home(test_dir.path(), false).unwrap().unwrap();
        assert!(validate_recovery_identity(&data).is_err());

        fs::write(test_dir.path().join("identity.age"), b"invalid").unwrap();
        assert!(validate_recovery_identity(&data).is_err());
    }

    #[test]
    fn set_refuses_to_write_when_recovery_identity_is_missing_or_malformed() {
        for recovery_identity in [None, Some(&b"invalid"[..])] {
            let test_dir = TestDir::new();
            let store = test_dir.path().join(STORE_NAME);
            let secrets = store.join("secrets");
            fs::create_dir(&store).unwrap();
            fs::create_dir(&secrets).unwrap();
            let recipient = age::x25519::Identity::generate().to_public();
            fs::write(store.join("recipient"), format!("{recipient}\n")).unwrap();
            if let Some(identity) = recovery_identity {
                fs::write(store.join("identity.age"), identity).unwrap();
            }

            let error = set_secret_at(test_dir.path(), "NEW", b"value", |_| {
                panic!("an existing store never prompts to replace its recovery identity")
            })
            .unwrap_err();
            assert!(error.contains("recovery identity") || error.contains("encrypted identity is malformed"));
            assert!(!secrets.join(secret_filename("NEW").unwrap()).exists());
        }
    }

}
