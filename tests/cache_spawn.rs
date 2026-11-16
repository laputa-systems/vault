// Whole production modules also contain entry points and libtest imports this probe does not use.
#![allow(dead_code, unused_imports)]

#[cfg(target_os = "macos")]
#[path = "../src/store.rs"]
mod store;
#[cfg(target_os = "macos")]
#[path = "../src/secure_enclave.rs"]
mod secure_enclave;

#[cfg(target_os = "macos")]
mod macos {
    struct DaemonGuard {
        socket: PathBuf,
        pid_file: PathBuf,
    }

    impl Drop for DaemonGuard {
        fn drop(&mut self) {
            let _ = clear_identity_cache_at(&self.socket);
            let Ok(text) = std::fs::read_to_string(&self.pid_file) else { return; };
            let pid = rustix::process::Pid::from_raw(text.trim().parse().unwrap()).unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                match rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG) {
                    Ok(Some(_)) | Err(rustix::io::Errno::CHILD) => return,
                    Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
                    Ok(None) => {
                        let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
                        let _ = rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::empty());
                        return;
                    }
                    Err(error) => panic!("reap owned cache daemon: {error}"),
                }
            }
        }
    }

    pub fn exercise(root: &Path) {
        let socket = cache_socket_path(root).expect("probe socket path fits the native limit");
        let _guard = DaemonGuard { socket: socket.clone(), pid_file: root.join("daemon.pid") };
        let identity = age::x25519::Identity::generate();
        let recipient = identity.to_public();
        assert_eq!(IDENTITY_CACHE_TTL, Duration::from_secs(900));
        let directory = File::open(root.join("vault")).unwrap();
        std::fs::create_dir(root.join("vault/secrets")).unwrap();
        std::fs::set_permissions(root.join("vault/secrets"), std::fs::Permissions::from_mode(0o700)).unwrap();
        let secrets = File::open(root.join("vault/secrets")).unwrap();
        atomic_write(&directory, "recipient", format!("{recipient}\n").as_bytes()).unwrap();
        let recovery = encrypt_identity(identity.to_string().expose_secret().as_bytes(),
            SecretString::from("disposable cache probe recovery".to_owned())).unwrap();
        atomic_write(&directory, "identity.age", &recovery).unwrap();
        let mut sidecar = b"VLTSE\x01".to_vec();
        for length in [1u32, 65, 28] { sidecar.extend(length.to_be_bytes()); }
        sidecar.resize(sidecar.len() + 94, 0);
        let error = unwrap_identity(&sidecar, &identity_binding(&recipient), Interaction::Disallowed).unwrap_err();
        assert!(matches!(error, SecureEnclaveError::CorruptSidecar(_) | SecureEnclaveError::Unavailable(_)));
        atomic_write(&directory, "identity.se", &sidecar).unwrap();
        atomic_write(&secrets, "44554d4d59.age", &encrypt_secret(&recipient, b"original dummy value").unwrap()).unwrap();
        let mut warnings = Vec::new();
        cache_unlocked_identity(&socket, &recipient, &identity, &mut |warning| {
            warnings.push(warning.to_owned());
            Ok(())
        });
        assert!(warnings.is_empty(), "cache startup warnings: {warnings:?}");
        let cached = fetch_cached_identity(&socket, &recipient).unwrap().expect("spawned cache stores the identity");
        assert_eq!(cached.to_public().to_string(), recipient.to_string());
        assert_eq!(get_secret("DUMMY", |_| Ok(())).unwrap(), "original dummy value");
        assert_eq!(get_secrets(&["DUMMY", "DUMMY"], |_| Ok(())).unwrap(),
            ["original dummy value", "original dummy value"]);
        for name in ["OTHER", "THIRD"] {
            set_secret(name, b"replacement dummy value", |_| panic!("cached writes do not prompt")).unwrap();
        }
        assert_eq!(get_secret("OTHER", |_| Ok(())).unwrap(), "replacement dummy value");
        assert_eq!(list_secrets().unwrap(), ["DUMMY", "OTHER", "THIRD"]);
        delete_secret("DUMMY").unwrap();
        assert!(delete_secret("DUMMY").unwrap_err().contains("not found"));
        assert_eq!(list_secrets().unwrap(), ["OTHER", "THIRD"]);
        assert!(recover(|_| Ok(SecretString::from("incorrect recovery passphrase".to_owned()))).is_err());
        assert_eq!(std::fs::read(root.join("vault/identity.se")).unwrap(), sidecar);
        assert_eq!(purge_secrets().unwrap(), 2);
        assert!(list_secrets().unwrap().is_empty());
        assert!(matches!(clear_identity_cache_at(&socket).unwrap(), CacheClearResult::Cleared));
    }

    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/macos.rs"));
}

#[cfg(target_os = "macos")]
fn main() {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    if std::env::args().nth(1).as_deref() == Some(macos::CACHE_DAEMON_ARG) {
        let parent = rustix::process::Pid::from_raw(std::env::var("VAULT_CACHE_PROBE_PARENT")
            .unwrap().parse().unwrap());
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_millis(20));
            if rustix::process::getppid() != parent { std::process::exit(99); }
        });
        let root = std::path::PathBuf::from(std::env::var_os("XDG_DATA_HOME").unwrap());
        let mut marker = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600)
            .open(root.join("daemon.pid")).unwrap();
        use std::io::Write;
        writeln!(marker, "{}", std::process::id()).unwrap();
        macos::run_cache_daemon().unwrap();
        return;
    }
    struct Directory(std::path::PathBuf);
    impl Drop for Directory {
        fn drop(&mut self) { std::fs::remove_dir_all(&self.0).unwrap(); }
    }
    let root = std::env::temp_dir().join(format!("c{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let directory = Directory(root);
    std::fs::create_dir(directory.0.join("vault")).unwrap();
    std::fs::set_permissions(directory.0.join("vault"), std::fs::Permissions::from_mode(0o700)).unwrap();
    // SAFETY: this standalone probe has not started threads or children.
    unsafe {
        std::env::set_var("XDG_DATA_HOME", &directory.0);
        std::env::set_var("VAULT_CACHE_PROBE_PARENT", std::process::id().to_string());
    }
    macos::exercise(&directory.0);
    println!("cache spawn and identity handoff passed");
}

#[cfg(not(target_os = "macos"))]
fn main() {}
