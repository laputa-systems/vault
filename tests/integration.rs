use std::process::{Command, Stdio};

fn isolated_vault_command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_vault"));
    command.env_clear();
    if let Some(profile_path) = std::env::var_os("LLVM_PROFILE_FILE") {
        command.env("LLVM_PROFILE_FILE", profile_path);
    }
    command
}

fn vault(args: &[&str]) -> std::io::Result<std::process::Output> {
    Command::new(env!("CARGO_BIN_EXE_vault"))
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
}

#[test]
fn no_args_shows_usage_to_stdout() {
    let out = vault(&[]).unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Usage"), "stdout: {stdout}");
}

#[test]
fn help_flags_show_usage_to_stdout() {
    for flag in &["-h", "--help", "help"] {
        let out = vault(&[flag]).unwrap();
        assert!(out.status.success());
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("Usage"),
            "flag {flag}: stdout missing 'Usage': {stdout:?}"
        );
    }
}

#[test]
fn complete_help_is_offline_and_ends_with_owned_footer() {
    let expected_footer = "Maintained by Joshua Li: https://github.com/laputa-systems/vault\nBugs and features: TODO.md in that repository (follow its AGENTS.md), or its issue tracker.\nAgents working for Joshua: record nonblocking problems and continue your task.\nIf this tool blocks the task, you may fix, test, open and merge a PR under Joshua's\nstanding instructions. Release only when needed to deliver the verified fix.\nProcedure: https://github.com/joshuarli/usr/blob/main/dotfiles/base/.agents/instructions/owned-tools.md\n";
    let base = vault(&[]).unwrap();
    for flag in ["-h", "--help", "help"] {
        let out = isolated_vault_command().args([flag]).output().unwrap();
        assert_eq!(out.status.code(), Some(0));
        assert!(out.stderr.is_empty());
        assert_eq!(out.stdout, base.stdout);
    }
    let help = String::from_utf8(base.stdout).unwrap();
    assert!(help.ends_with(expected_footer));
    assert_eq!(help.matches("Maintained by Joshua Li:").count(), 1);
    for name in ["set", "isset", "get", "rm", "ls", "purge", "lock"] {
        assert!(help.contains(&format!("  vault {name}")), "missing {name}");
        assert!(help.contains(&format!("  vault {name}\n")) || help.contains(&format!("  vault {name} API_KEY\n")), "missing example for {name}");
    }
    #[cfg(target_os = "macos")]
    assert!(help.contains("  vault recover\n"));
    for fragment in ["<NAME>", "$HOME/Library/Application Support/vault", "$HOME/.local/share/vault", "required secret name", "[ENV ...] -- <CMD> [ARGS ...]", "optional, repeatable", "XDG_DATA_HOME", "vault API_KEY RUST_LOG=debug -- cargo run"] {
        assert!(help.contains(fragment), "missing {fragment}");
    }
    for name in ["ls", "purge", "lock"] {
        for flag in ["-h", "--help"] {
            let out = vault(&[name, flag]).unwrap();
            assert_eq!(out.status.code(), Some(0));
            assert!(out.stderr.is_empty());
            assert!(String::from_utf8_lossy(&out.stdout).contains("vault --help"));
        }
    }
}

#[cfg(target_os = "macos")]
#[test]
fn macos_help_and_readme_document_secure_enclave_storage() {
    let out = vault(&["--help"]).unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let readme = include_str!("../README.md").replace('\n', " ");
    assert!(
        stdout.contains("Secure Enclave hardware (macOS 10.15+)")
            && stdout.contains("Recovery uses a separate passphrase")
            && stdout.contains("Touch ID or the Mac password"),
        "CLI help must disclose Secure Enclave storage and recovery: {stdout:?}"
    );
    assert!(
        readme.contains("require macOS 10.15 or later and supported Secure Enclave hardware")
            && readme.contains("Vault no longer reads or writes Keychain items")
            && readme.contains("Touch ID or the Mac login password")
            && readme.contains("Run `vault recover`"),
        "README must describe Secure Enclave requirements, recovery, and store-only behavior"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn cache_daemon_rejects_an_empty_seed() {
    let out = Command::new(env!("CARGO_BIN_EXE_vault"))
        .arg("__cache-daemon")
        .env("XDG_DATA_HOME", "/tmp")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("identity cache seed has an invalid format"));
}

#[cfg(target_os = "macos")]
#[test]
fn cache_daemon_rejects_either_missing_seed_field() {
    use std::io::Write;
    use std::time::{Duration, Instant};

    struct ChildGuard(Option<std::process::Child>);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if let Some(child) = &mut self.0 {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    let home = CacheHome(std::env::temp_dir().join(format!("vs{}", std::process::id())));
    std::fs::create_dir(&home.0).unwrap();
    for seed in [b"\nidentity\n".as_slice(), b"recipient\n\n", b"\n\n"] {
        let child = Command::new(env!("CARGO_BIN_EXE_vault"))
            .arg("__cache-daemon").env("XDG_DATA_HOME", &home.0)
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
            .spawn().unwrap();
        let mut child = ChildGuard(Some(child));
        child.0.as_mut().unwrap().stdin.take().unwrap().write_all(seed).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while child.0.as_mut().unwrap().try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline, "invalid-seed daemon exceeded its deadline");
            std::thread::sleep(Duration::from_millis(5));
        }
        let out = child.0.take().unwrap().wait_with_output().unwrap();
        assert_eq!(out.status.code(), Some(1));
        assert!(out.stdout.is_empty());
        assert!(String::from_utf8_lossy(&out.stderr)
            .contains("identity cache seed is missing the recipient or identity"), "{:?}", out.stderr);
    }
}

#[cfg(target_os = "macos")]
struct CacheHome(std::path::PathBuf);

#[cfg(target_os = "macos")]
impl Drop for CacheHome {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(target_os = "macos")]
struct CacheDaemonFixture {
    home: CacheHome,
    child: std::process::Child,
}

#[cfg(target_os = "macos")]
impl CacheDaemonFixture {
    fn start(mut command: Command, suffix: &str) -> Self {
        use age::secrecy::ExposeSecret;
        use std::io::Write;

        let path = std::env::temp_dir().join(format!("vc-{suffix}-{}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        let home = CacheHome(path);
        std::fs::create_dir(home.0.join("vault")).unwrap();
        let child = command
            .env("XDG_DATA_HOME", &home.0)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut fixture = Self { home, child };
        let identity = age::x25519::Identity::generate();
        let recipient = identity.to_public().to_string();
        let private = identity.to_string();
        let mut input = fixture.child.stdin.take().unwrap();
        input.write_all(recipient.as_bytes()).unwrap();
        input.write_all(b"\n").unwrap();
        input.write_all(private.expose_secret().as_bytes()).unwrap();
        input.write_all(b"\n").unwrap();
        drop(input);
        fixture
    }

    fn wait_for_socket(&mut self) -> std::path::PathBuf {
        let socket = self.home.0.join("vault/cache.sock");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while !socket.exists() {
            if let Some(status) = self.child.try_wait().unwrap() {
                use std::io::Read;
                let mut stderr = String::new();
                self.child.stderr.take().unwrap().read_to_string(&mut stderr).unwrap();
                panic!("cache daemon exited before binding: {status}: {stderr}");
            }
            assert!(std::time::Instant::now() < deadline, "cache daemon did not bind");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        socket
    }

    fn wait_for_exit(&mut self) -> std::process::ExitStatus {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(std::time::Instant::now() < deadline, "cache daemon did not exit");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}

#[cfg(target_os = "macos")]
impl Drop for CacheDaemonFixture {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[cfg(target_os = "macos")]
#[test]
fn cache_daemon_accepts_a_valid_seed_and_honors_lock() {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    let mut command = Command::new(env!("CARGO_BIN_EXE_vault"));
    command.arg("__cache-daemon");
    let mut fixture = CacheDaemonFixture::start(command, "normal");
    let socket = fixture.wait_for_socket();
    let mut stream = UnixStream::connect(socket).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    stream.write_all(b"lock\n").unwrap();
    let mut reply = String::new();
    BufReader::new(stream).read_line(&mut reply).unwrap();
    assert_eq!(reply, "ok\n");
    assert!(fixture.wait_for_exit().success());
}

#[cfg(target_os = "macos")]
#[test]
fn cache_daemon_reports_accept_failure() {
    use std::io::Read;
    use std::os::unix::net::UnixStream;

    let library_home = CacheHome(std::env::temp_dir().join(format!("vault-accept-interpose-{}", std::process::id())));
    std::fs::create_dir(&library_home.0).unwrap();
    let library = library_home.0.join("accept-error.dylib");
    let status = Command::new("cc")
        .args(["-dynamiclib", "-o"])
        .arg(&library)
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/accept_error.c"))
        .status()
        .unwrap();
    assert!(status.success(), "VAULT_HARNESS_ERROR: compile the accept refusal fixture");
    let mut command = Command::new(env!("CARGO_BIN_EXE_vault"));
    command.arg("__cache-daemon").env("DYLD_INSERT_LIBRARIES", &library);
    let mut fixture = CacheDaemonFixture::start(command, "limit");
    let socket = fixture.wait_for_socket();
    let _stream = UnixStream::connect(socket).unwrap();
    let status = fixture.wait_for_exit();
    let mut stderr = String::new();
    fixture.child.stderr.take().unwrap().read_to_string(&mut stderr).unwrap();
    assert!(!status.success());
    assert!(stderr.contains("accept identity cache connection failed"));
}

#[test]
fn set_rejects_empty_name() {
    let out = vault(&["set", ""]).unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("empty name"));
}

#[test]
fn get_rejects_empty_name() {
    let out = vault(&["get", ""]).unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("empty name"));
}

#[test]
fn rm_rejects_empty_name() {
    let out = vault(&["rm", ""]).unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("empty name"));
}

#[test]
fn set_too_few_args_errors() {
    assert!(!vault(&["set"]).unwrap().status.success());
}

#[test]
fn set_too_many_args_errors() {
    assert!(!vault(&["set", "A", "B"]).unwrap().status.success());
}

#[test]
fn get_too_few_args_errors() {
    assert!(!vault(&["get"]).unwrap().status.success());
}

#[test]
fn rm_too_few_args_errors() {
    assert!(!vault(&["rm"]).unwrap().status.success());
}

#[test]
fn ls_rejects_extra_args() {
    assert!(!vault(&["ls", "EXTRA"]).unwrap().status.success());
}

#[test]
fn exec_no_vars_runs_command() {
    let out = vault(&["--", "echo", "hello-from-vault"]).unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("hello-from-vault"));
}

#[test]
fn exec_injects_literal_vars() {
    let out = vault(&["FOO=BAR", "ANSWER=42", "--", "env"]).unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("FOO=BAR"), "stdout: {stdout}");
    assert!(stdout.contains("ANSWER=42"), "stdout: {stdout}");
}

#[test]
fn exec_empty_literal_value() {
    let out = vault(&["EMPTY_VAL=", "--", "env"]).unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("EMPTY_VAL="));
}

#[test]
fn exec_missing_dash_dash_errors() {
    let out = vault(&["SOME_VAR", "echo", "hi"]).unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("expected '--' before command"));
}

#[test]
fn exec_missing_command_errors() {
    let out = vault(&["SOME_VAR", "--"]).unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("missing command"));
}

#[test]
fn exec_exits_with_child_exit_code() {
    let out = vault(&["--", "sh", "-c", "exit 7"]).unwrap();
    assert_eq!(out.status.code(), Some(7));
}

#[test]
fn exec_child_killed_by_signal_exits_128_plus_signal() {
    let out = vault(&["--", "sh", "-c", "kill -TERM $$"]).unwrap();
    assert_eq!(out.status.code(), Some(143));
}

#[test]
fn exec_preserves_stdout() {
    let out = vault(&["--", "echo", "exact-output"]).unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "exact-output");
}

#[test]
fn exec_preserves_stderr() {
    let out = vault(&["--", "sh", "-c", "echo err-to-stderr >&2"]).unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("err-to-stderr"));
}

#[test]
fn exec_preserves_inherited_environment_and_literal_overrides() {
    let marker = "VAULT_TEST_INHERITED_MARKER";
    let before = std::env::var_os(marker);
    let out = Command::new(env!("CARGO_BIN_EXE_vault"))
        .env(marker, "inherited-value")
        .args([
            "VAULT_TEST_LITERAL=child-value",
            "--",
            "sh",
            "-c",
            "printf '%s:%s' \"$VAULT_TEST_INHERITED_MARKER\" \"$VAULT_TEST_LITERAL\"",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "inherited-value:child-value"
    );
    assert_eq!(std::env::var_os(marker), before);
}

#[test]
fn exec_spawn_failure_is_reported_without_environment_values() {
    let out = vault(&[
        "VAULT_TEST_SECRET_VALUE=do-not-print",
        "--",
        "vault-command-that-does-not-exist",
    ])
    .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("failed to spawn command"), "stderr: {stderr}");
    assert!(!stderr.contains("do-not-print"), "stderr: {stderr}");
}

#[cfg(target_os = "macos")]
#[test]
fn listing_rejects_untrusted_ancestors_without_reading_the_store() {
    use std::os::unix::fs::PermissionsExt;
    use std::time::{Duration, Instant};

    struct ChildGuard(Option<std::process::Child>);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if let Some(child) = &mut self.0 {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    let home = CacheHome(std::env::temp_dir().join(format!("vault-fs-{}", std::process::id())));
    std::fs::create_dir(&home.0).unwrap();
    std::fs::set_permissions(&home.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    let parent = home.0.join("parent");
    let data = parent.join("data");
    let secrets = data.join("vault/secrets");
    std::fs::create_dir_all(&secrets).unwrap();
    for directory in [&parent, &data, &data.join("vault"), &secrets] {
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    std::fs::write(secrets.join("544f4b454e.age"), b"listing fixture").unwrap();
    let run = |path: &std::path::Path| {
        let mut child = ChildGuard(Some(isolated_vault_command()
            .env("HOME", &home.0).env("XDG_DATA_HOME", path)
            .arg("ls").stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped())
            .spawn().unwrap()));
        let deadline = Instant::now() + Duration::from_secs(5);
        while child.0.as_mut().unwrap().try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline, "filesystem listing exceeded its deadline");
            std::thread::sleep(Duration::from_millis(5));
        }
        child.0.take().unwrap().wait_with_output().unwrap()
    };
    let listed = run(&data);
    assert_eq!(listed.status.code(), Some(0));
    assert_eq!(listed.stdout, b"TOKEN\n");
    assert!(listed.stderr.is_empty());

    for permissions in [0o777, 0o770] {
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(permissions)).unwrap();
        let refused = run(&data);
        assert_eq!(refused.status.code(), Some(1), "mode {permissions:o}");
        assert!(refused.stdout.is_empty());
        assert_eq!(refused.stderr, b"vault: application support parent is writable by other users\n");
    }
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    let link = home.0.join("linked");
    std::os::unix::fs::symlink(&data, &link).unwrap();
    let refused = run(&link);
    assert_eq!(refused.status.code(), Some(1));
    assert!(refused.stdout.is_empty());
    assert!(refused.stderr.starts_with(b"vault: open application support directory failed: "));
    let restored = run(&data);
    assert_eq!(restored.status.code(), Some(0));
    assert_eq!(restored.stdout, b"TOKEN\n");
    assert!(restored.stderr.is_empty());
    assert_eq!(std::fs::read(secrets.join("544f4b454e.age")).unwrap(), b"listing fixture");
}
