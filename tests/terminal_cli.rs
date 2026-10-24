#[cfg(unix)]
mod unix_pty {
    use rustix::termios::{InputModes, LocalModes, OptionalActions, tcgetattr, tcsetattr};
    use std::ffi::{c_char, c_int, c_void};
    use std::fs::File;
    use std::io::{self, Read, Write};
    use std::os::fd::FromRawFd;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::ExitStatusExt;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    #[cfg(target_os = "linux")]
    use std::process::Child;
    #[cfg(target_os = "linux")]
    use std::sync::atomic::{AtomicU64, Ordering};
    #[cfg(target_os = "linux")]
    use std::sync::mpsc::{self, Receiver};
    use std::thread;
    use std::time::{Duration, Instant};

    #[cfg(target_os = "linux")]
    static NEXT_DATA_HOME: AtomicU64 = AtomicU64::new(0);

    #[link(name = "util")]
    unsafe extern "C" {
        fn openpty(
            master: *mut c_int,
            slave: *mut c_int,
            name: *mut c_char,
            termios: *const c_void,
            window_size: *const c_void,
        ) -> c_int;
    }

    unsafe extern "C" {
        fn kill(process: c_int, signal: c_int) -> c_int;
        fn signal(signal: c_int, handler: usize) -> usize;
        fn waitpid(process: c_int, status: *mut c_int, options: c_int) -> c_int;
    }

    #[cfg(target_os = "linux")]
    const SIGTSTP: c_int = 20;
    #[cfg(target_os = "macos")]
    const SIGTSTP: c_int = 18;
    #[cfg(target_os = "linux")]
    const SIGCONT: c_int = 18;
    #[cfg(target_os = "macos")]
    const SIGCONT: c_int = 19;
    const WNOHANG: c_int = 1;
    const WUNTRACED: c_int = 2;

    fn open_pty() -> io::Result<(File, File)> {
        let mut master = -1;
        let mut slave = -1;
        let result = unsafe {
            openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        if result == -1 {
            return Err(io::Error::last_os_error());
        }
        let (master, slave) = unsafe {
            (
                File::from_raw_fd(master),
                File::from_raw_fd(slave),
            )
        };
        let mut settings = tcgetattr(&slave).map_err(io::Error::from)?;
        settings.input_modes &= !InputModes::ISTRIP;
        tcsetattr(&slave, OptionalActions::Now, &settings).map_err(io::Error::from)?;
        Ok((master, slave))
    }

    #[cfg(target_os = "linux")]
    struct TestDataHome(std::path::PathBuf);

    #[cfg(target_os = "linux")]
    impl TestDataHome {
        fn new() -> io::Result<Self> {
            let path = std::env::temp_dir().join(format!(
                "vault-cli-test-{}-{}",
                std::process::id(),
                NEXT_DATA_HOME.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path)?;
            Ok(Self(path))
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for TestDataHome {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(target_os = "linux")]
    fn launch_with_controlling_tty(
        slave: &File,
        data_home: &std::path::Path,
        args: &[&str],
        stdin: Stdio,
    ) -> io::Result<Child> {
        launch_binary_with_controlling_tty(
            std::ffi::OsStr::new(env!("CARGO_BIN_EXE_vault")),
            slave,
            data_home,
            args,
            &[],
            stdin,
        )
    }

    #[cfg(target_os = "linux")]
    fn launch_binary_with_controlling_tty(
        executable: &std::ffi::OsStr,
        slave: &File,
        data_home: &std::path::Path,
        args: &[&str],
        environment: &[(&str, &str)],
        stdin: Stdio,
    ) -> io::Result<Child> {
        let mut command = Command::new(executable);
        for (name, value) in environment {
            command.env(name, value);
        }
        command
            .args(args)
            .env("XDG_DATA_HOME", data_home)
            .stdin(stdin)
            .stdout(Stdio::piped())
            .stderr(Stdio::from(slave.try_clone()?));
        unsafe {
            // SAFETY: The pre-exec closure only creates a session and attaches the inherited terminal.
            command.pre_exec(|| {
                rustix::process::setsid().map_err(io::Error::from)?;
                rustix::process::ioctl_tiocsctty(rustix::stdio::stderr())
                    .map_err(io::Error::from)
            });
        }
        command.spawn()
    }

    #[cfg(target_os = "linux")]
    fn launch_headless(
        data_home: &std::path::Path,
        args: &[&str],
        stdin: Stdio,
    ) -> io::Result<Child> {
        let executable = env!("CARGO_BIN_EXE_vault");
        let mut command = Command::new(executable);
        command
            .args(args)
            .env("XDG_DATA_HOME", data_home)
            .stdin(stdin)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        unsafe {
            // SAFETY: The pre-exec closure only starts a session without a controlling terminal.
            command.pre_exec(|| rustix::process::setsid().map(|_| ()).map_err(io::Error::from));
        }
        command.spawn()
    }

    #[cfg(target_os = "linux")]
    fn read_terminal_chunks(mut reader: File, sender: mpsc::Sender<Vec<u8>>) {
        let mut buffer = [0u8; 1024];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => return,
                Ok(read) => {
                    if sender.send(buffer[..read].to_vec()).is_err() {
                        return;
                    }
                }
                Err(error) if error.raw_os_error() == Some(5) => return,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return,
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn wait_for_prompt(
        master: &mut File,
        chunks: &Receiver<Vec<u8>>,
        output: &mut Vec<u8>,
        prompt: &str,
        response: &str,
    ) -> io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !output
            .windows(prompt.len())
            .any(|window| window == prompt.as_bytes())
        {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("terminal did not show {prompt:?}"),
                ));
            }
            let chunk = chunks
                .recv_timeout(remaining)
                .map_err(|error| io::Error::new(io::ErrorKind::TimedOut, error))?;
            output.extend_from_slice(&chunk);
        }
        master.write_all(response.as_bytes())?;
        master.write_all(b"\n")
    }

    #[cfg(target_os = "linux")]
    fn finish_terminal_output(
        chunks: Receiver<Vec<u8>>,
        mut output: Vec<u8>,
    ) -> io::Result<Vec<u8>> {
        loop {
            match chunks.recv_timeout(Duration::from_secs(5)) {
                Ok(chunk) => output.extend_from_slice(&chunk),
                Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(output),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "terminal output did not close",
                    ));
                }
            }
        }
    }

    fn launch_isset(slave: &File) -> io::Result<std::process::Child> {
        let executable = env!("CARGO_BIN_EXE_vault");
        Command::new(executable)
            .args(["isset", "VAULT_TEST_TERMINAL_INPUT"])
            .stdin(Stdio::from(slave.try_clone()?))
            .stdout(Stdio::from(slave.try_clone()?))
            .stderr(Stdio::from(slave.try_clone()?))
            .spawn()
    }

    fn launch_isset_with_default_tstp(
        slave: &File,
    ) -> io::Result<std::process::Child> {
        let executable = env!("CARGO_BIN_EXE_vault");
        let mut command = Command::new(executable);
        command
            .args(["isset", "VAULT_TEST_TERMINAL_INPUT"])
            .stdin(Stdio::from(slave.try_clone()?))
            .stdout(Stdio::from(slave.try_clone()?))
            .stderr(Stdio::from(slave.try_clone()?))
            .process_group(0);
        unsafe {
            command.pre_exec(|| {
                if signal(SIGTSTP, 0) == usize::MAX {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        command.spawn()
    }

    fn wait_for_hidden_echo(terminal: &File) -> io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let settings = tcgetattr(terminal).map_err(io::Error::from)?;
            if !settings.local_modes.intersects(
                LocalModes::ECHO | LocalModes::ECHONL | LocalModes::ICANON,
            ) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "terminal echo did not turn off",
                ));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn wait_for_child_event(process: c_int) -> io::Result<Option<c_int>> {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let mut status = 0;
            let result = unsafe { waitpid(process, &mut status, WNOHANG | WUNTRACED) };
            if result == process {
                return Ok(Some(status));
            }
            if result == -1 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            thread::yield_now();
        }
    }

    fn is_stopped(status: c_int) -> bool {
        status & 0xff == 0x7f
    }

    fn read_terminal_output(mut master: File) -> io::Result<Vec<u8>> {
        let mut output = Vec::new();
        let mut buffer = [0u8; 1024];
        loop {
            match master.read(&mut buffer) {
                Ok(0) => return Ok(output),
                Ok(read) => output.extend_from_slice(&buffer[..read]),
                Err(error) if error.raw_os_error() == Some(5) => return Ok(output),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    }

    #[test]
    fn silent_terminal_input_hides_bytes_and_restores_settings_on_invalid_utf8() {
        let (mut master, slave) = open_pty().unwrap();
        let before = tcgetattr(&slave).unwrap();
        let output_reader = thread::spawn({
            let reader = master.try_clone().unwrap();
            move || read_terminal_output(reader)
        });
        let mut child = launch_isset(&slave).unwrap();
        drop(slave);
        wait_for_hidden_echo(&master).unwrap();
        master.write_all(b"vault-terminal-secret-\xff\n").unwrap();
        let status = child.wait().unwrap();
        assert!(!status.success(), "unexpected success: {status}");
        let after = tcgetattr(&master).unwrap();
        let output = output_reader.join().unwrap().unwrap();
        assert_eq!(
            before.local_modes & !LocalModes::PENDIN,
            after.local_modes & !LocalModes::PENDIN
        );
        assert!(!output
            .windows(b"vault-terminal-secret".len())
            .any(|window| window == b"vault-terminal-secret"));
        assert!(String::from_utf8_lossy(&output).contains("invalid UTF-8"));
    }

    #[test]
    fn terminal_interrupt_restores_settings_without_storing() {
        let (mut master, slave) = open_pty().unwrap();
        let before = tcgetattr(&slave).unwrap();
        let output_reader = thread::spawn({
            let reader = master.try_clone().unwrap();
            move || read_terminal_output(reader)
        });
        let mut child = launch_isset(&slave).unwrap();
        drop(slave);
        wait_for_hidden_echo(&master).unwrap();
        let result = unsafe { kill(child.id() as c_int, 2) };
        assert_eq!(result, 0);
        let deadline = Instant::now() + Duration::from_secs(2);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = master.write_all(b"\xff\n");
                let _ = child.wait();
                panic!("terminal input did not stop after SIGINT");
            }
            thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(status.code(), Some(130));
        let after = tcgetattr(&master).unwrap();
        let _ = output_reader.join().unwrap().unwrap();
        assert_eq!(
            before.local_modes & !LocalModes::PENDIN,
            after.local_modes & !LocalModes::PENDIN
        );
    }

    #[test]
    fn terminal_suspend_restores_settings_until_resume_and_continues_input() {
        let (mut master, slave) = open_pty().unwrap();
        let before = tcgetattr(&slave).unwrap();
        let output_reader = thread::spawn({
            let reader = master.try_clone().unwrap();
            move || read_terminal_output(reader)
        });
        let mut child = launch_isset_with_default_tstp(&slave).unwrap();
        drop(slave);
        wait_for_hidden_echo(&master).unwrap();
        master.write_all(b"vault-suspend-secret").unwrap();
        assert_eq!(unsafe { kill(child.id() as c_int, SIGTSTP) }, 0);

        let event = wait_for_child_event(child.id() as c_int).unwrap();
        let stopped = event.is_some_and(is_stopped);
        let stopped_settings = tcgetattr(&master).ok();
        let (final_status, resumed, resumed_in_silent_mode) =
            if event.is_some_and(|status| !is_stopped(status)) {
                let wait_result = child.wait();
                assert!(wait_result.is_err(), "waitpid already reaped the child");
                (std::process::ExitStatus::from_raw(event.unwrap()), false, false)
            } else {
                let resumed = unsafe { kill(child.id() as c_int, SIGCONT) } == 0;
                let resumed_in_silent_mode = wait_for_hidden_echo(&master).is_ok();
                let _ = master.write_all(b"-after-resume-\xff\n");
                (child.wait().unwrap(), resumed, resumed_in_silent_mode)
            };
        let after = tcgetattr(&master).unwrap();
        let output = output_reader.join().unwrap().unwrap();
        assert!(stopped, "process did not stop for SIGTSTP: {event:?}");
        assert!(resumed, "terminal reader did not resume after SIGCONT");
        assert!(resumed_in_silent_mode, "terminal input did not resume silently");
        let stopped_settings = stopped_settings.unwrap();
        assert_eq!(
            before.local_modes & !LocalModes::PENDIN,
            stopped_settings.local_modes & !LocalModes::PENDIN
        );
        assert!(!final_status.success());
        assert_eq!(
            before.local_modes & !LocalModes::PENDIN,
            after.local_modes & !LocalModes::PENDIN
        );
        assert!(!output
            .windows(b"vault-suspend-secret".len())
            .any(|window| window == b"vault-suspend-secret"));
        assert!(String::from_utf8_lossy(&output).contains("invalid UTF-8"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn controlling_tty_passphrase_is_independent_of_piped_secrets_and_exec_prompts_once() {
        let data_home = TestDataHome::new().unwrap();
        let (mut master, slave) = open_pty().unwrap();
        let (sender, chunks) = mpsc::channel();
        let reader_fd = master.try_clone().unwrap();
        let reader = thread::spawn(move || read_terminal_chunks(reader_fd, sender));
        let mut set = launch_with_controlling_tty(
            &slave,
            data_home.path(),
            &["set", "TOKEN"],
            Stdio::piped(),
        )
        .unwrap();
        drop(slave);
        set.stdin
            .take()
            .unwrap()
            .write_all(b"pipe-secret")
            .unwrap();
        let passphrase = "test master passphrase";
        let mut terminal_output = Vec::new();
        wait_for_prompt(
            &mut master,
            &chunks,
            &mut terminal_output,
            "Create master passphrase: ",
            passphrase,
        )
        .unwrap();
        wait_for_prompt(
            &mut master,
            &chunks,
            &mut terminal_output,
            "Confirm master passphrase: ",
            passphrase,
        )
        .unwrap();
        assert!(set.wait_with_output().unwrap().status.success());
        drop(master);
        let terminal_output = finish_terminal_output(chunks, terminal_output).unwrap();
        reader.join().unwrap();
        assert!(!terminal_output
            .windows(passphrase.len())
            .any(|window| window == passphrase.as_bytes()));
        assert!(!terminal_output
            .windows(b"pipe-secret".len())
            .any(|window| window == b"pipe-secret"));

        let mut second_set = launch_headless(
            data_home.path(),
            &["isset", "DATABASE_URL"],
            Stdio::piped(),
        )
        .unwrap();
        second_set
            .stdin
            .take()
            .unwrap()
            .write_all(b"database-secret")
            .unwrap();
        assert!(second_set.wait_with_output().unwrap().status.success());

        let headless_get = launch_headless(
            data_home.path(),
            &["get", "TOKEN"],
            Stdio::null(),
        )
        .unwrap()
        .wait_with_output()
        .unwrap();
        assert!(!headless_get.status.success());
        assert!(headless_get.stdout.is_empty());
        assert!(String::from_utf8_lossy(&headless_get.stderr)
            .contains("controlling terminal is required"));

        let (mut master, slave) = open_pty().unwrap();
        let (sender, chunks) = mpsc::channel();
        let reader_fd = master.try_clone().unwrap();
        let reader = thread::spawn(move || read_terminal_chunks(reader_fd, sender));
        let exec = launch_with_controlling_tty(
            &slave,
            data_home.path(),
            &[
                "TOKEN",
                "DATABASE_URL",
                "--",
                "sh",
                "-c",
                "printf '%s:%s' \"$TOKEN\" \"$DATABASE_URL\"",
            ],
            Stdio::null(),
        )
        .unwrap();
        drop(slave);
        let mut exec_terminal_output = Vec::new();
        wait_for_prompt(
            &mut master,
            &chunks,
            &mut exec_terminal_output,
            "Master passphrase: ",
            passphrase,
        )
        .unwrap();
        let exec_output = exec.wait_with_output().unwrap();
        assert!(exec_output.status.success());
        assert_eq!(exec_output.stdout, b"pipe-secret:database-secret");
        drop(master);
        let exec_terminal_output = finish_terminal_output(chunks, exec_terminal_output).unwrap();
        reader.join().unwrap();
        assert_eq!(
            String::from_utf8_lossy(&exec_terminal_output)
                .matches("Master passphrase: ")
                .count(),
            1
        );
        assert!(!exec_terminal_output
            .windows(passphrase.len())
            .any(|window| window == passphrase.as_bytes()));

        let cached_get = launch_headless(
            data_home.path(),
            &["get", "TOKEN"],
            Stdio::null(),
        )
        .unwrap()
        .wait_with_output()
        .unwrap();
        let cache_available = !String::from_utf8_lossy(&exec_terminal_output)
            .contains("identity cache unavailable");
        if cache_available {
            assert!(cached_get.status.success());
            assert_eq!(cached_get.stdout, b"pipe-secret\n");
            assert!(cached_get.stderr.is_empty());

            let locked = launch_headless(data_home.path(), &["lock"], Stdio::null())
                .unwrap()
                .wait_with_output()
                .unwrap();
            assert!(locked.status.success());
            assert_eq!(locked.stdout, b"identity cache cleared\n");

            let revoked_get = launch_headless(
                data_home.path(),
                &["get", "TOKEN"],
                Stdio::null(),
            )
            .unwrap()
            .wait_with_output()
            .unwrap();
            assert!(!revoked_get.status.success());
            assert!(String::from_utf8_lossy(&revoked_get.stderr)
                .contains("controlling terminal is required"));
        } else {
            assert!(!cached_get.status.success());
            assert!(String::from_utf8_lossy(&cached_get.stderr)
                .contains("controlling terminal is required"));
            let lock = launch_headless(data_home.path(), &["lock"], Stdio::null())
                .unwrap()
                .wait_with_output()
                .unwrap();
            if lock.status.success() {
                let stdout = String::from_utf8_lossy(&lock.stdout);
                assert!(
                    stdout == "identity cache cleared\n"
                        || stdout == "identity cache already clear\n",
                    "unexpected lock output: {stdout:?}"
                );
            } else {
                assert!(String::from_utf8_lossy(&lock.stderr)
                    .contains("clear Linux identity cache failed"));
            }
            let revoked_get = launch_headless(
                data_home.path(),
                &["get", "TOKEN"],
                Stdio::null(),
            )
            .unwrap()
            .wait_with_output()
            .unwrap();
            assert!(!revoked_get.status.success());
            assert!(String::from_utf8_lossy(&revoked_get.stderr)
                .contains("controlling terminal is required"));
        }

        let listed = launch_headless(data_home.path(), &["ls"], Stdio::null())
            .unwrap()
            .wait_with_output()
            .unwrap();
        assert!(listed.status.success());
        assert_eq!(listed.stdout, b"DATABASE_URL\nTOKEN\n");

        let removed = launch_headless(
            data_home.path(),
            &["rm", "DATABASE_URL"],
            Stdio::null(),
        )
        .unwrap()
        .wait_with_output()
        .unwrap();
        assert!(removed.status.success());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn invalid_linux_name_fails_before_reading_piped_input() {
        let data_home = TestDataHome::new().unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_vault"))
            .args(["set", "INVALID-NAME"])
            .env("XDG_DATA_HOME", data_home.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let held_stdin = child.stdin.take().unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while child.try_wait().unwrap().is_none() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        let status = child.try_wait().unwrap();
        drop(held_stdin);
        if status.is_none() {
            child.kill().unwrap();
            let _ = child.wait();
            panic!("vault blocked while reading input for an invalid name");
        }
        let output = child.wait_with_output().unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("invalid secret name"));
        assert!(!data_home.path().join("vault").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn piped_secret_over_the_limit_fails_without_initializing_the_store() {
        let data_home = TestDataHome::new().unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_vault"))
            .args(["isset", "TOKEN"])
            .env("XDG_DATA_HOME", data_home.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        let too_large = vec![b'x'; 16 * 1024 * 1024 + 1];
        let _ = input.write_all(&too_large);
        drop(input);
        let output = child.wait_with_output().unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("input exceeds 16 MiB limit"));
        assert!(!data_home.path().join("vault").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pinned_rage_interoperates_with_vault_age_files() {
        let rage = match std::env::var_os("RAGE") {
            Some(path) => std::path::PathBuf::from(path),
            None => match Command::new("rage").arg("--version").output() {
                Ok(output) if output.status.success() => std::path::PathBuf::from("rage"),
                _ => {
                    eprintln!("skipped age interoperability: rage 0.12.1 is unavailable");
                    return;
                }
            },
        };
        let version = Command::new(&rage).arg("--version").output().unwrap();
        if !version.status.success() || !String::from_utf8_lossy(&version.stdout).contains("0.12.1") {
            eprintln!("skipped age interoperability: rage 0.12.1 is required");
            return;
        }

        let data_home = TestDataHome::new().unwrap();
        let passphrase = "rage interoperability passphrase";
        let (mut master, slave) = open_pty().unwrap();
        let (sender, chunks) = mpsc::channel();
        let reader = thread::spawn({
            let reader = master.try_clone().unwrap();
            move || read_terminal_chunks(reader, sender)
        });
        let mut set = launch_with_controlling_tty(
            &slave,
            data_home.path(),
            &["set", "TOKEN"],
            Stdio::piped(),
        )
        .unwrap();
        drop(slave);
        set.stdin
            .take()
            .unwrap()
            .write_all(b"vault generated value")
            .unwrap();
        let mut terminal_output = Vec::new();
        wait_for_prompt(
            &mut master,
            &chunks,
            &mut terminal_output,
            "Create master passphrase: ",
            passphrase,
        )
        .unwrap();
        wait_for_prompt(
            &mut master,
            &chunks,
            &mut terminal_output,
            "Confirm master passphrase: ",
            passphrase,
        )
        .unwrap();
        assert!(set.wait_with_output().unwrap().status.success());
        drop(master);
        let terminal_output = finish_terminal_output(chunks, terminal_output).unwrap();
        reader.join().unwrap();
        assert!(!terminal_output
            .windows(passphrase.len())
            .any(|window| window == passphrase.as_bytes()));

        let store = data_home.path().join("vault");
        let identity_path = store.join("identity.age");
        let secret_path = store.join("secrets/TOKEN.age");
        let vault_ciphertext = std::fs::read(&secret_path).unwrap();
        assert!(vault_ciphertext.starts_with(b"age-encryption.org/v1\n"));
        assert!(!vault_ciphertext.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----"));

        let (mut master, slave) = open_pty().unwrap();
        let (sender, chunks) = mpsc::channel();
        let reader = thread::spawn({
            let reader = master.try_clone().unwrap();
            move || read_terminal_chunks(reader, sender)
        });
        let identity_arg = identity_path.to_str().unwrap();
        let decrypt_identity = launch_binary_with_controlling_tty(
            rage.as_os_str(),
            &slave,
            data_home.path(),
            &["--decrypt", identity_arg],
            &[("PINENTRY_PROGRAM", "")],
            Stdio::null(),
        )
        .unwrap();
        drop(slave);
        let mut terminal_output = Vec::new();
        wait_for_prompt(
            &mut master,
            &chunks,
            &mut terminal_output,
            "Type passphrase",
            passphrase,
        )
        .unwrap();
        let rage_identity = decrypt_identity.wait_with_output().unwrap();
        assert!(rage_identity.status.success());
        assert!(rage_identity.stdout.starts_with(b"AGE-SECRET-KEY-1"));
        drop(master);
        let terminal_output = finish_terminal_output(chunks, terminal_output).unwrap();
        reader.join().unwrap();
        assert!(!terminal_output
            .windows(passphrase.len())
            .any(|window| window == passphrase.as_bytes()));

        let mut decrypt_vault_secret = Command::new(&rage)
            .args(["--decrypt", "--identity", "-"])
            .arg(&secret_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        decrypt_vault_secret
            .stdin
            .take()
            .unwrap()
            .write_all(&rage_identity.stdout)
            .unwrap();
        let decrypted = decrypt_vault_secret.wait_with_output().unwrap();
        assert!(decrypted.status.success(), "{}", String::from_utf8_lossy(&decrypted.stderr));
        assert_eq!(decrypted.stdout, b"vault generated value");

        let recipient = std::fs::read_to_string(store.join("recipient")).unwrap();
        let mut encrypt_rage_secret = Command::new(&rage)
            .args(["--encrypt", "--recipient", recipient.trim()])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        encrypt_rage_secret
            .stdin
            .take()
            .unwrap()
            .write_all(b"rage generated value")
            .unwrap();
        let encrypted = encrypt_rage_secret.wait_with_output().unwrap();
        assert!(encrypted.status.success(), "{}", String::from_utf8_lossy(&encrypted.stderr));
        assert!(encrypted.stdout.starts_with(b"age-encryption.org/v1\n"));
        let rage_ciphertext_path = store.join("secrets/RAGE.age");
        std::fs::write(&rage_ciphertext_path, &encrypted.stdout).unwrap();
        std::fs::set_permissions(
            &rage_ciphertext_path,
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();

        let (mut master, slave) = open_pty().unwrap();
        let (sender, chunks) = mpsc::channel();
        let reader = thread::spawn({
            let reader = master.try_clone().unwrap();
            move || read_terminal_chunks(reader, sender)
        });
        let get = launch_with_controlling_tty(
            &slave,
            data_home.path(),
            &["get", "RAGE"],
            Stdio::null(),
        )
        .unwrap();
        drop(slave);
        let mut terminal_output = Vec::new();
        wait_for_prompt(
            &mut master,
            &chunks,
            &mut terminal_output,
            "Master passphrase: ",
            passphrase,
        )
        .unwrap();
        let output = get.wait_with_output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        assert_eq!(output.stdout, b"rage generated value\n");
        drop(master);
        finish_terminal_output(chunks, terminal_output).unwrap();
        reader.join().unwrap();

        let mut damaged = vault_ciphertext;
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        let damaged_path = store.join("secrets/DAMAGED.age");
        std::fs::write(&damaged_path, damaged).unwrap();
        std::fs::set_permissions(&damaged_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut reject_damaged = Command::new(&rage)
            .args(["--decrypt", "--identity", "-"])
            .arg(&damaged_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        reject_damaged
            .stdin
            .take()
            .unwrap()
            .write_all(&rage_identity.stdout)
            .unwrap();
        assert!(!reject_damaged.wait_with_output().unwrap().status.success());
    }
}
