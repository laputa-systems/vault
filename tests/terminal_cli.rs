#[cfg(unix)]
mod unix_pty {
    use rustix::termios::{InputModes, LocalModes, OptionalActions, tcgetattr, tcsetattr};
    use std::ffi::{c_char, c_int, c_void};
    use std::fs::File;
    use std::io::{self, Read, Write};
    use std::os::fd::FromRawFd;
    use std::os::unix::process::ExitStatusExt;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

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
}
