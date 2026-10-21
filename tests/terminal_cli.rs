#[cfg(unix)]
mod unix_pty {
    use rustix::termios::{InputModes, LocalModes, OptionalActions, tcgetattr, tcsetattr};
    use std::ffi::{c_char, c_int, c_void};
    use std::fs::File;
    use std::io::{self, Read, Write};
    use std::os::fd::FromRawFd;
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
    }

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
        assert_eq!(before.local_modes, after.local_modes);
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
        assert_eq!(before.local_modes, after.local_modes);
    }
}
