use rustix::termios::{InputModes, OptionalActions, tcgetattr, tcsetattr};
use std::fs::File;
use std::io;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};

use std::ffi::{c_char, c_int, c_void};
use std::os::fd::FromRawFd;

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


pub fn open_pty() -> io::Result<(File, File)> {
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


#[allow(dead_code)]
pub fn launch_binary_with_controlling_tty(
    executable: &std::ffi::OsStr, slave: &File, data_home: &std::path::Path,
    args: &[&str], environment: &[(&str, &str)], stdin: Stdio,
) -> io::Result<Child> {
    let mut command = Command::new(executable);
    for (name, value) in environment { command.env(name, value); }
    command.args(args).env("XDG_DATA_HOME", data_home).stdin(stdin)
        .stdout(Stdio::piped()).stderr(Stdio::from(slave.try_clone()?));
    let terminal = slave.try_clone()?;
    unsafe {
        // SAFETY: The pre-exec closure only creates a session and attaches the inherited terminal.
        command.pre_exec(move || {
            rustix::process::setsid().map_err(io::Error::from)?;
            rustix::process::ioctl_tiocsctty(&terminal).map_err(io::Error::from)
        });
    }
    command.spawn()
}
