use rustix::termios::{InputModes, OptionalActions, tcgetattr, tcsetattr};
use std::fs::File;
use std::io;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};

pub fn open_pty() -> io::Result<(File, File)> {
    use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
    let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).map_err(io::Error::from)?;
    grantpt(&master).map_err(io::Error::from)?;
    unlockpt(&master).map_err(io::Error::from)?;
    let name = ptsname(&master, Vec::new()).map_err(io::Error::from)?;
    let slave = rustix::fs::open(&name, rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOCTTY, rustix::fs::Mode::empty()).map_err(io::Error::from)?;
    let (master, slave) = (File::from(master), File::from(slave));
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
