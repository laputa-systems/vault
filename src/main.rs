use rustix::termios::{LocalModes, OptionalActions, Termios, tcgetattr, tcsetattr};
use std::fmt;
use std::io::{self, Read, Write};
use std::process::{Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};
use vault::keychain;

const USAGE: &str = "\
vault — macOS Keychain secret manager

Usage:

  vault set   <NAME>            Store a secret (prompts for value)
  vault isset <NAME>            Store a secret (silent, no prompt)
  vault get   <NAME>            Print a secret to stdout
  vault rm    <NAME>            Delete a secret
  vault ls                      List all stored secret names
  vault purge                   Delete every secret vault manages

  vault [ENV ...] -- <CMD> [ARGS ...]   Run CMD with secrets injected

Environment specifications before -- may be:

  KEY                          Look up KEY in the Keychain
  KEY=VALUE                    Pass literal KEY=VALUE

Examples:

  vault set OPENAI_API_KEY
  vault OPENAI_API_KEY DATABASE_URL RUST_LOG=debug -- cargo run
  vault -- cargo run
";

static PENDING_SIGNAL: AtomicI32 = AtomicI32::new(0);

unsafe extern "C" {
    fn signal(signal: i32, handler: usize) -> usize;
    fn siginterrupt(signal: i32, interrupt: i32) -> i32;
}

extern "C" fn remember_signal(signal: i32) {
    PENDING_SIGNAL.store(signal, Ordering::Relaxed);
}

#[derive(Debug)]
enum CliError {
    InvalidInput(String),
    Keychain(String),
    Io {
        operation: &'static str,
        source: io::Error,
    },
    Spawn(io::Error),
    Wait {
        source: io::Error,
        kill: Option<io::Error>,
        reap: Option<io::Error>,
    },
    TerminalSettings {
        operation: &'static str,
        source: io::Error,
        restore: Option<io::Error>,
    },
    TerminalReadAndRestore {
        read: Box<CliError>,
        restore: Box<CliError>,
    },
    SignalSetup {
        source: io::Error,
        restore: Option<io::Error>,
    },
    SignalRestore(io::Error),
    InvalidUtf8,
    Interrupted(i32),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(message) | Self::Keychain(message) => f.write_str(message),
            Self::Io { operation, source } => write!(f, "vault: {operation} failed: {source}"),
            Self::Spawn(source) => write!(f, "vault: failed to spawn command: {source}"),
            Self::Wait { source, kill, reap } => {
                write!(f, "vault: failed to wait for command: {source}")?;
                if let Some(error) = kill {
                    write!(f, "; failed to stop child during cleanup: {error}")?;
                }
                if let Some(error) = reap {
                    write!(f, "; failed to reap child during cleanup: {error}")?;
                }
                Ok(())
            }
            Self::TerminalSettings {
                operation,
                source,
                restore,
            } => {
                write!(f, "vault: terminal {operation} failed: {source}")?;
                if let Some(error) = restore {
                    write!(f, "; terminal restoration failed: {error}")?;
                }
                Ok(())
            }
            Self::TerminalReadAndRestore { read, restore } => {
                write!(f, "vault: {read}; terminal restoration also failed: {restore}")
            }
            Self::SignalSetup { source, restore } => {
                write!(f, "vault: failed to prepare interrupt handling: {source}")?;
                if let Some(error) = restore {
                    write!(f, "; signal handler cleanup failed: {error}")?;
                }
                Ok(())
            }
            Self::SignalRestore(source) => {
                write!(f, "vault: failed to restore signal handlers: {source}")
            }
            Self::InvalidUtf8 => f.write_str("vault: failed to read input: invalid UTF-8"),
            Self::Interrupted(_) => f.write_str("vault: input interrupted"),
        }
    }
}

impl std::error::Error for CliError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. }
            | Self::Spawn(source)
            | Self::SignalRestore(source) => Some(source),
            Self::Wait { source, .. } => Some(source),
            Self::TerminalSettings { source, .. } => Some(source),
            Self::TerminalReadAndRestore { read, .. } => Some(read),
            Self::SignalSetup { source, .. } => Some(source),
            Self::InvalidInput(_)
            | Self::Keychain(_)
            | Self::InvalidUtf8
            | Self::Interrupted(_) => None,
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(status) => status,
        Err(CliError::Interrupted(signal)) => ExitCode::from((128 + signal) as u8),
        Err(error) => {
            let _ = writeln!(io::stderr().lock(), "{error}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<ExitCode, CliError> {
    if args.is_empty() {
        write_stdout(USAGE.as_bytes())?;
        return Ok(ExitCode::SUCCESS);
    }

    match args[0].as_str() {
        "set" => {
            cmd_set(&args[1..], false)?;
            Ok(ExitCode::SUCCESS)
        }
        "isset" => {
            cmd_set(&args[1..], true)?;
            Ok(ExitCode::SUCCESS)
        }
        "get" => {
            cmd_get(&args[1..])?;
            Ok(ExitCode::SUCCESS)
        }
        "rm" => {
            cmd_rm(&args[1..])?;
            Ok(ExitCode::SUCCESS)
        }
        "ls" => {
            cmd_ls(&args[1..])?;
            Ok(ExitCode::SUCCESS)
        }
        "purge" => {
            cmd_purge(&args[1..])?;
            Ok(ExitCode::SUCCESS)
        }
        "-h" | "--help" | "help" => {
            write_stdout(USAGE.as_bytes())?;
            Ok(ExitCode::SUCCESS)
        }
        _ => exec_mode(args),
    }
}

fn write_stdout(bytes: &[u8]) -> Result<(), CliError> {
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(bytes)
        .and_then(|()| stdout.flush())
        .map_err(|source| CliError::Io {
            operation: "write stdout",
            source,
        })
}

fn write_stderr(bytes: &[u8]) -> Result<(), CliError> {
    let mut stderr = io::stderr().lock();
    stderr
        .write_all(bytes)
        .and_then(|()| stderr.flush())
        .map_err(|source| CliError::Io {
            operation: "write stderr",
            source,
        })
}

fn require_exact_name<'a>(args: &'a [String], cmd: &str) -> Result<&'a str, CliError> {
    if args.is_empty() {
        return Err(CliError::InvalidInput(format!(
            "vault: missing name for {cmd}"
        )));
    }
    if args.len() > 1 {
        return Err(CliError::InvalidInput(format!(
            "vault: unexpected argument for {cmd}"
        )));
    }
    if args[0].is_empty() {
        return Err(CliError::InvalidInput(
            "vault: empty name not allowed".to_owned(),
        ));
    }
    Ok(&args[0])
}

fn cmd_set(args: &[String], silent: bool) -> Result<(), CliError> {
    let name = require_exact_name(args, if silent { "isset" } else { "set" })?;
    let value = read_secret(name, silent)?;
    persist_secret(name, Ok(value), keychain::set_secret)
}

fn persist_secret(
    name: &str,
    read_value: Result<String, CliError>,
    store: impl FnOnce(&str, &[u8]) -> Result<(), String>,
) -> Result<(), CliError> {
    let value = read_value?;
    store(name, value.as_bytes()).map_err(CliError::Keychain)
}

fn cmd_get(args: &[String]) -> Result<(), CliError> {
    let name = require_exact_name(args, "get")?;
    let value = keychain::get_secret(name).map_err(CliError::Keychain)?;
    write_stdout(value.as_bytes())?;
    write_stdout(b"\n")
}

fn cmd_rm(args: &[String]) -> Result<(), CliError> {
    let name = require_exact_name(args, "rm")?;
    keychain::delete_secret(name).map_err(CliError::Keychain)
}

fn cmd_ls(args: &[String]) -> Result<(), CliError> {
    require_no_args(args, "ls")?;
    for name in keychain::list_secrets().map_err(CliError::Keychain)? {
        write_stdout(name.as_bytes())?;
        write_stdout(b"\n")?;
    }
    Ok(())
}

fn cmd_purge(args: &[String]) -> Result<(), CliError> {
    cmd_purge_with(args, keychain::purge_secrets)
}

fn cmd_purge_with(
    args: &[String],
    purge: impl FnOnce() -> Result<usize, String>,
) -> Result<(), CliError> {
    require_no_args(args, "purge")?;
    match purge().map_err(CliError::Keychain)? {
        0 => write_stdout(b"nothing to purge\n"),
        count => write_stdout(
            format!("purged {count} secret{}\n", if count == 1 { "" } else { "s" }).as_bytes(),
        ),
    }
}

fn require_no_args(args: &[String], cmd: &str) -> Result<(), CliError> {
    if args.is_empty() {
        Ok(())
    } else {
        Err(CliError::InvalidInput(format!(
            "vault: {cmd} takes no arguments"
        )))
    }
}

enum EnvSpec<'a> {
    Literal { name: &'a str, value: &'a str },
    Keychain(&'a str),
}

fn parse_env_spec(spec: &str) -> EnvSpec<'_> {
    if let Some((name, value)) = spec.split_once('=')
        && !name.is_empty()
        && !value.contains('=')
    {
        return EnvSpec::Literal { name, value };
    }
    EnvSpec::Keychain(spec)
}

fn parse_exec_args(args: &[String]) -> Result<(&[String], &[String]), CliError> {
    let Some(dash_pos) = args.iter().position(|arg| arg == "--") else {
        return Err(CliError::InvalidInput(
            "vault: expected '--' before command".to_owned(),
        ));
    };
    let specs = &args[..dash_pos];
    let command = &args[dash_pos + 1..];
    if command.is_empty() {
        return Err(CliError::InvalidInput(
            "vault: missing command".to_owned(),
        ));
    }
    Ok((specs, command))
}

fn exec_mode(args: &[String]) -> Result<ExitCode, CliError> {
    let (specs, cmd_args) = parse_exec_args(args)?;
    let mut environment = Vec::with_capacity(specs.len());
    for spec in specs {
        match parse_env_spec(spec) {
            EnvSpec::Literal { name, value } => {
                environment.push((name.to_owned(), value.to_owned()));
            }
            EnvSpec::Keychain(name) => {
                let value = keychain::get_secret(name).map_err(CliError::Keychain)?;
                environment.push((name.to_owned(), value));
            }
        }
    }
    run_child(cmd_args, &environment)
}

fn run_child(
    cmd_args: &[String],
    environment: &[(String, String)],
) -> Result<ExitCode, CliError> {
    let mut command = Command::new(&cmd_args[0]);
    command
        .args(&cmd_args[1..])
        .envs(environment.iter().map(|(name, value)| (name, value)))
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    let mut child = command.spawn().map_err(CliError::Spawn)?;
    match child.wait() {
        Ok(status) => {
            #[cfg(unix)]
            if let Some(signal) = std::os::unix::process::ExitStatusExt::signal(&status) {
                return Ok(ExitCode::from((128 + signal) as u8));
            }
            Ok(ExitCode::from(status.code().unwrap_or(1) as u8))
        }
        Err(source) => {
            let kill = child.kill().err();
            let reap = child.wait().err();
            Err(CliError::Wait { source, kill, reap })
        }
    }
}

fn read_secret(name: &str, silent: bool) -> Result<String, CliError> {
    let stdin = io::stdin();
    if rustix::termios::isatty(&stdin) {
        if !silent {
            write_stderr(format!("Enter value for {name}: ").as_bytes())?;
        }
        let mut signals = SignalHandlers::install()?;
        let mut terminal = StdinTerminal { stdin: &stdin };
        let read_result = read_without_echo(
            &mut stdin.lock(),
            &mut io::stderr().lock(),
            silent,
            &mut terminal,
            || {
                let signal = PENDING_SIGNAL.load(Ordering::Relaxed);
                (signal != 0).then_some(signal)
            },
        );
        let signal_restore = signals.restore();
        if let Err(source) = signal_restore {
            return Err(CliError::SignalRestore(source));
        }
        let value = read_result?;
        let signal = PENDING_SIGNAL.load(Ordering::Relaxed);
        if signal != 0 {
            return Err(CliError::Interrupted(signal));
        }
        Ok(value)
    } else {
        let mut bytes = Vec::new();
        stdin
            .lock()
            .read_to_end(&mut bytes)
            .map_err(|source| CliError::Io {
                operation: "read stdin",
                source,
            })?;
        let mut value = String::from_utf8(bytes).map_err(|_| CliError::InvalidUtf8)?;
        strip_trailing_newline(&mut value);
        Ok(value)
    }
}

fn read_without_echo<R, W, T, I>(
    input: &mut R,
    feedback: &mut W,
    silent: bool,
    terminal: &mut T,
    mut interrupted: I,
) -> Result<String, CliError>
where
    R: Read,
    W: Write,
    T: TerminalSettings,
    I: FnMut() -> Option<i32>,
{
    let mut session = TerminalSession::enter(terminal)?;
    let read_result = read_terminal_line(input, feedback, silent, &mut interrupted);
    let restore_result = session
        .restore()
        .map_err(|source| CliError::TerminalSettings {
            operation: "restore settings",
            source,
            restore: None,
        });
    let bytes = match (read_result, restore_result) {
        (Ok(bytes), Ok(())) => bytes,
        (Err(error), Ok(())) => return Err(error),
        (Ok(_), Err(error)) => return Err(error),
        (Err(read), Err(restore)) => {
            return Err(CliError::TerminalReadAndRestore {
                read: Box::new(read),
                restore: Box::new(restore),
            });
        }
    };
    if !silent {
        feedback.write_all(b"\n").map_err(|source| CliError::Io {
            operation: "write terminal feedback",
            source,
        })?;
        feedback.flush().map_err(|source| CliError::Io {
            operation: "write terminal feedback",
            source,
        })?;
    }
    String::from_utf8(bytes).map_err(|_| CliError::InvalidUtf8)
}

fn read_terminal_line<R, W, I>(
    input: &mut R,
    feedback: &mut W,
    silent: bool,
    interrupted: &mut I,
) -> Result<Vec<u8>, CliError>
where
    R: Read,
    W: Write,
    I: FnMut() -> Option<i32>,
{
    let mut value = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if let Some(signal) = interrupted() {
            return Err(CliError::Interrupted(signal));
        }
        match input.read(&mut byte) {
            Ok(0) => return Ok(value),
            Ok(_) => {
                if let Some(signal) = interrupted() {
                    return Err(CliError::Interrupted(signal));
                }
                match byte[0] {
                    b'\n' | b'\r' => return Ok(value),
                    0x7f => {
                        if value.pop().is_some() && !silent {
                            feedback.write_all(b"\x08 \x08").map_err(|source| {
                                CliError::Io {
                                    operation: "write terminal feedback",
                                    source,
                                }
                            })?;
                        }
                    }
                    byte => {
                        value.push(byte);
                        if !silent {
                            feedback.write_all(b"*").map_err(|source| CliError::Io {
                                operation: "write terminal feedback",
                                source,
                            })?;
                        }
                    }
                }
            }
            Err(source) if source.kind() == io::ErrorKind::Interrupted => {
                if let Some(signal) = interrupted() {
                    return Err(CliError::Interrupted(signal));
                }
            }
            Err(source) => {
                return Err(CliError::Io {
                    operation: "read terminal input",
                    source,
                });
            }
        }
    }
}

trait TerminalSettings {
    type Saved;

    fn snapshot(&mut self) -> io::Result<Self::Saved>;
    fn disable_echo(&mut self, saved: &Self::Saved) -> io::Result<()>;
    fn restore(&mut self, saved: &Self::Saved) -> io::Result<()>;
}

struct StdinTerminal<'a> {
    stdin: &'a io::Stdin,
}

impl TerminalSettings for StdinTerminal<'_> {
    type Saved = Termios;

    fn snapshot(&mut self) -> io::Result<Self::Saved> {
        tcgetattr(self.stdin).map_err(io::Error::from)
    }

    fn disable_echo(&mut self, saved: &Self::Saved) -> io::Result<()> {
        let mut hidden = saved.clone();
        hidden.local_modes &= !(LocalModes::ECHO | LocalModes::ECHONL | LocalModes::ICANON);
        tcsetattr(self.stdin, OptionalActions::Now, &hidden).map_err(io::Error::from)
    }

    fn restore(&mut self, saved: &Self::Saved) -> io::Result<()> {
        tcsetattr(self.stdin, OptionalActions::Now, saved).map_err(io::Error::from)
    }
}

struct TerminalSession<'a, T: TerminalSettings> {
    terminal: &'a mut T,
    saved: Option<T::Saved>,
}

impl<'a, T: TerminalSettings> TerminalSession<'a, T> {
    fn enter(terminal: &'a mut T) -> Result<Self, CliError> {
        let saved = terminal.snapshot().map_err(|source| CliError::TerminalSettings {
            operation: "read settings",
            source,
            restore: None,
        })?;
        let mut session = Self {
            terminal,
            saved: Some(saved),
        };
        if let Err(source) = session
            .terminal
            .disable_echo(session.saved.as_ref().expect("terminal settings were saved"))
        {
            let restore = session.restore().err();
            return Err(CliError::TerminalSettings {
                operation: "disable echo",
                source,
                restore,
            });
        }
        Ok(session)
    }

    fn restore(&mut self) -> io::Result<()> {
        let Some(saved) = &self.saved else {
            return Ok(());
        };
        self.terminal.restore(saved)?;
        self.saved = None;
        Ok(())
    }
}

impl<T: TerminalSettings> Drop for TerminalSession<'_, T> {
    fn drop(&mut self) {
        if let Some(saved) = &self.saved {
            let _ = self.terminal.restore(saved);
        }
    }
}

struct SignalHandlers {
    previous: Vec<(i32, usize)>,
}

impl SignalHandlers {
    fn install() -> Result<Self, CliError> {
        PENDING_SIGNAL.store(0, Ordering::Relaxed);
        let mut handlers = Self {
            previous: Vec::new(),
        };
        for signal_number in [1, 2, 3, 15] {
            let previous = unsafe {
                signal(
                    signal_number,
                    remember_signal as *const () as usize,
                )
            };
            if previous == usize::MAX {
                let source = io::Error::last_os_error();
                let restore = handlers.restore().err();
                return Err(CliError::SignalSetup { source, restore });
            }
            handlers.previous.push((signal_number, previous));
            if unsafe { siginterrupt(signal_number, 1) } == -1 {
                let source = io::Error::last_os_error();
                let restore = handlers.restore().err();
                return Err(CliError::SignalSetup { source, restore });
            }
        }
        Ok(handlers)
    }

    fn restore(&mut self) -> io::Result<()> {
        let mut first_error = None;
        let mut pending = Vec::new();
        for (signal_number, previous) in self.previous.drain(..).rev() {
            if unsafe { signal(signal_number, previous) } == usize::MAX {
                pending.push((signal_number, previous));
                if first_error.is_none() {
                    first_error = Some(io::Error::last_os_error());
                }
            }
        }
        pending.reverse();
        self.previous = pending;
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

impl Drop for SignalHandlers {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

fn strip_trailing_newline(value: &mut String) {
    if value.ends_with('\n') {
        value.pop();
    }
    if value.ends_with('\r') {
        value.pop();
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CliError, EnvSpec, TerminalSettings, cmd_purge_with, parse_env_spec, parse_exec_args,
        persist_secret, read_without_echo, run_child,
    };
    use std::io::{self, Cursor, Read, Write};

    struct FakeTerminal {
        echo_enabled: bool,
        snapshot_error: bool,
        disable_error: bool,
        restore_error: bool,
        restores: usize,
    }

    impl FakeTerminal {
        fn ready() -> Self {
            Self {
                echo_enabled: true,
                snapshot_error: false,
                disable_error: false,
                restore_error: false,
                restores: 0,
            }
        }
    }

    impl TerminalSettings for FakeTerminal {
        type Saved = bool;

        fn snapshot(&mut self) -> io::Result<Self::Saved> {
            if self.snapshot_error {
                Err(io::Error::other("snapshot failure"))
            } else {
                Ok(self.echo_enabled)
            }
        }

        fn disable_echo(&mut self, _saved: &Self::Saved) -> io::Result<()> {
            if self.disable_error {
                Err(io::Error::other("disable failure"))
            } else {
                self.echo_enabled = false;
                Ok(())
            }
        }

        fn restore(&mut self, saved: &Self::Saved) -> io::Result<()> {
            self.restores += 1;
            if self.restore_error {
                Err(io::Error::other("restore failure"))
            } else {
                self.echo_enabled = *saved;
                Ok(())
            }
        }
    }

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("read failure"))
        }
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("feedback failure"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn env_spec_requires_nonempty_name_and_one_equals_sign() {
        assert!(matches!(
            parse_env_spec("NAME="),
            EnvSpec::Literal {
                name: "NAME",
                value: ""
            }
        ));
        assert!(matches!(parse_env_spec("=VALUE"), EnvSpec::Keychain("=VALUE")));
        assert!(matches!(parse_env_spec("A=B=C"), EnvSpec::Keychain("A=B=C")));
        assert!(matches!(parse_env_spec("NAME"), EnvSpec::Keychain("NAME")));
    }

    #[test]
    fn exec_parser_rejects_missing_separator_and_command() {
        let no_separator = vec!["NAME=value".to_owned(), "command".to_owned()];
        assert!(matches!(
            parse_exec_args(&no_separator),
            Err(CliError::InvalidInput(message)) if message.contains("expected '--'")
        ));
        let no_command = vec!["NAME=value".to_owned(), "--".to_owned()];
        assert!(matches!(
            parse_exec_args(&no_command),
            Err(CliError::InvalidInput(message)) if message.contains("missing command")
        ));
    }

    #[test]
    fn purge_rejects_extra_args_before_calling_storage() {
        let mut called = false;
        let args = vec!["EXTRA".to_owned()];
        let error = cmd_purge_with(&args, || {
            called = true;
            Ok(0)
        })
        .unwrap_err();
        assert!(matches!(error, CliError::InvalidInput(message) if message.contains("purge takes no arguments")));
        assert!(!called);
    }

    #[test]
    fn child_environment_overrides_do_not_mutate_the_parent() {
        let name = "VAULT_TEST_PARENT_ENV";
        let before = std::env::var_os(name);
        let args = vec![
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            format!("test \"${name}\" = child-value"),
        ];
        let environment = [(name.to_owned(), "child-value".to_owned())];
        assert_eq!(run_child(&args, &environment).unwrap(), std::process::ExitCode::SUCCESS);
        assert_eq!(std::env::var_os(name), before);
    }

    #[test]
    fn terminal_input_is_silent_and_restores_echo() {
        let mut terminal = FakeTerminal::ready();
        let mut input = Cursor::new(b"secret\n".to_vec());
        let mut feedback = Vec::new();
        let value = read_without_echo(&mut input, &mut feedback, true, &mut terminal, || None)
            .unwrap();
        assert_eq!(value, "secret");
        assert!(feedback.is_empty());
        assert!(terminal.echo_enabled);
        assert_eq!(terminal.restores, 1);
    }

    #[test]
    fn terminal_input_rejects_invalid_utf8_after_restoration() {
        let mut terminal = FakeTerminal::ready();
        let mut input = Cursor::new(vec![0xc3, 0x28, b'\n']);
        let error = read_without_echo(&mut input, &mut Vec::new(), true, &mut terminal, || None)
            .unwrap_err();
        assert!(matches!(error, CliError::InvalidUtf8));
        assert!(terminal.echo_enabled);
    }

    #[test]
    fn terminal_settings_failures_are_reported_and_restoration_is_attempted() {
        let mut get_failure = FakeTerminal::ready();
        get_failure.snapshot_error = true;
        let error = read_without_echo(
            &mut Cursor::new(b"secret\n"),
            &mut Vec::new(),
            true,
            &mut get_failure,
            || None,
        )
        .unwrap_err();
        assert!(matches!(error, CliError::TerminalSettings { operation: "read settings", .. }));
        assert_eq!(get_failure.restores, 0);

        let mut set_failure = FakeTerminal::ready();
        set_failure.disable_error = true;
        let error = read_without_echo(
            &mut Cursor::new(b"secret\n"),
            &mut Vec::new(),
            true,
            &mut set_failure,
            || None,
        )
        .unwrap_err();
        assert!(matches!(error, CliError::TerminalSettings { operation: "disable echo", .. }));
        assert_eq!(set_failure.restores, 1);

        let mut restore_failure = FakeTerminal::ready();
        restore_failure.restore_error = true;
        let error = read_without_echo(
            &mut Cursor::new(b"secret\n"),
            &mut Vec::new(),
            true,
            &mut restore_failure,
            || None,
        )
        .unwrap_err();
        assert!(matches!(error, CliError::TerminalSettings { operation: "restore settings", .. }));
        assert!(restore_failure.restores >= 1);
    }

    #[test]
    fn terminal_read_failure_restores_echo() {
        let mut terminal = FakeTerminal::ready();
        let error = read_without_echo(
            &mut FailingReader,
            &mut Vec::new(),
            true,
            &mut terminal,
            || None,
        )
        .unwrap_err();
        assert!(matches!(error, CliError::Io { operation: "read terminal input", .. }));
        assert!(terminal.echo_enabled);
        assert_eq!(terminal.restores, 1);
    }

    #[test]
    fn terminal_read_and_restore_failures_are_both_reported() {
        let mut terminal = FakeTerminal::ready();
        terminal.restore_error = true;
        let error = read_without_echo(
            &mut FailingReader,
            &mut Vec::new(),
            true,
            &mut terminal,
            || None,
        )
        .unwrap_err();
        assert!(matches!(error, CliError::TerminalReadAndRestore { .. }));

        let mut terminal = FakeTerminal::ready();
        terminal.restore_error = true;
        let error = read_without_echo(
            &mut Cursor::new(b"secret\n"),
            &mut FailingWriter,
            false,
            &mut terminal,
            || None,
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("write terminal feedback"));
        assert!(message.contains("terminal restoration also failed"));
    }

    #[test]
    fn terminal_interrupt_restores_echo() {
        let mut terminal = FakeTerminal::ready();
        let error = read_without_echo(
            &mut Cursor::new(b"secret\n"),
            &mut Vec::new(),
            true,
            &mut terminal,
            || Some(2),
        )
        .unwrap_err();
        assert!(matches!(error, CliError::Interrupted(2)));
        assert!(terminal.echo_enabled);
    }

    #[test]
    fn failed_terminal_restoration_prevents_storage() {
        let mut stored = false;
        let error = persist_secret(
            "NAME",
            Err(CliError::TerminalSettings {
                operation: "restore settings",
                source: io::Error::other("restore failure"),
                restore: None,
            }),
            |_, _| {
                stored = true;
                Ok(())
            },
        )
        .unwrap_err();
        assert!(matches!(error, CliError::TerminalSettings { .. }));
        assert!(!stored);
    }
}
