use rustix::termios::{LocalModes, OptionalActions, Termios, tcgetattr, tcsetattr};
use std::fmt;
use std::io::{self, Read, Write};
use std::os::fd::AsFd;
use std::process::{Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};
use age::secrecy::SecretString;
use zeroize::{Zeroize, Zeroizing};
use crate::store::MAX_SECRET_BYTES;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
mod secure_enclave;

mod store;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
use crate::linux as storage;

use std::fs::OpenOptions;

#[cfg(target_os = "macos")]
use crate::macos as storage;

const USAGE_HEADER: &str = "\
  vault — secret manager

Usage:

  vault set   <NAME>            Store a secret (prompts for value)
  vault isset <NAME>            Store a secret (silent, no prompt)
  vault get   <NAME>            Print a secret to stdout
  vault rm    <NAME>            Delete a secret
  vault ls                      List all stored secret names
  vault purge                   Delete every secret vault manages
";

#[cfg(target_os = "linux")]
const PLATFORM_USAGE: &str = "  vault lock                    Remove this store's cached identity\n";

#[cfg(target_os = "macos")]
const PLATFORM_USAGE: &str = "  vault recover                 Rewrap the age identity with a new Secure Enclave key\n";

const USAGE_FOOTER: &str = "\
\n\
  vault [ENV ...] -- <CMD> [ARGS ...]   Run CMD with secrets injected

Environment specifications before -- may be:

  KEY                          Look up KEY in the vault
  KEY=VALUE                    Pass literal KEY=VALUE

Examples:

  vault set OPENAI_API_KEY
  vault OPENAI_API_KEY DATABASE_URL RUST_LOG=debug -- cargo run
  vault -- cargo run
";

#[cfg(target_os = "macos")]
const STORAGE_WARNING: &str = concat!(
    "macOS storage: new secrets use an age store protected by Secure Enclave hardware (macOS 10.15+). ",
    "Existing Keychain items remain in compatibility mode until replaced with 'vault set'. ",
    "Their userPresence enforcement is unverified; an isolated file-Keychain item was readable without interaction. ",
    "The recovery identity uses a separate passphrase. Device-owner authentication may use Touch ID or the Mac password.\n",
);

#[cfg(target_os = "linux")]
const STORAGE_WARNING: &str = "";

static PENDING_SIGNAL: AtomicI32 = AtomicI32::new(0);
#[cfg(target_os = "linux")]
const SIG_TSTP: i32 = 20;
#[cfg(target_os = "macos")]
const SIG_TSTP: i32 = 18;

unsafe extern "C" {
    fn raise(signal: i32) -> i32;
    fn signal(signal: i32, handler: usize) -> usize;
    fn siginterrupt(signal: i32, interrupt: i32) -> i32;
}

extern "C" fn remember_signal(signal: i32) {
    PENDING_SIGNAL.store(signal, Ordering::Relaxed);
}

#[derive(Debug)]
enum CliError {
    InvalidInput(String),
    Storage(String),
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
    TerminalReadAndPromptOutput {
        read: Box<CliError>,
        output: io::Error,
    },
    SignalSetup {
        source: io::Error,
        restore: Option<io::Error>,
    },
    SignalRestore(io::Error),
    SignalSuspend(io::Error),
    InvalidUtf8,
    Interrupted(i32),
    InputTooLarge(usize),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(message) | Self::Storage(message) => f.write_str(message),
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
            Self::TerminalReadAndPromptOutput { read, output } => {
                write!(f, "vault: {read}; passphrase prompt output also failed: {output}")
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
            Self::SignalSuspend(source) => {
                write!(f, "vault: failed to suspend for terminal job control: {source}")
            }
            Self::InvalidUtf8 => f.write_str("vault: failed to read input: invalid UTF-8"),
            Self::Interrupted(_) => f.write_str("vault: input interrupted"),
            Self::InputTooLarge(limit) => {
                if limit % (1024 * 1024) == 0 {
                    write!(f, "vault: input exceeds {} MiB limit", limit / (1024 * 1024))
                } else {
                    write!(f, "vault: input exceeds {limit} byte limit")
                }
            }
        }
    }
}

impl std::error::Error for CliError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. }
            | Self::Spawn(source)
            | Self::SignalRestore(source)
            | Self::SignalSuspend(source) => Some(source),
            Self::Wait { source, .. } => Some(source),
            Self::TerminalSettings { source, .. } => Some(source),
            Self::TerminalReadAndRestore { read, .. } => Some(read),
            Self::TerminalReadAndPromptOutput { read, .. } => Some(read),
            Self::SignalSetup { source, .. } => Some(source),
            Self::InvalidInput(_)
            | Self::Storage(_)
            | Self::InvalidUtf8
            | Self::InputTooLarge(_)
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
        write_usage()?;
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
        #[cfg(target_os = "linux")]
        "lock" => {
            cmd_lock(&args[1..])?;
            Ok(ExitCode::SUCCESS)
        }
        #[cfg(target_os = "macos")]
        "recover" => {
            cmd_recover(&args[1..])?;
            Ok(ExitCode::SUCCESS)
        }
        "-h" | "--help" | "help" => {
            write_usage()?;
            Ok(ExitCode::SUCCESS)
        }
        _ => exec_mode(args),
    }
}

fn write_usage() -> Result<(), CliError> {
    write_stdout(USAGE_HEADER.as_bytes())?;
    write_stdout(PLATFORM_USAGE.as_bytes())?;
    write_stdout(USAGE_FOOTER.as_bytes())?;
    write_stdout(STORAGE_WARNING.as_bytes())
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
    #[cfg(target_os = "linux")]
    crate::store::validate_name(name).map_err(CliError::InvalidInput)?;
    let value = read_secret(name, silent)?;
    persist_secret(name, Ok(value), store_secret)
}

#[cfg(target_os = "macos")]
fn store_secret(name: &str, value: &[u8]) -> Result<(), String> {
    storage::set_secret(name, value, prompt_recovery_passphrase)
}

#[cfg(target_os = "linux")]
fn store_secret(name: &str, value: &[u8]) -> Result<(), String> {
    storage::set_secret(name, value, prompt_master_passphrase)
}

fn persist_secret(
    name: &str,
    read_value: Result<String, CliError>,
    store: impl FnOnce(&str, &[u8]) -> Result<(), String>,
) -> Result<(), CliError> {
    let value = read_value?;
    let result = store(name, value.as_bytes());
    let mut value = value;
    value.zeroize();
    result.map_err(CliError::Storage)
}

fn cmd_get(args: &[String]) -> Result<(), CliError> {
    let name = require_exact_name(args, "get")?;
    let value = get_secret(name)?;
    let result = write_stdout(value.as_bytes()).and_then(|()| write_stdout(b"\n"));
    let mut value = value;
    value.zeroize();
    result
}

#[cfg(target_os = "macos")]
fn get_secret(name: &str) -> Result<String, CliError> {
    storage::get_secret(name).map_err(CliError::Storage)
}

#[cfg(target_os = "linux")]
fn get_secret(name: &str) -> Result<String, CliError> {
    storage::get_secret(name, prompt_master_passphrase, report_identity_cache_warning)
        .map_err(CliError::Storage)
}

fn cmd_rm(args: &[String]) -> Result<(), CliError> {
    let name = require_exact_name(args, "rm")?;
    storage::delete_secret(name).map_err(CliError::Storage)
}

fn cmd_ls(args: &[String]) -> Result<(), CliError> {
    require_no_args(args, "ls")?;
    for name in storage::list_secrets().map_err(CliError::Storage)? {
        write_stdout(name.as_bytes())?;
        write_stdout(b"\n")?;
    }
    Ok(())
}

fn cmd_purge(args: &[String]) -> Result<(), CliError> {
    cmd_purge_with(args, storage::purge_secrets)
}

#[cfg(target_os = "linux")]
fn cmd_lock(args: &[String]) -> Result<(), CliError> {
    require_no_args(args, "lock")?;
    match storage::clear_identity_cache().map_err(CliError::Storage)? {
        linux::CacheClearResult::Cleared => write_stdout(b"identity cache cleared\n"),
        linux::CacheClearResult::AlreadyClear => write_stdout(b"identity cache already clear\n"),
    }
}

#[cfg(target_os = "macos")]
fn cmd_recover(args: &[String]) -> Result<(), CliError> {
    require_no_args(args, "recover")?;
    storage::recover(prompt_recovery_passphrase).map_err(CliError::Storage)?;
    write_stdout(b"Secure Enclave identity recovered\n")
}

fn cmd_purge_with(
    args: &[String],
    purge: impl FnOnce() -> Result<usize, String>,
) -> Result<(), CliError> {
    require_no_args(args, "purge")?;
    match purge().map_err(CliError::Storage)? {
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
    Secret(&'a str),
}

fn parse_env_spec(spec: &str) -> EnvSpec<'_> {
    if let Some((name, value)) = spec.split_once('=')
        && !name.is_empty()
        && !value.contains('=')
    {
        return EnvSpec::Literal { name, value };
    }
    EnvSpec::Secret(spec)
}

enum ExecEnv<'a> {
    Literal(String, String),
    Secret(&'a str),
}

#[cfg(target_os = "macos")]
fn get_secrets(names: &[&str]) -> Result<Vec<String>, CliError> {
    storage::get_secrets(names).map_err(CliError::Storage)
}

#[cfg(target_os = "linux")]
fn get_secrets(names: &[&str]) -> Result<Vec<String>, CliError> {
    if names.is_empty() {
        return Ok(Vec::new());
    }
    storage::get_secrets(names, prompt_master_passphrase, report_identity_cache_warning)
        .map_err(CliError::Storage)
}

#[cfg(target_os = "linux")]
fn prompt_master_passphrase(prompt: linux::PassphrasePrompt) -> Result<SecretString, String> {
    read_passphrase(prompt.prompt(), "master").map_err(|error| error.to_string())
}

#[cfg(target_os = "macos")]
fn prompt_recovery_passphrase(prompt: macos::RecoveryPrompt) -> Result<SecretString, String> {
    read_passphrase(prompt.prompt(), "recovery").map_err(|error| error.to_string())
}

#[cfg(target_os = "linux")]
fn report_identity_cache_warning(message: &str) -> io::Result<()> {
    let mut stderr = io::stderr().lock();
    writeln!(stderr, "vault: {message}")?;
    stderr.flush()
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
    let mut resolved_specs = Vec::with_capacity(specs.len());
    let mut names = Vec::new();
    for spec in specs {
        match parse_env_spec(spec) {
            EnvSpec::Literal { name, value } => {
                resolved_specs.push(ExecEnv::Literal(name.to_owned(), value.to_owned()));
            }
            EnvSpec::Secret(name) => {
                names.push(name);
                resolved_specs.push(ExecEnv::Secret(name));
            }
        }
    }

    let mut values = get_secrets(&names)?.into_iter();
    let mut environment: Vec<_> = resolved_specs
        .into_iter()
        .map(|spec| match spec {
            ExecEnv::Literal(name, value) => (name, value),
            ExecEnv::Secret(name) => (name.to_owned(), values.next().expect("resolved secret")),
        })
        .collect();
    run_child(cmd_args, &mut environment)
}

fn run_child(
    cmd_args: &[String],
    environment: &mut [(String, String)],
) -> Result<ExitCode, CliError> {
    let mut command = Command::new(&cmd_args[0]);
    command
        .args(&cmd_args[1..])
        .envs(environment.iter().map(|(name, value)| (name, value)))
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    let spawn_result = command.spawn();
    drop(command);
    for (_, value) in environment {
        value.zeroize();
    }
    let mut child = spawn_result.map_err(CliError::Spawn)?;
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
        let mut terminal = TerminalFd { fd: &stdin };
        let read_result = read_without_echo(
            &mut stdin.lock(),
            &mut io::stderr().lock(),
            silent,
            MAX_SECRET_BYTES,
            &mut terminal,
            || {
                let signal = PENDING_SIGNAL.load(Ordering::Relaxed);
                (signal != 0).then_some(signal)
            },
            || signals.suspend_and_resume(),
        );
        if read_result.is_ok() && PENDING_SIGNAL.load(Ordering::Relaxed) == SIG_TSTP {
            signals.suspend_and_resume()?;
        }
        let signal_restore = signals.restore();
        if let Err(source) = signal_restore {
            return Err(CliError::SignalRestore(source));
        }
        if PENDING_SIGNAL.load(Ordering::Relaxed) == SIG_TSTP {
            signals.suspend_and_resume()?;
            signals.restore().map_err(CliError::SignalRestore)?;
        }
        let mut value = read_result?;
        let signal = PENDING_SIGNAL.load(Ordering::Relaxed);
        if signal != 0 {
            value.zeroize();
            return Err(CliError::Interrupted(signal));
        }
        Ok(value)
    } else {
        read_limited_utf8(stdin.lock(), MAX_SECRET_BYTES)
    }
}

fn read_limited_utf8(reader: impl Read, limit: usize) -> Result<String, CliError> {
    let read_limit = limit.saturating_add(3) as u64;
    let mut bytes = Zeroizing::new(Vec::new());
    reader
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|source| CliError::Io {
            operation: "read stdin",
            source,
        })?;
    if bytes.ends_with(b"\n") {
        bytes.pop();
        if bytes.ends_with(b"\r") {
            bytes.pop();
        }
    } else if bytes.ends_with(b"\r") {
        bytes.pop();
    }
    if bytes.len() > limit {
        return Err(CliError::InputTooLarge(limit));
    }
    match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(value) => Ok(value),
        Err(error) => {
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            Err(CliError::InvalidUtf8)
        }
    }
}

fn read_passphrase(prompt: &str, passphrase_kind: &str) -> Result<SecretString, CliError> {
    let mut tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| {
            CliError::InvalidInput(
                format!("vault: a controlling terminal is required to enter the {passphrase_kind} passphrase"),
            )
        })?;
    if !rustix::termios::isatty(&tty) {
        return Err(CliError::InvalidInput(
            format!("vault: a controlling terminal is required to enter the {passphrase_kind} passphrase"),
        ));
    }

    let mut output = tty.try_clone().map_err(|source| CliError::Io {
        operation: "open controlling terminal for passphrase prompt",
        source,
    })?;
    output
        .write_all(prompt.as_bytes())
        .and_then(|()| output.flush())
        .map_err(|source| CliError::Io {
            operation: "write passphrase prompt",
            source,
        })?;

    let terminal_fd = tty.try_clone().map_err(|source| CliError::Io {
        operation: "open controlling terminal for terminal settings",
        source,
    })?;
    let mut signals = SignalHandlers::install()?;
    let mut terminal = TerminalFd { fd: &terminal_fd };
    let read_result = read_without_echo(
        &mut tty,
        &mut output,
        true,
        MAX_SECRET_BYTES,
        &mut terminal,
        || {
            let signal = PENDING_SIGNAL.load(Ordering::Relaxed);
            (signal != 0).then_some(signal)
        },
        || signals.suspend_and_resume(),
    );
    let signal_restore = signals.restore();
    let newline_result = output.write_all(b"\n").and_then(|()| output.flush());
    if let Err(source) = signal_restore {
        if let Ok(mut value) = read_result {
            value.zeroize();
        }
        return Err(CliError::SignalRestore(source));
    }
    if PENDING_SIGNAL.load(Ordering::Relaxed) == SIG_TSTP {
        signals.suspend_and_resume()?;
        signals.restore().map_err(CliError::SignalRestore)?;
    }
    let pending_signal = PENDING_SIGNAL.load(Ordering::Relaxed);
    if pending_signal != 0 {
        if let Ok(mut value) = read_result {
            value.zeroize();
        }
        return Err(CliError::Interrupted(pending_signal));
    }
    let value = match (read_result, newline_result) {
        (Ok(value), Ok(())) => value,
        (Err(error), Ok(())) => return Err(error),
        (Ok(mut value), Err(source)) => {
            value.zeroize();
            return Err(CliError::Io {
                operation: "write passphrase prompt",
                source,
            });
        }
        (Err(read), Err(source)) => {
            return Err(CliError::TerminalReadAndPromptOutput {
                read: Box::new(read),
                output: source,
            });
        }
    };
    Ok(SecretString::from(value))
}

#[derive(Clone, Copy)]
enum TerminalRead {
    Complete,
    Suspended,
}

fn read_without_echo<R, W, T, I, S>(
    input: &mut R,
    feedback: &mut W,
    silent: bool,
    max_bytes: usize,
    terminal: &mut T,
    mut interrupted: I,
    mut suspend: S,
) -> Result<String, CliError>
where
    R: Read,
    W: Write,
    T: TerminalSettings,
    I: FnMut() -> Option<i32>,
    S: FnMut() -> Result<(), CliError>,
{
    let mut value = Zeroizing::new(Vec::new());
    loop {
        let mut session = TerminalSession::enter(terminal)?;
        let read_result = read_terminal_line(
            input,
            feedback,
            silent,
            &mut value,
            max_bytes,
            &mut interrupted,
        );
        let restore_result = session
            .restore()
            .map_err(|source| CliError::TerminalSettings {
                operation: "restore settings",
                source,
                restore: None,
            });
        let state = match (read_result, restore_result) {
            (Ok(state), Ok(())) => state,
            (Err(error), Ok(())) => return Err(error),
            (Ok(_), Err(error)) => return Err(error),
            (Err(read), Err(restore)) => {
                return Err(CliError::TerminalReadAndRestore {
                    read: Box::new(read),
                    restore: Box::new(restore),
                });
            }
        };
        match state {
            TerminalRead::Complete => {
                if interrupted() == Some(SIG_TSTP) {
                    suspend()?;
                }
                break;
            }
            TerminalRead::Suspended => suspend()?,
        }
    }
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
    match String::from_utf8(std::mem::take(&mut *value)) {
        Ok(value) => Ok(value),
        Err(error) => {
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            Err(CliError::InvalidUtf8)
        }
    }
}

fn read_terminal_line<R, W, I>(
    input: &mut R,
    feedback: &mut W,
    silent: bool,
    value: &mut Vec<u8>,
    max_bytes: usize,
    interrupted: &mut I,
) -> Result<TerminalRead, CliError>
where
    R: Read,
    W: Write,
    I: FnMut() -> Option<i32>,
{
    let mut byte = [0u8; 1];
    loop {
        if let Some(signal) = interrupted() {
            if signal == SIG_TSTP {
                return Ok(TerminalRead::Suspended);
            }
            return Err(CliError::Interrupted(signal));
        }
        match input.read(&mut byte) {
            Ok(0) => return Ok(TerminalRead::Complete),
            Ok(_) => {
                match byte[0] {
                    b'\n' | b'\r' => return Ok(TerminalRead::Complete),
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
                        if value.len() >= max_bytes {
                            return Err(CliError::InputTooLarge(max_bytes));
                        }
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
                    if signal == SIG_TSTP {
                        return Ok(TerminalRead::Suspended);
                    }
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

struct TerminalFd<'a, Fd: AsFd> {
    fd: &'a Fd,
}

impl<Fd: AsFd> TerminalSettings for TerminalFd<'_, Fd> {
    type Saved = Termios;

    fn snapshot(&mut self) -> io::Result<Self::Saved> {
        tcgetattr(self.fd).map_err(io::Error::from)
    }

    fn disable_echo(&mut self, saved: &Self::Saved) -> io::Result<()> {
        let mut hidden = saved.clone();
        hidden.local_modes &= !(LocalModes::ECHO | LocalModes::ECHONL | LocalModes::ICANON);
        tcsetattr(self.fd, OptionalActions::Now, &hidden).map_err(io::Error::from)
    }

    fn restore(&mut self, saved: &Self::Saved) -> io::Result<()> {
        tcsetattr(self.fd, OptionalActions::Now, saved).map_err(io::Error::from)
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
        for signal_number in [1, 2, 3, 15, SIG_TSTP] {
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

    fn suspend_and_resume(&mut self) -> Result<(), CliError> {
        self.restore().map_err(CliError::SignalRestore)?;
        PENDING_SIGNAL.store(0, Ordering::Relaxed);
        if unsafe { raise(SIG_TSTP) } != 0 {
            return Err(CliError::SignalSuspend(io::Error::last_os_error()));
        }
        *self = Self::install()?;
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::{
        CliError, EnvSpec, MAX_SECRET_BYTES, TerminalSettings, cmd_purge_with, parse_env_spec,
        parse_exec_args, persist_secret, read_limited_utf8, read_without_echo, run_child,
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

    struct RepeatingReader {
        remaining: usize,
        bytes_read: usize,
    }

    impl Read for RepeatingReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let count = self.remaining.min(buffer.len());
            buffer[..count].fill(b'x');
            self.remaining -= count;
            self.bytes_read += count;
            Ok(count)
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
        assert!(matches!(parse_env_spec("=VALUE"), EnvSpec::Secret("=VALUE")));
        assert!(matches!(parse_env_spec("A=B=C"), EnvSpec::Secret("A=B=C")));
        assert!(matches!(parse_env_spec("NAME"), EnvSpec::Secret("NAME")));
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
        let mut environment = [(name.to_owned(), "child-value".to_owned())];
        assert_eq!(run_child(&args, &mut environment).unwrap(), std::process::ExitCode::SUCCESS);
        assert_eq!(std::env::var_os(name), before);
    }

    #[test]
    fn terminal_input_is_silent_and_restores_echo() {
        let mut terminal = FakeTerminal::ready();
        let mut input = Cursor::new(b"secret\n".to_vec());
        let mut feedback = Vec::new();
        let value = read_without_echo(
            &mut input,
            &mut feedback,
            true,
            MAX_SECRET_BYTES,
            &mut terminal,
            || None,
            || Ok(()),
        )
        .unwrap();
        assert_eq!(value, "secret");
        assert!(feedback.is_empty());
        assert!(terminal.echo_enabled);
        assert_eq!(terminal.restores, 1);
    }

    #[test]
    fn piped_input_is_bounded_and_accepts_the_exact_limit_with_line_endings() {
        for input in [b"abc".as_slice(), b"abc\n", b"abc\r", b"abc\r\n"] {
            assert_eq!(read_limited_utf8(input, 3).unwrap(), "abc");
        }

        let mut input = RepeatingReader {
            remaining: 100,
            bytes_read: 0,
        };
        assert!(matches!(read_limited_utf8(&mut input, 3), Err(CliError::InputTooLarge(3))));
        assert_eq!(input.bytes_read, 6);

        let input = vec![b'x'; MAX_SECRET_BYTES + 1];
        assert!(matches!(
            read_limited_utf8(&input[..], MAX_SECRET_BYTES),
            Err(CliError::InputTooLarge(MAX_SECRET_BYTES))
        ));
    }

    #[test]
    fn terminal_input_limit_restores_echo_and_accepts_the_exact_boundary() {
        let mut terminal = FakeTerminal::ready();
        let mut input = Cursor::new(b"abc\n".to_vec());
        assert_eq!(
            read_without_echo(
                &mut input,
                &mut Vec::new(),
                true,
                3,
                &mut terminal,
                || None,
                || Ok(()),
            )
            .unwrap(),
            "abc"
        );
        assert!(terminal.echo_enabled);

        let mut terminal = FakeTerminal::ready();
        let mut feedback = Vec::new();
        let error = read_without_echo(
            &mut Cursor::new(b"abcd\n"),
            &mut feedback,
            false,
            3,
            &mut terminal,
            || None,
            || Ok(()),
        )
        .unwrap_err();
        assert!(matches!(error, CliError::InputTooLarge(3)));
        assert!(terminal.echo_enabled);
        assert_eq!(terminal.restores, 1);
        assert_eq!(feedback, b"***");
    }

    #[test]
    fn terminal_input_rejects_invalid_utf8_after_restoration() {
        let mut terminal = FakeTerminal::ready();
        let mut input = Cursor::new(vec![0xc3, 0x28, b'\n']);
        let error = read_without_echo(
            &mut input,
            &mut Vec::new(),
            true,
            MAX_SECRET_BYTES,
            &mut terminal,
            || None,
            || Ok(()),
        )
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
            MAX_SECRET_BYTES,
            &mut get_failure,
            || None,
            || Ok(()),
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
            MAX_SECRET_BYTES,
            &mut set_failure,
            || None,
            || Ok(()),
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
            MAX_SECRET_BYTES,
            &mut restore_failure,
            || None,
            || Ok(()),
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
            MAX_SECRET_BYTES,
            &mut terminal,
            || None,
            || Ok(()),
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
            MAX_SECRET_BYTES,
            &mut terminal,
            || None,
            || Ok(()),
        )
        .unwrap_err();
        assert!(matches!(error, CliError::TerminalReadAndRestore { .. }));

        let mut terminal = FakeTerminal::ready();
        terminal.restore_error = true;
        let error = read_without_echo(
            &mut Cursor::new(b"secret\n"),
            &mut FailingWriter,
            false,
            MAX_SECRET_BYTES,
            &mut terminal,
            || None,
            || Ok(()),
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
            MAX_SECRET_BYTES,
            &mut terminal,
            || Some(2),
            || Ok(()),
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
