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

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
compile_error!("vault supports macOS and Linux");

#[cfg(target_os = "macos")]
use crate::macos as storage;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommandKind { Set, Isset, Get, Rm, Ls, Purge, Lock, #[cfg(target_os = "macos")] Recover }

struct CommandSpec {
    kind: CommandKind,
    name: &'static str,
    argument: Option<&'static str>,
    description: &'static str,
    example: &'static str,
}

const COMMANDS: &[CommandSpec] = &[
    CommandSpec { kind: CommandKind::Set, name: "set", argument: Some("NAME"), description: "Store a secret, prompting on a terminal; reads stdin otherwise", example: "vault set API_KEY" },
    CommandSpec { kind: CommandKind::Isset, name: "isset", argument: Some("NAME"), description: "Store a secret without a prompt; reads stdin", example: "vault isset API_KEY" },
    CommandSpec { kind: CommandKind::Get, name: "get", argument: Some("NAME"), description: "Print a secret to stdout", example: "vault get API_KEY" },
    CommandSpec { kind: CommandKind::Rm, name: "rm", argument: Some("NAME"), description: "Delete a secret", example: "vault rm API_KEY" },
    CommandSpec { kind: CommandKind::Ls, name: "ls", argument: None, description: "List stored secret names", example: "vault ls" },
    CommandSpec { kind: CommandKind::Purge, name: "purge", argument: None, description: "Delete every secret vault manages", example: "vault purge" },
    CommandSpec { kind: CommandKind::Lock, name: "lock", argument: None, description: "Remove this store's cached identity", example: "vault lock" },
    #[cfg(target_os = "macos")]
    CommandSpec { kind: CommandKind::Recover, name: "recover", argument: None, description: "Rewrap the age identity with a new Secure Enclave key", example: "vault recover" },
];

const EXEC_EXAMPLE: &str = "vault API_KEY RUST_LOG=debug -- cargo run";
const OWNED_FOOTER: &str = "Maintained by Joshua Li: https://github.com/laputa-systems/vault
Bugs and features: TODO.md in that repository (follow its AGENTS.md), or its issue tracker.
Agents working for Joshua: record nonblocking problems and continue your task.
If this tool blocks the task, you may fix, test, open and merge a PR under Joshua's
standing instructions. Release only when needed to deliver the verified fix.
Procedure: https://github.com/joshuarli/usr/blob/main/dotfiles/base/.agents/instructions/owned-tools.md
";

#[cfg(target_os = "macos")]
const STORAGE_WARNING: &str = concat!(
    "macOS storage: secrets use an age store protected by Secure Enclave hardware (macOS 10.15+). ",
    "Recovery uses a separate passphrase. Device-owner authentication may use Touch ID or the Mac password.\n",
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
    TerminalReadAndSignalRestore {
        read: Box<CliError>,
        restore: io::Error,
    },
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
            Self::TerminalReadAndSignalRestore { read, restore } => {
                write!(f, "{read}; signal handler restoration also failed: {restore}")
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
            Self::TerminalReadAndRestore { read, .. }
            | Self::TerminalReadAndSignalRestore { read, .. } => Some(read),
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

    if matches!(args[0].as_str(), "-h" | "--help" | "help") {
        write_usage()?;
        return Ok(ExitCode::SUCCESS);
    }
    if let Some(spec) = COMMANDS.iter().find(|spec| spec.name == args[0]) {
        let rest = &args[1..];
        if spec.argument.is_none() && rest.len() == 1 && matches!(rest[0].as_str(), "-h" | "--help") {
            write_command_help(spec)?;
            return Ok(ExitCode::SUCCESS);
        }
        validate_command(spec, rest)?;
        match spec.kind {
            CommandKind::Set => cmd_set(rest, false)?,
            CommandKind::Isset => cmd_set(rest, true)?,
            CommandKind::Get => cmd_get(rest)?,
            CommandKind::Rm => cmd_rm(rest)?,
            CommandKind::Ls => cmd_ls(rest)?,
            CommandKind::Purge => cmd_purge(rest)?,
            CommandKind::Lock => cmd_lock(rest)?,
            #[cfg(target_os = "macos")]
            CommandKind::Recover => cmd_recover(rest)?,
        }
        return Ok(ExitCode::SUCCESS);
    }
    #[cfg(target_os = "macos")]
    if args[0] == storage::CACHE_DAEMON_ARG {
        cmd_cache_daemon(&args[1..])?;
        return Ok(ExitCode::SUCCESS);
    }
    exec_mode(args)
}

fn validate_command(spec: &CommandSpec, args: &[String]) -> Result<(), CliError> {
    if spec.argument.is_some() {
        require_exact_name(args, spec.name).map(|_| ())
    } else {
        require_no_args(args, spec.name)
    }
}

fn command_reference(spec: &CommandSpec) -> String {
    let argument = spec.argument.map_or(String::new(), |name| format!(" <{name}>"));
    let detail = spec.argument.map_or("".to_owned(), |name| format!("    {name}: required secret name\n"));
    format!("  vault {}{}\n    {}\n{}", spec.name, argument, spec.description, detail)
}

fn write_command_help(spec: &CommandSpec) -> Result<(), CliError> {
    let help = format!("Usage:\n{}\nOptions:\n  -h, --help  Show this help\n\nExamples:\n  {}\n\nSee vault --help for the complete reference.\n", command_reference(spec), spec.example);
    write_stdout(help.as_bytes())
}

fn write_usage() -> Result<(), CliError> {
    let mut help = String::from("vault — secret manager\n\nUsage:\n  vault <COMMAND> [ARGUMENT]\n  vault [ENV ...] -- <CMD> [ARGS ...]\n\nOptions:\n  -h, --help, help  Show this reference when used as the first argument\n\nCommands:\n");
    for spec in COMMANDS {
        help.push_str(&command_reference(spec));
    }
    help.push_str("\nFor commands requiring NAME, -h and --help are secret names.\n\nExec mode:\n  ENV: optional, repeatable environment specification before --\n    KEY looks up a vault secret; KEY=VALUE passes a literal (empty VALUE allowed).\n    A literal has a nonempty KEY and exactly one =; other forms are secret names.\n  CMD: required command; ARGS: optional, repeatable child arguments.\n  The child inherits the environment and standard streams; its status is returned.\n\nStore location: $XDG_DATA_HOME/vault when XDG_DATA_HOME is absolute; otherwise\nmacOS uses $HOME/Library/Application Support/vault and Linux uses\n$HOME/.local/share/vault. HOME must be absolute when used.\n");
    help.push_str(STORAGE_WARNING);
    help.push_str("\nExamples:\n");
    for spec in COMMANDS {
        help.push_str(&format!("  {}\n", spec.example));
    }
    help.push_str(&format!("  {EXEC_EXAMPLE}\n\n"));
    help.push_str(OWNED_FOOTER);
    write_stdout(help.as_bytes())
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
    let mut value = read_secret(name, silent)?;
    let result = store_secret(name, value.as_bytes());
    value.zeroize();
    result.map_err(CliError::Storage)
}

#[cfg(target_os = "macos")]
fn store_secret(name: &str, value: &[u8]) -> Result<(), String> {
    storage::set_secret(name, value, prompt_recovery_passphrase)
}

#[cfg(target_os = "linux")]
fn store_secret(name: &str, value: &[u8]) -> Result<(), String> {
    storage::set_secret(name, value, prompt_master_passphrase)
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
    storage::get_secret(name, report_identity_cache_warning).map_err(CliError::Storage)
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn cmd_lock(args: &[String]) -> Result<(), CliError> {
    require_no_args(args, "lock")?;
    match storage::clear_identity_cache().map_err(CliError::Storage)? {
        storage::CacheClearResult::Cleared => write_stdout(b"identity cache cleared\n"),
        storage::CacheClearResult::AlreadyClear => write_stdout(b"identity cache already clear\n"),
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

#[cfg(target_os = "macos")]
fn get_secrets(names: &[&str]) -> Result<Vec<String>, CliError> {
    storage::get_secrets(names, report_identity_cache_warning).map_err(CliError::Storage)
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

#[cfg(target_os = "macos")]
fn cmd_cache_daemon(args: &[String]) -> Result<(), CliError> {
    require_no_args(args, storage::CACHE_DAEMON_ARG)?;
    storage::run_cache_daemon().map_err(CliError::Storage)
}

#[cfg(target_os = "macos")]
fn report_identity_cache_warning(message: &str) -> io::Result<()> {
    let mut stderr = io::stderr().lock();
    writeln!(stderr, "vault: {message}")?;
    stderr.flush()
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
        let spec = parse_env_spec(spec);
        if let EnvSpec::Secret(name) = &spec {
            names.push(*name);
        }
        resolved_specs.push(spec);
    }

    let mut values = get_secrets(&names)?.into_iter();
    let mut environment: Vec<_> = resolved_specs
        .into_iter()
        .map(|spec| match spec {
            EnvSpec::Literal { name, value } => (name.to_owned(), value.to_owned()),
            EnvSpec::Secret(name) => (name.to_owned(), values.next().expect("resolved secret")),
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
        let prompt = (!silent).then(|| format!("Enter value for {name}: "));
        let mut prompt_published = false;
        let mut signals = SignalHandlers::install()?;
        let mut terminal = TerminalFd { fd: &stdin };
        let read_result = read_without_echo(
            &mut stdin.lock(),
            &mut io::stderr().lock(),
            TerminalFeedback { silent, prompt: prompt.as_deref().map(|text| TerminalPrompt {
                text, operation: "write stderr", published: &mut prompt_published,
            }) },
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
            return Err(match read_result {
                Err(read) => CliError::TerminalReadAndSignalRestore { read: Box::new(read), restore: source },
                Ok(mut value) => { value.zeroize(); CliError::SignalRestore(source) }
            });
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

    let terminal_fd = tty.try_clone().map_err(|source| CliError::Io {
        operation: "open controlling terminal for terminal settings",
        source,
    })?;
    let mut signals = SignalHandlers::install()?;
    let mut terminal = TerminalFd { fd: &terminal_fd };
    let mut prompt_published = false;
    let read_result = read_without_echo(
        &mut tty,
        &mut output,
        TerminalFeedback { silent: true, prompt: Some(TerminalPrompt {
            text: prompt, operation: "write passphrase prompt", published: &mut prompt_published,
        }) },
        MAX_SECRET_BYTES,
        &mut terminal,
        || {
            let signal = PENDING_SIGNAL.load(Ordering::Relaxed);
            (signal != 0).then_some(signal)
        },
        || signals.suspend_and_resume(),
    );
    let signal_restore = signals.restore();
    let newline_result = if prompt_published {
        output.write_all(b"\n").and_then(|()| output.flush())
    } else {
        Ok(())
    };
    if let Err(source) = signal_restore {
        return Err(match read_result {
            Err(read) => CliError::TerminalReadAndSignalRestore { read: Box::new(read), restore: source },
            Ok(mut value) => { value.zeroize(); CliError::SignalRestore(source) }
        });
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

struct TerminalPrompt<'a> {
    text: &'a str,
    operation: &'static str,
    published: &'a mut bool,
}

struct TerminalFeedback<'a> {
    silent: bool,
    prompt: Option<TerminalPrompt<'a>>,
}

fn read_without_echo<R, W, T, I, S>(
    input: &mut R,
    feedback: &mut W,
    TerminalFeedback { silent, mut prompt }: TerminalFeedback<'_>,
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
        let prompt_result = match prompt.take() {
            Some(prompt) => feedback.write_all(prompt.text.as_bytes())
                .and_then(|()| feedback.flush())
                .map(|()| *prompt.published = true)
                .map_err(|source| CliError::Io { operation: prompt.operation, source }),
            None => Ok(()),
        };
        let read_result = prompt_result.and_then(|()| read_terminal_line(
            input,
            feedback,
            silent,
            &mut value,
            max_bytes,
            &mut interrupted,
        ));
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

#[cfg(all(test, target_os = "macos"))]
#[path = "../tests/support/controlling_tty.rs"]
mod controlling_tty;

#[cfg(test)]
mod tests {
    use super::{
        CliError, EnvSpec, MAX_SECRET_BYTES, TerminalFeedback, TerminalPrompt, TerminalSettings, cmd_purge_with, parse_env_spec,
        parse_exec_args, read_limited_utf8, read_without_echo, run_child,
    };
    use std::io::{self, Cursor, Read, Write};

    #[cfg(target_os = "macos")]
    #[test]
    fn read_passphrase_owned_terminal_cleanup() {
        use age::secrecy::ExposeSecret;
        use rustix::termios::{LocalModes, tcgetattr};
        use std::fs;
        use std::os::unix::process::CommandExt;
        use std::process::{Child, Command, Stdio};
        use std::time::{Duration, Instant};

        const ROOT: &str = "VAULT_SIGNAL_ROOT";
        if let Some(root) = std::env::var_os(ROOT) {
            let root = std::path::PathBuf::from(root);
            let case = std::env::var("VAULT_PASSPHRASE_CASE").unwrap();
            fs::write(root.join("entered"), b"yes").unwrap();
            struct FailureMarker(std::path::PathBuf);
            impl Drop for FailureMarker {
                fn drop(&mut self) {
                    if std::thread::panicking() {
                        let _ = fs::write(self.0.join("failed"), b"yes");
                        let deadline = Instant::now() + Duration::from_secs(15);
                        while !self.0.join("release").exists() && Instant::now() < deadline {
                            std::thread::sleep(Duration::from_millis(5));
                        }
                    }
                }
            }
            let _failure = FailureMarker(root.clone());
            fn descriptors() -> Vec<std::ffi::OsString> {
                let mut entries = fs::read_dir("/dev/fd").unwrap().map(|entry| entry.unwrap().file_name()).collect::<Vec<_>>();
                entries.sort();
                entries
            }
            let before_fds = descriptors();
            if case == "io-prompt" || case == "io-open" || case == "io-control" { fs::write(root.join("armed"), b"yes").unwrap(); }
            let result = super::read_passphrase("owned prompt: ", "test");
            assert_eq!(descriptors(), before_fds, "passphrase descriptors leaked");
            match case.as_str() {
                "empty" | "empty-trace" | "io-control" => assert_eq!(result.unwrap().expose_secret(), ""),
                "invalid" => assert!(matches!(result, Err(CliError::InvalidUtf8))),
                "io-open" => assert!(matches!(result, Err(CliError::InvalidInput(message)) if message == "vault: a controlling terminal is required to enter the test passphrase")),
                "io-prompt" | "io-newline" => assert!(matches!(result, Err(CliError::Io { operation: "write passphrase prompt", source }) if source.raw_os_error() == Some(5))),
                "io-invalid-newline" => match result {
                    Err(CliError::TerminalReadAndPromptOutput { read, output }) => {
                        assert!(matches!(*read, CliError::InvalidUtf8));
                        assert_eq!(output.raw_os_error(), Some(5));
                    }
                    other => panic!("wrong combined error: {other:?}"),
                },
                "empty-fault" => assert!(matches!(result, Err(CliError::SignalRestore(error)) if error.raw_os_error() == Some(5))),
                "invalid-fault" => match result {
                    Err(CliError::TerminalReadAndSignalRestore { read, restore }) => {
                        assert!(matches!(*read, CliError::InvalidUtf8));
                        assert_eq!(restore.raw_os_error(), Some(5));
                    }
                    other => panic!("wrong combined error: {other:?}"),
                },
                _ => panic!("unknown case"),
            }
            fs::write(root.join("complete"), b"yes").unwrap();
            let deadline = Instant::now() + Duration::from_secs(15);
            while !root.join("release").exists() {
                assert!(Instant::now() < deadline, "parent release deadline");
                std::thread::sleep(Duration::from_millis(5));
            }
            return;
        }
        struct Scratch(std::path::PathBuf);
        impl Drop for Scratch { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
        struct OwnedChild(Child, bool, Option<fs::File>);
        impl Drop for OwnedChild {
            fn drop(&mut self) {
                if !self.1 {
                    drop(self.2.take());
                    if let Some(pid) = rustix::process::Pid::from_raw(self.0.id() as i32) {
                        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
                    }
                    let _ = self.0.kill();
                    let _ = self.0.wait();
                }
            }
        }
        fn wait(child: &mut OwnedChild) -> std::process::ExitStatus {
            let deadline = Instant::now() + Duration::from_secs(15);
            loop {
                if let Some(status) = child.0.try_wait().unwrap() { child.1 = true; return status; }
                assert!(Instant::now() < deadline, "owned child deadline");
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        let path = std::env::temp_dir().join(format!("passphrase-{}", std::process::id()));
        fs::create_dir(&path).unwrap();
        let scratch = Scratch(path);
        let library = scratch.0.join("fault.dylib");
        let mut compiler = OwnedChild(Command::new("cc").args(["-dynamiclib", "-Wall", "-Wextra", "-Werror", "-Wno-deprecated-declarations"])
            .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/signal_fault.c")).arg("-o").arg(&library)
            .process_group(0).spawn().unwrap(), false, None);
        assert!(wait(&mut compiler).success(), "fixture compile");
        for case in ["empty", "invalid", "empty-trace", "empty-fault", "invalid-fault", "io-prompt", "io-newline", "io-invalid-newline", "io-control", "io-open"] {
            let root = scratch.0.join(case);
            fs::create_dir(&root).unwrap();
            let (master, slave) = super::controlling_tty::open_pty().unwrap();
            let before = tcgetattr(&slave).unwrap();
            let flags = rustix::fs::fcntl_getfl(&master).unwrap();
            rustix::fs::fcntl_setfl(&master, flags | rustix::fs::OFlags::NONBLOCK).unwrap();
            let root_text = root.to_str().unwrap();
            let library_text = library.to_str().unwrap();
            let mut child = OwnedChild(super::controlling_tty::launch_binary_with_controlling_tty(
                std::env::current_exe().unwrap().as_os_str(), &slave, &root,
                &["--exact", "tests::read_passphrase_owned_terminal_cleanup", "--nocapture"],
                &[(ROOT, root_text), ("VAULT_PASSPHRASE_CASE", case), ("VAULT_SIGNAL_MODE", if case == "empty-trace" { "caller-control" } else if case == "io-prompt" || case == "io-open" || case == "io-control" { case } else if case.starts_with("io-") { "io-newline" } else { "caller-restore" }), ("DYLD_INSERT_LIBRARIES", library_text)],
                Stdio::null(),
            ).unwrap(), false, Some(master));
            let deadline = Instant::now() + Duration::from_secs(15);
            let mut output = Vec::new();
            loop {
                let mut buf = [0; 512];
                match child.2.as_mut().unwrap().read(&mut buf) {
                    Ok(n) => output.extend_from_slice(&buf[..n]),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {},
                    Err(e) => panic!("{case}: terminal read: {e}"),
                }
                let hidden = !tcgetattr(&slave).unwrap().local_modes.intersects(LocalModes::ECHO | LocalModes::ECHONL | LocalModes::ICANON);
                if output.windows(b"owned prompt: ".len()).any(|w| w == b"owned prompt: ") && hidden { break; }
                if (case == "io-prompt" || case == "io-open") && (root.join("complete").exists() || root.join("failed").exists()) { break; }
                assert!(child.0.try_wait().unwrap().is_none(), "{case}: child exited before prompt: {output:?}");
                assert!(Instant::now() < deadline, "{case}: prompt deadline: {output:?}");
                std::thread::sleep(Duration::from_millis(5));
            }
            assert_eq!(fs::read(root.join("entered")).unwrap(), b"yes");
            if case.ends_with("fault") || case == "empty-trace" || case == "io-newline" || case == "io-invalid-newline" { fs::write(root.join("armed"), b"yes").unwrap(); }
            if case != "io-prompt" && case != "io-open" {
                child.2.as_mut().unwrap().write_all(if case.starts_with("invalid") || case == "io-invalid-newline" { b"\xff\n" } else { b"\n" }).unwrap();
            }
            let deadline = Instant::now() + Duration::from_secs(15);
            while !root.join("complete").exists() && !root.join("failed").exists() {
                assert!(child.0.try_wait().unwrap().is_none(), "{case}: child exited before completion");
                assert!(Instant::now() < deadline, "{case}: completion deadline");
                std::thread::sleep(Duration::from_millis(5));
            }
            let after = tcgetattr(&slave).unwrap();
            assert_eq!(after.input_modes, before.input_modes);
            assert_eq!(after.output_modes, before.output_modes);
            assert_eq!(after.control_modes, before.control_modes);
            assert_eq!(after.local_modes & !LocalModes::PENDIN, before.local_modes & !LocalModes::PENDIN);
            let mut buf = [0; 4096];
            while let Ok(n) = child.2.as_mut().unwrap().read(&mut buf) {
                if n == 0 { break; }
                output.extend_from_slice(&buf[..n]);
            }
            fs::write(root.join("release"), b"yes").unwrap();
            drop(child.2.take());
            let status = wait(&mut child);
            let mut stdout = String::new();
            child.0.stdout.take().unwrap().read_to_string(&mut stdout).unwrap();
            assert!(status.success(), "{case}: {status}: {stdout}: {}", String::from_utf8_lossy(&output));
            assert_eq!(fs::read(root.join("complete")).unwrap(), b"yes");
            if case.starts_with("io-") && case != "io-control" {
                assert_eq!(fs::read_to_string(root.join("events")).unwrap(), if case == "io-prompt" { "W1!\n" } else if case == "io-open" { "O1!\n" } else { "W2!\n" });
            } else if case.ends_with("fault") {
                assert_eq!(fs::read_to_string(root.join("events")).unwrap(), "S18!\nS15\nS3\nS2\nS1\nS18\n");
            } else if case == "empty-trace" {
                assert_eq!(fs::read_to_string(root.join("events")).unwrap(), "S18\nS15\nS3\nS2\nS1\n");
            } else {
                assert!(!root.join("events").exists());
            }
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn signal_handler_native_faults() {
        use super::SignalHandlers;
        use std::fs;
        use std::os::unix::process::CommandExt;
        use std::process::{Child, Command, Stdio};
        use std::time::{Duration, Instant};

        const ROOT: &str = "VAULT_SIGNAL_ROOT";
        const MODE: &str = "VAULT_SIGNAL_MODE";
        if let Some(root) = std::env::var_os(ROOT) {
            let root = std::path::PathBuf::from(root);
            let mode = std::env::var(MODE).unwrap();
            fs::write(root.join("entered"), b"yes").unwrap();
            fs::write(root.join("armed"), b"yes").unwrap();
            match mode.as_str() {
                "install" | "interrupt" | "combined" => {
                    let error = match SignalHandlers::install() { Err(error) => error, Ok(_) => panic!("install succeeded") };
                    match error {
                        CliError::SignalSetup { source, restore } => {
                            assert_eq!(source.raw_os_error(), Some(if mode == "interrupt" { 22 } else { 5 }));
                            assert_eq!(restore.and_then(|e| e.raw_os_error()), if mode == "combined" { Some(5) } else { None });
                        }
                        other => panic!("wrong error: {other:?}"),
                    }
                }
                "restore" | "suspend-restore" => {
                    let mut handlers = SignalHandlers::install().unwrap();
                    assert_eq!(handlers.previous.len(), 5);
                    if mode == "restore" {
                        assert_eq!(handlers.restore().unwrap_err().raw_os_error(), Some(5));
                    } else {
                        match handlers.suspend_and_resume() {
                            Err(CliError::SignalRestore(error)) => assert_eq!(error.raw_os_error(), Some(5)),
                            other => panic!("wrong restore result: {other:?}"),
                        }
                    }
                    assert_eq!(handlers.previous.iter().map(|entry| entry.0).collect::<Vec<_>>(), [3, 18]);
                    handlers.restore().unwrap();
                    assert!(handlers.previous.is_empty());
                }
                "raise" => {
                    let mut handlers = SignalHandlers::install().unwrap();
                    match handlers.suspend_and_resume() {
                        Err(CliError::SignalSuspend(error)) => assert_eq!(error.raw_os_error(), Some(3)),
                        other => panic!("wrong suspend result: {other:?}"),
                    }
                    assert!(handlers.previous.is_empty());
                }
                "control" => {
                    let mut handlers = SignalHandlers::install().unwrap();
                    assert_eq!(handlers.previous.len(), 5);
                    let pid = rustix::process::Pid::from_raw(i32::try_from(std::process::id()).unwrap()).unwrap();
                    rustix::process::kill_process(pid, rustix::process::Signal::INT).unwrap();
                    let deadline = Instant::now() + Duration::from_secs(2);
                    while super::PENDING_SIGNAL.load(std::sync::atomic::Ordering::Relaxed) != 2 {
                        assert!(Instant::now() < deadline, "installed handler did not receive SIGINT");
                        std::thread::yield_now();
                    }
                    handlers.restore().unwrap();
                    assert!(handlers.previous.is_empty());
                }
                _ => panic!("unknown mode"),
            }
            fs::remove_file(root.join("armed")).unwrap();
            fs::write(root.join("complete"), b"yes").unwrap();
            return;
        }
        struct Scratch(std::path::PathBuf);
        impl Drop for Scratch { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
        struct OwnedChild(Child, bool);
        impl Drop for OwnedChild {
            fn drop(&mut self) {
                if !self.1 {
                    if let Some(pid) = rustix::process::Pid::from_raw(self.0.id() as i32) {
                        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
                    }
                    let _ = self.0.wait();
                }
            }
        }
        fn wait(child: &mut OwnedChild) -> std::process::ExitStatus {
            let deadline = Instant::now() + Duration::from_secs(15);
            loop {
                if let Some(status) = child.0.try_wait().unwrap() { child.1 = true; return status; }
                assert!(Instant::now() < deadline, "owned child deadline");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        let scratch_path = std::env::temp_dir().join(format!("sig-{}", std::process::id()));
        fs::create_dir(&scratch_path).unwrap();
        let scratch = Scratch(scratch_path);
        let library = scratch.0.join("fault.dylib");
        let mut compiler = OwnedChild(Command::new("cc").args(["-dynamiclib", "-Wall", "-Wextra", "-Werror", "-Wno-deprecated-declarations"])
            .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/signal_fault.c")).arg("-o").arg(&library)
            .process_group(0).spawn().unwrap(), false);
        assert!(wait(&mut compiler).success(), "fixture compile");
        for (mode, events) in [
            ("control", ""),
            ("install", "S1\nI1\nS2!\nS1\n"),
            ("interrupt", "S1\nI1\nS2\nI2!\nS2\nS1\n"),
            ("combined", "S1\nI1\nS2!\nS1!\nS1\n"),
            ("restore", "S1\nI1\nS2\nI2\nS3\nI3\nS15\nI15\nS18\nI18\nS18!\nS15\nS3!\nS2\nS1\nS18\nS3\n"),
            ("suspend-restore", "S1\nI1\nS2\nI2\nS3\nI3\nS15\nI15\nS18\nI18\nS18!\nS15\nS3!\nS2\nS1\nS18\nS3\n"),
            ("raise", "S1\nI1\nS2\nI2\nS3\nI3\nS15\nI15\nS18\nI18\nS18\nS15\nS3\nS2\nS1\nR18!\n"),
        ] {
            let root = scratch.0.join(mode);
            fs::create_dir(&root).unwrap();
            let log = fs::File::create(root.join("log")).unwrap();
            let mut command = Command::new(std::env::current_exe().unwrap());
            command.args(["--exact", "tests::signal_handler_native_faults", "--nocapture"])
                .env(ROOT, &root).env(MODE, mode).stdout(Stdio::from(log.try_clone().unwrap())).stderr(Stdio::from(log)).process_group(0);
            if mode == "control" { command.env_remove("DYLD_INSERT_LIBRARIES"); }
            else { command.env("DYLD_INSERT_LIBRARIES", &library); }
            let mut child = OwnedChild(command.spawn().unwrap(), false);
            let status = wait(&mut child);
            assert!(status.success(), "{mode}: {status}: {}", fs::read_to_string(root.join("log")).unwrap());
            assert_eq!(fs::read(root.join("entered")).unwrap(), b"yes");
            assert_eq!(fs::read(root.join("complete")).unwrap(), b"yes");
            if !events.is_empty() { assert_eq!(fs::read_to_string(root.join("events")).unwrap(), events, "{mode}"); }
        }
    }

    #[test]
    fn help_examples_parse_without_running_commands() {
        use super::{COMMANDS, EXEC_EXAMPLE, parse_exec_args, validate_command};
        for spec in COMMANDS {
            let words: Vec<String> = spec.example.split_whitespace().map(str::to_owned).collect();
            assert_eq!(words[0], "vault");
            let parsed = COMMANDS.iter().find(|entry| entry.name == words[1]).unwrap();
            assert_eq!(parsed.kind, spec.kind);
            validate_command(parsed, &words[2..]).unwrap();
            if spec.argument.is_some() {
                for flag in ["-h", "--help"] {
                    validate_command(spec, &[flag.to_owned()]).unwrap();
                }
            }
        }
        let words: Vec<String> = EXEC_EXAMPLE.split_whitespace().skip(1).map(str::to_owned).collect();
        let (env, command) = parse_exec_args(&words).unwrap();
        assert_eq!(env.len(), 2);
        assert_eq!(command, ["cargo", "run"]);
        for (i, spec) in COMMANDS.iter().enumerate() {
            assert!(!COMMANDS[..i].iter().any(|other| other.name == spec.name));
        }
    }

    struct FakeTerminal {
        echo_enabled: bool,
        snapshot_error: bool,
        disable_error: bool,
        restore_error: bool,
        restore_once_error: bool,
        restores: usize,
    }

    impl FakeTerminal {
        fn ready() -> Self {
            Self {
                echo_enabled: true,
                snapshot_error: false,
                disable_error: false,
                restore_error: false,
                restore_once_error: false,
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
            if std::mem::take(&mut self.restore_once_error) || self.restore_error {
                Err(io::Error::other("restore failure"))
            } else {
                self.echo_enabled = *saved;
                Ok(())
            }
        }
    }

    #[test]
    fn prompt_and_read_share_one_hidden_terminal_session() {
        use std::cell::RefCell;
        use std::rc::Rc;

        struct ObservedTerminal(Rc<RefCell<Vec<&'static str>>>);
        impl TerminalSettings for ObservedTerminal {
            type Saved = ();
            fn snapshot(&mut self) -> io::Result<()> { Ok(()) }
            fn disable_echo(&mut self, _: &()) -> io::Result<()> {
                self.0.borrow_mut().push("hide");
                Ok(())
            }
            fn restore(&mut self, _: &()) -> io::Result<()> {
                self.0.borrow_mut().push("restore");
                Ok(())
            }
        }
        struct ObservedIo(Rc<RefCell<Vec<&'static str>>>);
        impl Write for ObservedIo {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.borrow_mut().push("prompt");
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> { Ok(()) }
        }
        impl Read for ObservedIo {
            fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
                self.0.borrow_mut().push("read");
                bytes[0] = b'\n';
                Ok(1)
            }
        }
        let events = Rc::new(RefCell::new(Vec::new()));
        let mut terminal = ObservedTerminal(events.clone());
        let mut output = ObservedIo(events.clone());
        let mut input = ObservedIo(events.clone());
        let mut published = false;
        read_without_echo(&mut input, &mut output, TerminalFeedback { silent: true, prompt: Some(TerminalPrompt {
            text: "prompt: ", operation: "write passphrase prompt", published: &mut published,
        }) }, 100, &mut terminal, || None, || Ok(())).unwrap();
        assert!(published);
        assert_eq!(*events.borrow(), ["hide", "prompt", "read", "restore"]);
    }

    struct FailingReader(bool);

    impl Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            if std::mem::replace(&mut self.0, true) {
                Ok(0)
            } else {
                Err(io::Error::other("read failure"))
            }
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
            TerminalFeedback { silent: true, prompt: None },
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
                TerminalFeedback { silent: true, prompt: None },
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
            TerminalFeedback { silent: false, prompt: None },
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
            TerminalFeedback { silent: true, prompt: None },
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
            TerminalFeedback { silent: true, prompt: None },
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
            TerminalFeedback { silent: true, prompt: None },
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
            TerminalFeedback { silent: true, prompt: None },
            MAX_SECRET_BYTES,
            &mut restore_failure,
            || None,
            || Ok(()),
        )
        .unwrap_err();
        assert!(matches!(error, CliError::TerminalSettings { operation: "restore settings", .. }));
        assert!(restore_failure.restores >= 1);

        let mut transient_restore_failure = FakeTerminal::ready();
        transient_restore_failure.restore_once_error = true;
        let error = read_without_echo(
            &mut Cursor::new(b"secret\n"),
            &mut Vec::new(),
            TerminalFeedback { silent: true, prompt: None },
            MAX_SECRET_BYTES,
            &mut transient_restore_failure,
            || None,
            || Ok(()),
        )
        .unwrap_err();
        assert!(matches!(error, CliError::TerminalSettings { operation: "restore settings", .. }));
        assert!(transient_restore_failure.echo_enabled);
    }

    #[test]
    fn prompt_failure_restores_echo_and_reports_restore_failure() {
        for restore_error in [false, true] {
            let mut terminal = FakeTerminal::ready();
            terminal.restore_error = restore_error;
            let mut published = false;
            let error = read_without_echo(
                &mut Cursor::new(b"unused\n"),
                &mut FailingWriter,
                TerminalFeedback { silent: true, prompt: Some(TerminalPrompt {
                    text: "prompt: ", operation: "write passphrase prompt", published: &mut published,
                }) },
                MAX_SECRET_BYTES,
                &mut terminal,
                || None,
                || Ok(()),
            ).unwrap_err();
            assert!(!published);
            assert!(error.to_string().contains("write passphrase prompt"));
            assert_eq!(terminal.echo_enabled, !restore_error);
            assert!(terminal.restores >= 1);
            assert_eq!(matches!(error, CliError::TerminalReadAndRestore { .. }), restore_error);
        }
    }

    #[test]
    fn terminal_read_failure_restores_echo() {
        let mut terminal = FakeTerminal::ready();
        let error = read_without_echo(
            &mut FailingReader(false),
            &mut Vec::new(),
            TerminalFeedback { silent: true, prompt: None },
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
            &mut FailingReader(false),
            &mut Vec::new(),
            TerminalFeedback { silent: true, prompt: None },
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
            TerminalFeedback { silent: false, prompt: None },
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
        let mut signal = Some(2);
        let error = read_without_echo(
            &mut Cursor::new(b"secret\n"),
            &mut Vec::new(),
            TerminalFeedback { silent: true, prompt: None },
            MAX_SECRET_BYTES,
            &mut terminal,
            || signal.take(),
            || Ok(()),
        )
        .unwrap_err();
        assert!(matches!(error, CliError::Interrupted(2)));
        assert!(terminal.echo_enabled);
    }
}
