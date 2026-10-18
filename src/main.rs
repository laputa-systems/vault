use vault::keychain;

use std::ffi::{CString, c_char, c_int, c_void};
use std::io;
use std::ptr;

const STDIN: c_int = 0;
const STDOUT: c_int = 1;
const STDERR: c_int = 2;
const EINTR: c_int = 4;

unsafe extern "C" {
    fn _NSGetEnviron() -> *mut *mut *mut c_char;
    fn __error() -> *mut c_int;
    fn exit(status: c_int) -> !;
    fn isatty(fd: c_int) -> c_int;
    fn posix_spawnp(
        pid: *mut c_int,
        file: *const c_char,
        file_actions: *const c_void,
        attrp: *const c_void,
        argv: *const *mut c_char,
        envp: *const *mut c_char,
    ) -> c_int;
    fn read(fd: c_int, buf: *mut c_void, count: usize) -> isize;
    fn setenv(name: *const c_char, value: *const c_char, overwrite: c_int) -> c_int;
    fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
    fn write(fd: c_int, buf: *const c_void, count: usize) -> isize;
}

const USAGE: &str = "\
vault — macOS Keychain secret manager

Usage:

  vault set   <NAME>            Store a secret (prompts for value)
  vault isset <NAME>            Store a secret (silent, no prompt)
  vault get   <NAME>            Print a secret to stdout
  vault rm    <NAME>            Delete a secret
  vault ls                      List all stored secret names
  vault lock                    Reset authorization for every secret
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

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        write_fd(STDOUT, USAGE.as_bytes());
        return;
    }

    let first = &args[1];

    match first.as_str() {
        "set" => cmd_set(&args, false),
        "isset" => cmd_set(&args, true),
        "get" => cmd_get(&args),
        "rm" => cmd_rm(&args),
        "ls" => cmd_ls(&args),
        "lock" => cmd_lock(&args),
        "purge" => cmd_purge(),
        "-h" | "--help" | "help" => write_fd(STDOUT, USAGE.as_bytes()),
        _ => exec_mode(&args[1..]),
    }
}

fn write_fd(fd: c_int, mut bytes: &[u8]) {
    while !bytes.is_empty() {
        let written = unsafe { write(fd, bytes.as_ptr().cast::<c_void>(), bytes.len()) };
        if written > 0 {
            bytes = &bytes[written as usize..];
        } else if written < 0 && unsafe { *__error() } == EINTR {
            continue;
        } else {
            return;
        }
    }
}

fn write_line(fd: c_int, text: &str) {
    write_fd(fd, text.as_bytes());
    write_fd(fd, b"\n");
}

fn fail(message: &str) -> ! {
    write_line(STDERR, message);
    unsafe { exit(1) }
}

fn require_exact_args(args: &[String], cmd: &str, expected: usize) {
    if args.len() < expected {
        fail(&format!("vault: missing name for {cmd}"));
    }
    if args.len() > expected {
        fail(&format!("vault: unexpected argument: {}", args[expected]));
    }
    if args[2].is_empty() {
        fail("vault: empty name not allowed");
    }
}

fn cmd_set(args: &[String], silent: bool) {
    require_exact_args(args, if silent { "isset" } else { "set" }, 3);
    let name = &args[2];
    let value = read_secret(name, silent);
    if let Err(e) = keychain::set_secret(name, value.as_bytes()) {
        fail(&e);
    }
}

fn cmd_get(args: &[String]) {
    require_exact_args(args, "get", 3);
    let name = &args[2];
    match keychain::get_secret(name) {
        Ok(value) => write_line(STDOUT, &value),
        Err(e) => fail(&e),
    }
}

fn cmd_rm(args: &[String]) {
    require_exact_args(args, "rm", 3);
    let name = &args[2];
    if let Err(e) = keychain::delete_secret(name) {
        fail(&e);
    }
}

fn cmd_ls(args: &[String]) {
    if args.len() > 2 {
        fail("vault: ls takes no arguments");
    }
    match keychain::list_secrets() {
        Ok(names) => {
            for name in names {
                write_line(STDOUT, &name);
            }
        }
        Err(e) => fail(&e),
    }
}

fn cmd_purge() {
    match keychain::purge_secrets() {
        Ok(0) => write_line(STDOUT, "nothing to purge"),
        Ok(n) => write_line(
            STDOUT,
            &format!("purged {n} secret{}", if n == 1 { "" } else { "s" }),
        ),
        Err(e) => fail(&e),
    }
}

fn cmd_lock(args: &[String]) {
    if args.len() != 2 {
        fail("vault: lock takes no arguments");
    }
    if let Err(e) = keychain::lock_secrets() {
        fail(&e);
    }
    write_line(STDOUT, "locked vault secrets");
}

fn exec_mode(args: &[String]) {
    let dash_pos = args.iter().position(|a| a == "--");

    let dash_pos = match dash_pos {
        Some(p) => p,
        None => fail("vault: expected '--' before command"),
    };

    let env_specs = &args[..dash_pos];
    let cmd_args = &args[dash_pos + 1..];

    if cmd_args.is_empty() {
        fail("vault: missing command");
    }

    let mut env = Vec::with_capacity(env_specs.len());
    for spec in env_specs {
        if let Some((name, value)) = spec.split_once('=')
            && !name.is_empty()
            && !value.contains('=')
        {
            env.push((name.to_owned(), value.to_owned()));
            continue;
        }
        let value = keychain::get_secret(spec).unwrap_or_else(|e| fail(&e));
        env.push((spec.clone(), value));
    }

    spawn_and_exit(cmd_args, &env);
}

fn read_secret(name: &str, silent: bool) -> String {
    if unsafe { isatty(STDIN) } == 1 {
        if !silent {
            write_fd(STDERR, format!("Enter value for {name}: ").as_bytes());
        }
        read_without_echo(silent)
    } else {
        let bytes = read_all().unwrap_or_else(|_| fail("vault: failed to read stdin"));
        let mut value = String::from_utf8(bytes)
            .unwrap_or_else(|_| fail("vault: failed to read stdin: invalid UTF-8"));
        strip_trailing_newline(&mut value);
        value
    }
}

fn read_byte() -> Result<Option<u8>, ()> {
    let mut byte = 0u8;
    loop {
        let result = unsafe {
            read(
                STDIN,
                (&mut byte as *mut u8).cast::<c_void>(),
                std::mem::size_of::<u8>(),
            )
        };
        if result == 1 {
            return Ok(Some(byte));
        }
        if result == 0 {
            return Ok(None);
        }
        if result < 0 && unsafe { *__error() } == EINTR {
            continue;
        }
        return Err(());
    }
}

fn read_all() -> Result<Vec<u8>, ()> {
    let mut value = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let result = unsafe { read(STDIN, buffer.as_mut_ptr().cast::<c_void>(), buffer.len()) };
        if result > 0 {
            value.extend_from_slice(&buffer[..result as usize]);
        } else if result == 0 {
            return Ok(value);
        } else if unsafe { *__error() } != EINTR {
            return Err(());
        }
    }
}

fn read_line() -> Result<Vec<u8>, ()> {
    let mut bytes = Vec::new();
    loop {
        match read_byte()? {
            Some(b'\n') | Some(b'\r') | None => {
                return Ok(bytes);
            }
            Some(byte) => bytes.push(byte),
        }
    }
}

fn read_without_echo(silent: bool) -> String {
    use rustix::termios::{LocalModes, OptionalActions, tcgetattr, tcsetattr};

    let stdin = io::stdin();

    let Ok(original) = tcgetattr(&stdin) else {
        let bytes = read_line().unwrap_or_else(|_| fail("vault: failed to read input"));
        return decode_terminal_input(bytes)
            .unwrap_or_else(|_| fail("vault: failed to read input: invalid UTF-8"));
    };

    let mut termios = original.clone();
    termios.local_modes &= !(LocalModes::ECHO | LocalModes::ECHONL | LocalModes::ICANON);
    let _ = tcsetattr(&stdin, OptionalActions::Now, &termios);

    struct Restore(io::Stdin, rustix::termios::Termios);
    impl Drop for Restore {
        fn drop(&mut self) {
            let _ = tcsetattr(&self.0, OptionalActions::Now, &self.1);
        }
    }

    let mut value = Vec::new();
    let mut read_error = false;
    {
        let _restore = Restore(stdin, original);
        loop {
            let byte = match read_byte() {
                Ok(Some(byte)) => byte,
                Ok(None) => break,
                Err(()) => {
                    read_error = true;
                    break;
                }
            };
            match byte {
                b'\n' | b'\r' => break,
                0x7f => {
                    if value.pop().is_some() && !silent {
                        write_fd(STDERR, b"\x08 \x08");
                    }
                }
                byte => {
                    value.push(byte);
                    if !silent {
                        write_fd(STDERR, b"*");
                    }
                }
            }
        }
    }

    if read_error {
        fail("vault: failed to read input");
    }

    if !silent {
        write_fd(STDERR, b"\n");
    }

    decode_terminal_input(value)
        .unwrap_or_else(|_| fail("vault: failed to read input: invalid UTF-8"))
}

fn decode_terminal_input(bytes: Vec<u8>) -> Result<String, std::string::FromUtf8Error> {
    String::from_utf8(bytes)
}

fn strip_trailing_newline(s: &mut String) {
    if s.ends_with('\n') {
        s.pop();
    }
    if s.ends_with('\r') {
        s.pop();
    }
}

fn spawn_and_exit(cmd_args: &[String], env: &[(String, String)]) -> ! {
    let c_args: Vec<CString> = cmd_args
        .iter()
        .map(|arg| {
            CString::new(arg.as_str()).unwrap_or_else(|e| {
                fail(&format!("vault: invalid command argument: {e}"));
            })
        })
        .collect();
    let mut argv: Vec<*mut c_char> = c_args.iter().map(|arg| arg.as_ptr().cast_mut()).collect();
    argv.push(ptr::null_mut());

    for (name, value) in env {
        let name = CString::new(name.as_str()).unwrap_or_else(|e| {
            fail(&format!("vault: invalid environment name: {e}"));
        });
        let value = CString::new(value.as_str()).unwrap_or_else(|e| {
            fail(&format!("vault: invalid environment value: {e}"));
        });
        if unsafe { setenv(name.as_ptr(), value.as_ptr(), 1) } != 0 {
            fail(&format!(
                "vault: failed to set environment variable {name:?}"
            ));
        }
    }

    let mut pid = 0;
    let envp = unsafe { *_NSGetEnviron() };
    let result = unsafe {
        posix_spawnp(
            &mut pid,
            c_args[0].as_ptr(),
            ptr::null(),
            ptr::null(),
            argv.as_ptr(),
            envp,
        )
    };
    if result != 0 {
        fail(&format!("vault: failed to spawn command (error {result})"));
    }

    let mut status = 0;
    loop {
        let waited = unsafe { waitpid(pid, &mut status, 0) };
        if waited == pid {
            break;
        }
        if waited < 0 && unsafe { *__error() } == EINTR {
            continue;
        }
        fail("vault: failed to wait for command");
    }

    let signal = status & 0x7f;
    let exit_status = if signal != 0 && signal != 0x7f {
        128 + signal
    } else {
        (status >> 8) & 0xff
    };
    unsafe { exit(exit_status) }
}

#[cfg(test)]
mod tests {
    use super::decode_terminal_input;

    #[test]
    fn terminal_input_preserves_utf8() {
        assert_eq!(
            decode_terminal_input("café 🚀".as_bytes().to_vec()).unwrap(),
            "café 🚀"
        );
    }

    #[test]
    fn terminal_input_rejects_invalid_utf8() {
        assert!(decode_terminal_input(vec![0xC3, 0x28]).is_err());
    }
}
