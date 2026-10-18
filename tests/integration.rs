use std::io::Write;
use std::process::{Command, Stdio};

fn vault(args: &[&str]) -> std::io::Result<std::process::Output> {
    let path =
        std::env::var("CARGO_BIN_EXE_vault").unwrap_or_else(|_| "target/debug/vault".to_string());
    Command::new(path)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
}

fn vault_stdin(args: &[&str], input: &str) -> std::io::Result<std::process::Output> {
    let path =
        std::env::var("CARGO_BIN_EXE_vault").unwrap_or_else(|_| "target/debug/vault".to_string());
    let mut child = Command::new(path)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child.stdin.take().unwrap().write_all(input.as_bytes())?;
    child.wait_with_output()
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
fn get_missing_key_errors() {
    let out = vault(&["get", "VAULT_TEST_NONEXISTENT"]).unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("VAULT_TEST_NONEXISTENT"),
        "stderr: {stderr}"
    );
    assert!(stderr.contains("could not be found"), "stderr: {stderr}");
}

#[test]
fn rm_missing_key_errors() {
    let out = vault(&["rm", "VAULT_TEST_NONEXISTENT"]).unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not found"), "stderr: {stderr}");
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
fn lock_rejects_extra_args() {
    let out = vault(&["lock", "EXTRA"]).unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("lock takes no arguments"));
}

#[test]
#[ignore = "requires macOS keychain authentication"]
fn set_reads_from_stdin_pipe() {
    let out = vault_stdin(&["set", "VAULT_TEST_PIPE"], "piped-value").unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
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
fn exec_unknown_keychain_var_errors() {
    let out = vault(&["VAULT_TEST_DOES_NOT_EXIST", "--", "true"]).unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("VAULT_TEST_DOES_NOT_EXIST"),
        "stderr: {stderr}"
    );
    assert!(stderr.contains("could not be found"), "stderr: {stderr}");
}

#[test]
fn exec_multiple_equals_is_keychain_lookup() {
    let out = vault(&["X=Y=Z", "--", "true"]).unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("could not be found"));
}

#[test]
fn exec_equals_at_start_is_keychain_lookup() {
    let out = vault(&["=NOT_LITERAL", "--", "true"]).unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("could not be found"));
}

#[test]
fn exec_exits_with_child_exit_code() {
    let out = vault(&["--", "sh", "-c", "exit 7"]).unwrap();
    assert_eq!(out.status.code(), Some(7));
}

#[test]
fn exec_child_killed_by_signal_exits_128_plus_signal() {
    let out = vault(&["--", "sh", "-c", "kill -TERM $$"]).unwrap();
    let code = out.status.code();
    assert!(
        code == Some(143) || code.is_none(),
        "expected Some(143) or None (signal), got {code:?}"
    );
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
#[ignore = "requires macOS keychain authentication"]
fn set_creates_user_presence_item() {
    let name = "VAULT_TEST_USER_PRESENCE_REGRESSION";

    let out = vault_stdin(&["set", name], "acl-test-value").unwrap();
    assert!(
        out.status.success(),
        "set failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let dump = std::process::Command::new("security")
        .args(["dump-keychain", "-a"])
        .output()
        .expect("failed to run security dump-keychain");
    let dump_str = String::from_utf8_lossy(&dump.stdout);

    let after_acct = match dump_str.find(&format!("\"acct\"<blob>=\"{name}\"")) {
        Some(pos) => &dump_str[pos..],
        None => {
            let _ = vault(&["rm", name]);
            panic!("item not found in keychain dump");
        }
    };

    let item_section = &after_acct[..after_acct.find("\nkeychain:").unwrap_or(after_acct.len())];
    assert!(
        item_section.contains("dev.joshuarli.vault.secure"),
        "item is not in the protected service namespace:\n{item_section}"
    );

    vault(&["rm", name]).unwrap();
}

#[test]
#[ignore = "requires macOS Keychain authorization"]
fn lock_preserves_stored_secret() {
    let name = "VAULT_TEST_LOCK_PRESERVES_SECRET";
    let set = vault_stdin(&["set", name], "lock-test-value").unwrap();
    assert!(
        set.status.success(),
        "{}",
        String::from_utf8_lossy(&set.stderr)
    );

    let locked = vault(&["lock"]).unwrap();
    let listed = vault(&["ls"]).unwrap();
    let retrieved = vault(&["get", name]).unwrap();
    let removed = vault(&["rm", name]).unwrap();

    assert!(
        locked.status.success(),
        "{}",
        String::from_utf8_lossy(&locked.stderr)
    );
    assert!(String::from_utf8_lossy(&locked.stdout).contains("locked vault secrets"));
    assert!(
        String::from_utf8_lossy(&listed.stdout)
            .lines()
            .any(|listed_name| listed_name == name)
    );
    assert!(
        retrieved.status.success(),
        "{}",
        String::from_utf8_lossy(&retrieved.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&retrieved.stdout).trim(),
        "lock-test-value"
    );
    assert!(
        removed.status.success(),
        "{}",
        String::from_utf8_lossy(&removed.stderr)
    );
}
