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

#[cfg(target_os = "macos")]
#[test]
fn macos_keychain_compatibility_warning_stays_in_help_and_readme() {
    let out = vault(&["--help"]).unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let readme = include_str!("../README.md").replace('\n', " ");
    let compatibility_mode = "uses the file-based Keychain in compatibility mode";
    assert!(
        stdout.contains("macOS security warning")
            && stdout.contains("userPresence enforcement is unverified")
            && stdout.contains("dummy item with interaction disabled")
            && stdout.contains(compatibility_mode),
        "CLI help must disclose the unverified file-Keychain policy: {stdout:?}"
    );
    assert!(
        readme.contains(compatibility_mode),
        "README must repeat the CLI's compatibility-mode label so its storage warning stays consistent"
    );
    assert!(
        readme.contains("`userPresence` enforcement is unverified")
            && readme.contains("dummy item with interaction disabled"),
        "README must preserve the same observed Keychain limitation as CLI help"
    );
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
fn exec_exits_with_child_exit_code() {
    let out = vault(&["--", "sh", "-c", "exit 7"]).unwrap();
    assert_eq!(out.status.code(), Some(7));
}

#[test]
fn exec_child_killed_by_signal_exits_128_plus_signal() {
    let out = vault(&["--", "sh", "-c", "kill -TERM $$"]).unwrap();
    assert_eq!(out.status.code(), Some(143));
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
fn exec_preserves_inherited_environment_and_literal_overrides() {
    let marker = "VAULT_TEST_INHERITED_MARKER";
    let before = std::env::var_os(marker);
    let path =
        std::env::var("CARGO_BIN_EXE_vault").unwrap_or_else(|_| "target/debug/vault".to_string());
    let out = Command::new(path)
        .env(marker, "inherited-value")
        .args([
            "VAULT_TEST_LITERAL=child-value",
            "--",
            "sh",
            "-c",
            "printf '%s:%s' \"$VAULT_TEST_INHERITED_MARKER\" \"$VAULT_TEST_LITERAL\"",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "inherited-value:child-value"
    );
    assert_eq!(std::env::var_os(marker), before);
}

#[test]
fn exec_spawn_failure_is_reported_without_environment_values() {
    let out = vault(&[
        "VAULT_TEST_SECRET_VALUE=do-not-print",
        "--",
        "vault-command-that-does-not-exist",
    ])
    .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("failed to spawn command"), "stderr: {stderr}");
    assert!(!stderr.contains("do-not-print"), "stderr: {stderr}");
}
