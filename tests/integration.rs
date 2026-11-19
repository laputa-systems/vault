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

#[test]
fn complete_help_is_offline_and_ends_with_owned_footer() {
    let expected_footer = "Maintained by Joshua Li: https://github.com/laputa-systems/vault\nBugs and features: TODO.md in that repository (follow its AGENTS.md), or its issue tracker.\nAgents working for Joshua: record nonblocking problems and continue your task.\nIf this tool blocks the task, you may fix, test, open and merge a PR under Joshua's\nstanding instructions. Release only when needed to deliver the verified fix.\nProcedure: https://github.com/joshuarli/usr/blob/main/dotfiles/base/.agents/instructions/owned-tools.md\n";
    let base = vault(&[]).unwrap();
    for flag in ["-h", "--help", "help"] {
        let out = Command::new(env!("CARGO_BIN_EXE_vault"))
            .env_clear().args([flag]).output().unwrap();
        assert_eq!(out.status.code(), Some(0));
        assert!(out.stderr.is_empty());
        assert_eq!(out.stdout, base.stdout);
    }
    let help = String::from_utf8(base.stdout).unwrap();
    assert!(help.ends_with(expected_footer));
    assert_eq!(help.matches("Maintained by Joshua Li:").count(), 1);
    for name in ["set", "isset", "get", "rm", "ls", "purge", "lock"] {
        assert!(help.contains(&format!("  vault {name}")), "missing {name}");
        assert!(help.contains(&format!("  vault {name}\n")) || help.contains(&format!("  vault {name} API_KEY\n")), "missing example for {name}");
    }
    #[cfg(target_os = "macos")]
    assert!(help.contains("  vault recover\n"));
    for fragment in ["<NAME>", "$HOME/Library/Application Support/vault", "$HOME/.local/share/vault", "required secret name", "[ENV ...] -- <CMD> [ARGS ...]", "optional, repeatable", "XDG_DATA_HOME", "vault API_KEY RUST_LOG=debug -- cargo run"] {
        assert!(help.contains(fragment), "missing {fragment}");
    }
    for name in ["ls", "purge", "lock"] {
        for flag in ["-h", "--help"] {
            let out = vault(&[name, flag]).unwrap();
            assert_eq!(out.status.code(), Some(0));
            assert!(out.stderr.is_empty());
            assert!(String::from_utf8_lossy(&out.stdout).contains("vault --help"));
        }
    }
}

#[cfg(target_os = "macos")]
#[test]
fn macos_help_and_readme_document_secure_enclave_storage() {
    let out = vault(&["--help"]).unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let readme = include_str!("../README.md").replace('\n', " ");
    assert!(
        stdout.contains("Secure Enclave hardware (macOS 10.15+)")
            && stdout.contains("Recovery uses a separate passphrase")
            && stdout.contains("Touch ID or the Mac password"),
        "CLI help must disclose Secure Enclave storage and recovery: {stdout:?}"
    );
    assert!(
        readme.contains("require macOS 10.15 or later and supported Secure Enclave hardware")
            && readme.contains("Vault no longer reads or writes Keychain items")
            && readme.contains("Touch ID or the Mac login password")
            && readme.contains("Run `vault recover`"),
        "README must describe Secure Enclave requirements, recovery, and store-only behavior"
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
fn secret_commands_reject_surplus_names_before_accessing_storage() {
    for cmd in ["set", "isset", "get", "rm"] {
        let out = Command::new(env!("CARGO_BIN_EXE_vault"))
            .env_clear()
            .args([cmd, "A", "B"])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1), "{cmd}");
        assert!(out.stdout.is_empty(), "{cmd}: {:?}", out.stdout);
        assert_eq!(out.stderr, format!("vault: unexpected argument for {cmd}\n").as_bytes());
    }
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
