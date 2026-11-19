fn missing_prerequisite(message: &str) {
    if std::env::var_os("CI").is_some() {
        panic!("missing test prerequisite: {message}");
    }
    use std::io::Write;
    writeln!(std::io::stderr().lock(), "skipped test boundary: {message}").unwrap();
}
