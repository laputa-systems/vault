use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn main() {
    println!("cargo:rerun-if-changed=src/secure_enclave.swift");
    println!("cargo:rerun-if-env-changed=MACOSX_DEPLOYMENT_TARGET");
    println!("cargo:rerun-if-env-changed=SDKROOT");
    println!("cargo:rerun-if-env-changed=DEVELOPER_DIR");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }

    let target = required_env("TARGET");
    let rustc = required_env("RUSTC");
    let deployment = deployment_target(&rustc, &target);
    let arch = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("aarch64") => "arm64",
        Ok("x86_64") => "x86_64",
        Ok(arch) => panic!("unsupported macOS architecture for Swift bridge: {arch}"),
        Err(error) => panic!("Cargo did not provide CARGO_CFG_TARGET_ARCH: {error}"),
    };
    let out_dir = PathBuf::from(required_env("OUT_DIR"));
    let object = out_dir.join("secure_enclave.o");
    let archive = out_dir.join("libvault_secure_enclave.a");
    let swift_target = format!("{arch}-apple-macos{deployment}");
    let swiftc = PathBuf::from(
        run_stdout(Command::new("xcrun").args(["--find", "swiftc"]))
            .trim()
            .to_owned(),
    );
    let sdk = run_stdout(Command::new("xcrun").args(["--sdk", "macosx", "--show-sdk-path"]));
    let sdk = Path::new(sdk.trim());

    run(Command::new(&swiftc)
        .args(["-emit-object", "-parse-as-library", "-O", "-swift-version", "5"])
        .arg("-sdk")
        .arg(sdk)
        .args(["-target", &swift_target])
        .arg("src/secure_enclave.swift")
        .arg("-o")
        .arg(&object));
    run(Command::new("ar").arg("crs").arg(&archive).arg(&object));

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=vault_secure_enclave");
    println!("cargo:rustc-link-search=native=/usr/lib/swift");

    println!("cargo:rustc-link-search=native={}", sdk.join("usr/lib/swift").display());

    let runtime_resource_path = swiftc
        .parent()
        .and_then(Path::parent)
        .expect("swiftc path has no toolchain runtime directory")
        .join("lib/swift");
    println!(
        "cargo:rustc-link-search=native={}",
        runtime_resource_path.join("macosx").display()
    );
}

fn deployment_target(rustc: &str, target: &str) -> String {
    let output = run_stdout(Command::new(rustc).args(["--print", "deployment-target", "--target", target]));
    output
        .trim()
        .strip_prefix("MACOSX_DEPLOYMENT_TARGET=")
        .expect("unexpected rustc --print deployment-target output")
        .to_owned()
}

fn required_env(name: &str) -> String {
    env::var(name).unwrap_or_else(|error| panic!("Cargo did not provide {name}: {error}"))
}

fn run(command: &mut Command) {
    let output = command.output().unwrap_or_else(|error| panic!("failed to run {command:?}: {error}"));
    check_output(command, output);
}

fn run_stdout(command: &mut Command) -> String {
    let output = command.output().unwrap_or_else(|error| panic!("failed to run {command:?}: {error}"));
    let output = check_output(command, output);
    String::from_utf8(output.stdout).unwrap_or_else(|error| panic!("{command:?} returned non-UTF-8 output: {error}"))
}

fn check_output(command: &Command, output: Output) -> Output {
    if !output.status.success() {
        panic!("{command:?} failed with {}: {}", output.status, String::from_utf8_lossy(&output.stderr));
    }
    output
}
