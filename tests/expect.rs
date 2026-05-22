use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::process::Stdio;

/// Derive the path to the `tiber` binary from the location of the current
/// test executable.  Both `cargo test` and `cargo llvm-cov` place test
/// binaries under `<target-dir>/debug/deps/`; the `tiber` binary lands one
/// level up at `<target-dir>/debug/tiber`.  Using the executable's location
/// means we automatically pick up the instrumented binary when running under
/// `cargo llvm-cov`, without needing to hard-code any paths.
fn tiber_bin() -> PathBuf {
    std::env::current_exe()
        .expect("could not read current_exe")
        .parent() // …/debug/deps
        .expect("no parent")
        .parent() // …/debug
        .expect("no grandparent")
        .join("tiber")
}

fn ensure_binary_built(bin: &Path) {
    if bin.exists() {
        return; // already built (e.g. by cargo-llvm-cov before test run)
    }
    let output = Command::new("cargo")
        .args(["build", "--quiet", "--bin", "tiber"])
        .output()
        .expect("failed to build tiber binary");
    if !output.status.success() {
        panic!(
            "Failed to build tiber binary: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

fn check_expect_installed() {
    let expect_check = Command::new("expect")
        .arg("-v")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if expect_check.is_err() || !expect_check.unwrap().success() {
        panic!("Tcl Expect is not installed or not found in PATH.");
    }
}

#[test]
fn run_expect_scripts() {
    check_expect_installed();
    let bin = tiber_bin();
    ensure_binary_built(&bin);
    let scripts = fs::read_dir("tests/expect").unwrap();
    for entry in scripts {
        let path = entry.unwrap().path();
        if path.extension().and_then(|s| s.to_str()) == Some("exp") {
            let filename = path.file_name().unwrap();
            let status = Command::new("expect")
                .arg(filename)
                .current_dir("tests/expect")
                .env("TIBER_BIN", &bin)
                .status()
                .expect("failed to run expect script");
            assert!(status.success(), "Expect script failed: {:?}", path);
        }
    }
}
