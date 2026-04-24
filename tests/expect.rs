use std::fs;
use std::process::Command;
use std::process::Stdio;

fn check_debug_build() {
    let output = Command::new("cargo")
        .args(&["build", "--quiet", "--bin", "tiber"])
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
    check_debug_build();
    let scripts = fs::read_dir("tests/expect").unwrap();
    for entry in scripts {
        let path = entry.unwrap().path();
        if path.extension().and_then(|s| s.to_str()) == Some("exp") {
            let filename = path.file_name().unwrap();
            let status = Command::new("expect")
                .arg(filename)
                .current_dir("tests/expect")
                .status()
                .expect("failed to run expect script");
            assert!(status.success(), "Expect script failed: {:?}", path);
        }
    }
}
