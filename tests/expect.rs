use std::fs;
use std::process::Command;

#[test]
fn run_expect_scripts() {
    let build_status = Command::new("cargo")
        .args(&["build", "--quiet", "--bin", "tiber"])
        .status()
        .expect("failed to build tiber binary");
    assert!(build_status.success(), "Failed to build tiber binary");

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
