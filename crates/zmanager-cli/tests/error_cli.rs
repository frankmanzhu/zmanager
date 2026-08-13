#[cfg(feature = "tzap-online")]
use std::process::Command;

#[cfg(not(feature = "tzap-online"))]
use std::process::Command;

#[test]
// Auth-command argument handling only exists in the full build; the
// offline binary's `zm auth` is a stub that rejects everything.
#[cfg(feature = "tzap-online")]
fn test_missing_argument_value_does_not_panic() {
    let output = Command::new(env!("CARGO_BIN_EXE_zm"))
        .arg("auth")
        .arg("login")
        .arg("--state-dir")
        // Missing the actual value for --state-dir
        .output()
        .expect("Failed to execute zm");

    // It should exit with a non-zero code (1), not a panic (e.g. 101)
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Check that it didn't panic (Rust panics usually contain "thread 'main' panicked")
    assert!(!stderr.contains("panicked"));
    assert!(stderr.contains("missing value for"));
}

#[cfg(not(feature = "tzap-online"))]
#[test]
fn reduced_profile_reports_hosted_auth_as_unavailable() {
    let output = Command::new(env!("CARGO_BIN_EXE_zm")).args(["auth", "login"]).output().expect("Failed to execute zm");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("does not include online identity features"));
}
