//! The registry's `LocalSend` identity must survive a restart.
//!
//! A `LocalSend` device *is* its certificate fingerprint: peers store it,
//! de-duplicate their device lists on it, and pin it. An identity regenerated
//! per launch makes `ZManager` a new device to every peer on every start.
//!
//! This is its own integration binary because the registry is a process-wide
//! singleton whose identity is materialised once — the "second launch" here is
//! a fresh load from the same directory, which is exactly what a real restart
//! does.

use std::path::Path;

/// Reads the identity a shell would find on its next launch.
fn identity_on_disk(directory: &Path) -> localsend_rs::TlsCertificate {
    localsend_rs::load_or_generate_tls_certificate(directory.join("certificate.pem"), directory.join("private-key.pem"))
        .expect("the persisted identity must be readable")
}

#[test]
fn identity_persists_and_reconfiguration_is_refused() {
    let directory = tempfile::tempdir().expect("temporary application-data directory");

    zmanager_localsend::registry().set_identity_dir(directory.path()).expect("configure the identity directory");

    // A shell that starts again against the same directory is the same device.
    let first_launch = identity_on_disk(directory.path());
    let second_launch = identity_on_disk(directory.path());
    assert_eq!(first_launch.fingerprint, second_launch.fingerprint, "a restart must not change this device's fingerprint");
    assert!(!first_launch.fingerprint.is_empty());

    assert!(directory.path().join("certificate.pem").exists());
    assert!(directory.path().join("private-key.pem").exists());
    let other = tempfile::tempdir().expect("a second directory");

    let second = zmanager_localsend::registry().set_identity_dir(other.path());

    assert!(second.is_err(), "reconfiguring an in-use identity must be refused");
}
