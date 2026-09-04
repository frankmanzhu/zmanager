use super::support::rfc3339_utc_to_unix_seconds;
use crate::cli::options::GlobalOptions;
#[cfg(feature = "tzap-online")]
use crate::cli::tzap::auth::auth_command;
#[cfg(feature = "tzap-online")]
use crate::cli::tzap::cert::cert_command;
use crate::cli::tzap::certs::certs_command;
use crate::cli::tzap::contacts::contact_command;
#[cfg(feature = "tzap-online")]
use crate::cli::tzap::device::device_command;
use crate::cli::tzap::share::share_command;
use crate::cli::tzap::sign::sign_command;
use std::process::ExitCode;

#[test]
fn rfc3339_parses_valid_utc_timestamps() {
    assert_eq!(rfc3339_utc_to_unix_seconds("1970-01-01T00:00:00Z").unwrap(), 0);
    assert_eq!(rfc3339_utc_to_unix_seconds("1970-01-01T00:00:00.123Z").unwrap(), 0);
    assert_eq!(rfc3339_utc_to_unix_seconds("2024-02-29T12:34:56Z").unwrap(), 1_709_210_096);
}

#[test]
fn rfc3339_rejects_invalid_calendar_values() {
    for value in [
        "2026-13-01T00:00:00Z",
        "2026-00-01T00:00:00Z",
        "2026-02-30T00:00:00Z",
        "2025-02-29T00:00:00Z",
        "2026-04-31T00:00:00Z",
        "2026-06-01T24:00:00Z",
        "2026-06-01T00:60:00Z",
        "2026-06-01T00:00:60Z",
    ] {
        assert!(rfc3339_utc_to_unix_seconds(value).is_err(), "expected rejection for {value}");
    }
}

#[test]
fn rfc3339_rejects_malformed_timestamps() {
    for value in ["2026-06-01T00:00:00", "2026-06-01", "not-a-timestamp", "2026-06-01T00:00:00+02:00"] {
        assert!(rfc3339_utc_to_unix_seconds(value).is_err(), "expected rejection for {value}");
    }
}

#[test]
fn test_cli_tzap_subcommands_help_and_errors() {
    // Share command
    assert_eq!(share_command(&["--help".to_string()], GlobalOptions::default()), ExitCode::SUCCESS);
    assert_eq!(share_command(&[], GlobalOptions::default()), ExitCode::from(2));
    assert_eq!(share_command(&["out.tzap".to_string()], GlobalOptions::default()), ExitCode::from(2));

    // Contact command
    assert_eq!(contact_command(&[], GlobalOptions::default()), ExitCode::from(2));
    assert_eq!(contact_command(&["--help".to_string()], GlobalOptions::default()), ExitCode::SUCCESS);
    assert_eq!(contact_command(&["unknown".to_string()], GlobalOptions::default()), ExitCode::from(2));
    assert_eq!(contact_command(&["remove".to_string()], GlobalOptions::default()), ExitCode::from(2));

    // Sign command
    assert_eq!(sign_command(&["--help".to_string()], GlobalOptions::default()), ExitCode::SUCCESS);
    assert_eq!(sign_command(&[], GlobalOptions::default()), ExitCode::from(2));

    // Certs command (reads the local catalogue, no network)
    assert_eq!(certs_command(&["--help".to_string()], GlobalOptions::default()), ExitCode::SUCCESS);
}

#[cfg(feature = "tzap-online")]
#[test]
fn test_cli_auth_subcommands_help_and_errors() {
    // Device command
    assert_eq!(device_command(&[], GlobalOptions::default()), ExitCode::from(2));
    assert_eq!(device_command(&["--help".to_string()], GlobalOptions::default()), ExitCode::SUCCESS);
    assert_eq!(device_command(&["unknown".to_string()], GlobalOptions::default()), ExitCode::from(2));
    assert_eq!(device_command(&["revoke".to_string()], GlobalOptions::default()), ExitCode::from(2));

    // Auth command
    assert_eq!(auth_command(&[], GlobalOptions::default()), ExitCode::from(2));
    assert_eq!(auth_command(&["--help".to_string()], GlobalOptions::default()), ExitCode::SUCCESS);
    assert_eq!(auth_command(&["unknown".to_string()], GlobalOptions::default()), ExitCode::from(2));

    // Cert command
    assert_eq!(cert_command(&[], GlobalOptions::default()), ExitCode::from(2));
    assert_eq!(cert_command(&["--help".to_string()], GlobalOptions::default()), ExitCode::SUCCESS);
    assert_eq!(cert_command(&["unknown".to_string()], GlobalOptions::default()), ExitCode::from(2));
}
