use super::support::rfc3339_utc_to_unix_seconds;

#[test]
fn rfc3339_parses_valid_utc_timestamps() {
    assert_eq!(rfc3339_utc_to_unix_seconds("1970-01-01T00:00:00Z").unwrap(), 0);
    assert_eq!(rfc3339_utc_to_unix_seconds("1970-01-01T00:00:00.123Z").unwrap(), 0);
    assert_eq!(rfc3339_utc_to_unix_seconds("2024-02-29T12:34:56Z").unwrap(), 1_709_210_096);
}

#[test]
fn rfc3339_rejects_invalid_calendar_values() {
    for value in
        ["2026-13-01T00:00:00Z", "2026-00-01T00:00:00Z", "2026-02-30T00:00:00Z", "2025-02-29T00:00:00Z", "2026-04-31T00:00:00Z", "2026-06-01T24:00:00Z", "2026-06-01T00:60:00Z", "2026-06-01T00:00:60Z"]
    {
        assert!(rfc3339_utc_to_unix_seconds(value).is_err(), "expected rejection for {value}");
    }
}

#[test]
fn rfc3339_rejects_malformed_timestamps() {
    for value in ["2026-06-01T00:00:00", "2026-06-01", "not-a-timestamp", "2026-06-01T00:00:00+02:00"] {
        assert!(rfc3339_utc_to_unix_seconds(value).is_err(), "expected rejection for {value}");
    }
}
