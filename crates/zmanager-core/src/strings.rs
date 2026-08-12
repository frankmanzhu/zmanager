//! Shared case-insensitive string helpers.
//!
//! The archive backends compare suffixes without case (`.TZST` vs `.tzst`,
//! `.TAR.ZST` vs `.tar.zst`, container suffixes) and previously shipped two
//! copies of these helpers.

/// Returns whether `value` ends with `suffix`, ignoring ASCII case.
#[must_use]
pub(crate) fn ends_with_ignore_ascii_case(value: &str, suffix: &str) -> bool {
    strip_suffix_ignore_ascii_case(value, suffix).is_some()
}

/// Strips `suffix` from `value` when it is present, ignoring ASCII case.
#[must_use]
pub(crate) fn strip_suffix_ignore_ascii_case<'a>(value: &'a str, suffix: &str) -> Option<&'a str> {
    let suffix = suffix.as_bytes();
    if value.len() >= suffix.len() && value.as_bytes()[value.len() - suffix.len()..].eq_ignore_ascii_case(suffix) { Some(&value[..value.len() - suffix.len()]) } else { None }
}
