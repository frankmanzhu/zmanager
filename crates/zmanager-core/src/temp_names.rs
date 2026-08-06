//! Shared temporary file and directory name generation.
//!
//! The archive backends need unique, process-scoped temporary names for
//! decoded intermediates and preview roots. These were historically generated
//! inline with pid-plus-nanoseconds schemes duplicated in three places; the
//! core helper lives here so the schemes cannot drift.

use std::time::{SystemTime, UNIX_EPOCH};

/// Builds a unique temporary name component: `{label}-{pid}-{nanos}`.
///
/// `nanos` is the current Unix timestamp in nanoseconds at call time. In
/// theory two calls in the same process in the same nanosecond collide;
/// callers that create directories or files must retry on `AlreadyExists`
/// when they need to be robust (see `raw_stream_backend::TemporaryDirectory`).
pub(crate) fn unique_temp_name(label: &str) -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_nanos());
    format!("{label}-{}-{now}", std::process::id())
}
