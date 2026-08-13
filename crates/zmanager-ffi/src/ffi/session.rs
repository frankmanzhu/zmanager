//! Retained FFI archive sessions for stateful open/list/close lifecycle (ARC-204).

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use zmanager_core::engine::{ArchiveError, ArchiveHandle, ArchiveListing, ArchiveSource, ErrorKind, OpenOptions, create_default_engine};

const MAX_RETAINED_SESSIONS: usize = 64;

static SESSION_REGISTRY: OnceLock<Mutex<ArchiveSessionRegistry>> = OnceLock::new();

/// Returns the global singleton `ArchiveSessionRegistry`.
pub fn session_registry() -> &'static Mutex<ArchiveSessionRegistry> {
    SESSION_REGISTRY.get_or_init(|| Mutex::new(ArchiveSessionRegistry::default()))
}

/// In-process registry of retained stateful archive session handles (ARC-204).
///
/// Each session wraps a live [`ArchiveHandle`] opened against a specific source
/// and keeps it alive until an explicit `close_session` call. The registry
/// enforces a hard ceiling of [`MAX_RETAINED_SESSIONS`] to prevent unbounded
/// handle accumulation in long-running FFI host processes.
#[derive(Default)]
pub struct ArchiveSessionRegistry {
    next_index: u64,
    sessions: HashMap<String, ArchiveHandle>,
}

impl ArchiveSessionRegistry {
    /// Opens a new stateful archive handle session and registers it.
    ///
    /// A unique `session_id` string is returned for subsequent `list_session` /
    /// `close_session` calls.
    ///
    /// # Errors
    ///
    /// Returns an error string if:
    /// - the session count ceiling is reached (`MAX_RETAINED_SESSIONS`),
    /// - engine construction fails, or
    /// - the underlying `open` call fails (e.g., unrecognised format or missing path).
    pub fn open_session(&mut self, source: ArchiveSource, options: OpenOptions) -> Result<String, ArchiveError> {
        if self.sessions.len() >= MAX_RETAINED_SESSIONS {
            return Err(ArchiveError::usable(
                ErrorKind::ResourceLimitExceeded,
                format!("Session limit reached: maximum {MAX_RETAINED_SESSIONS} active archive sessions allowed"),
            ));
        }

        let engine = create_default_engine()?;
        let handle = engine.open(source, options)?;

        self.next_index = self.next_index.wrapping_add(1);
        let id = format!("session-{}", self.next_index);
        self.sessions.insert(id.clone(), handle);
        Ok(id)
    }

    /// Lists entries from an active session handle.
    ///
    /// # Errors
    ///
    /// Returns an error string if the session ID is unknown or listing fails.
    pub fn list_session(&mut self, session_id: &str) -> Result<ArchiveListing, ArchiveError> {
        let handle = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| ArchiveError::usable(ErrorKind::InvalidFormat, format!("Unknown or closed archive session: '{session_id}'")))?;
        handle.list()
    }

    /// Explicitly closes and removes a session handle, releasing underlying resources.
    ///
    /// # Errors
    ///
    /// Returns an error string if the session ID is unknown or the close call fails.
    pub fn close_session(&mut self, session_id: &str) -> Result<(), ArchiveError> {
        let handle = self
            .sessions
            .remove(session_id)
            .ok_or_else(|| ArchiveError::usable(ErrorKind::InvalidFormat, format!("Unknown or closed archive session: '{session_id}'")))?;
        handle.close()
    }

    /// Returns the number of currently active session handles.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.sessions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture_path(name: &str) -> PathBuf {
        // Resolve relative to the workspace root from CARGO_MANIFEST_DIR
        let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
        PathBuf::from(manifest).join("../../fixtures/archives").join(name)
    }

    #[test]
    fn session_open_list_close_basic_zip() {
        let zip_path = fixture_path("basic.zip");
        if !zip_path.exists() {
            // Fixture absent in this environment; skip gracefully.
            return;
        }

        let mut reg = ArchiveSessionRegistry::default();
        assert_eq!(reg.active_count(), 0);

        let source = ArchiveSource::from_path_autodetect(&zip_path);
        let session_id = reg.open_session(source, OpenOptions::default()).expect("open_session should succeed for basic.zip");

        assert_eq!(reg.active_count(), 1);

        let listing = reg.list_session(&session_id).expect("list_session should return entries");
        assert!(!listing.entries.is_empty(), "basic.zip should contain at least one entry");

        reg.close_session(&session_id).expect("close_session should succeed");
        assert_eq!(reg.active_count(), 0);
    }

    #[test]
    fn list_unknown_session_returns_error() {
        let mut reg = ArchiveSessionRegistry::default();
        let result = reg.list_session("session-999");
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.message.contains("session-999"), "Error should mention the unknown session ID");
    }

    #[test]
    fn close_unknown_session_returns_error() {
        let mut reg = ArchiveSessionRegistry::default();
        let result = reg.close_session("session-999");
        assert!(result.is_err());
    }
}
