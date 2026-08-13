//! Stateful archive handle lifecycle and engine entry points (ARC-105).

use std::io::Write;
use std::sync::Arc;

use crate::archive_format::detect_archive_format;
use crate::engine::format::FormatId;
use crate::engine::registry::{AdapterRegistry, ReadAdapterFactory};
use crate::engine::source::ArchiveSource;
use crate::engine::types::{
    ArchiveError, ArchiveListing, ArchiveOperation, CopyReport, DetectedArchive, EntryId, ErrorKind, ExtractOptions, ExtractReport, HandleCapabilities,
    OpenOptions, SelectedExtractOptions, SessionDisposition, TestOptions, TestReport,
};

/// The stateful archive engine instance.
#[derive(Clone, Debug)]
pub struct ArchiveEngine {
    registry: AdapterRegistry,
}

impl ArchiveEngine {
    /// Creates a new `ArchiveEngine` wrapping an immutable `AdapterRegistry`.
    #[must_use]
    pub const fn new(registry: AdapterRegistry) -> Self {
        Self { registry }
    }

    /// Accesses the underlying registry.
    #[must_use]
    pub fn registry(&self) -> &AdapterRegistry {
        &self.registry
    }

    /// Returns the immutable operation capability snapshot for this engine.
    #[must_use]
    pub fn capability_snapshot(&self) -> Vec<crate::engine::types::FormatCapabilities> {
        self.registry.capability_snapshot()
    }

    /// Opens an archive handle for the given source path or volume set (ARC-105).
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError`] if format detection fails or no adapter is registered.
    pub fn open(&self, source: ArchiveSource, options: OpenOptions) -> Result<ArchiveHandle, ArchiveError> {
        let primary_path = source.primary_path();
        let kind = detect_archive_format(primary_path);
        let source_exists = primary_path.exists()
            || (matches!(kind, crate::archive_format::ArchiveFormatKind::SevenZ) && crate::sevenz_backend::has_existing_7z_input(primary_path));
        if !source_exists {
            return Err(ArchiveError::usable(ErrorKind::Io, format!("Archive path does not exist: {}", primary_path.display())).with_path(primary_path));
        }

        let format_id: Option<FormatId> = kind.into();
        let format = format_id.ok_or_else(|| {
            ArchiveError::usable(ErrorKind::InvalidFormat, format!("Unsupported or unrecognized archive format for {}", primary_path.display()))
                .with_path(primary_path)
        })?;

        let detected = DetectedArchive { format, source };

        Ok(ArchiveHandle {
            engine_registry: self.registry.clone(),
            detected,
            options,
            cached_session: None,
            cached_test_session: None,
            cached_extract_session: None,
            cached_selected_extract_session: None,
            cached_copy_session: None,
            disposition: SessionDisposition::Usable,
        })
    }
}

/// Stateful handle representing an opened archive session (ARC-105).
pub struct ArchiveHandle {
    engine_registry: AdapterRegistry,
    detected: DetectedArchive,
    options: OpenOptions,
    cached_session: Option<Arc<dyn ReadAdapterFactory>>,
    cached_test_session: Option<Arc<dyn ReadAdapterFactory>>,
    cached_extract_session: Option<Arc<dyn ReadAdapterFactory>>,
    cached_selected_extract_session: Option<Arc<dyn ReadAdapterFactory>>,
    cached_copy_session: Option<Arc<dyn ReadAdapterFactory>>,
    disposition: SessionDisposition,
}

impl std::fmt::Debug for ArchiveHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArchiveHandle").field("detected", &self.detected).field("disposition", &self.disposition).finish_non_exhaustive()
    }
}

impl ArchiveHandle {
    /// Returns the detected archive format and source layout.
    #[must_use]
    pub const fn detected(&self) -> &DetectedArchive {
        &self.detected
    }

    /// Returns the current session disposition (`Usable` or `Unusable`).
    #[must_use]
    pub const fn disposition(&self) -> SessionDisposition {
        self.disposition
    }

    /// Returns handle capabilities derived from registered adapter descriptors.
    #[must_use]
    pub fn capabilities(&self) -> Option<HandleCapabilities> {
        self.engine_registry.capabilities_for_format(self.detected.format)
    }

    /// Lists archive entries using the bound adapter (ARC-105, ARC-108).
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError`] if the session is unusable or listing fails.
    pub fn list(&mut self) -> Result<ArchiveListing, ArchiveError> {
        if self.disposition == SessionDisposition::Unusable {
            return Err(ArchiveError::unusable(ErrorKind::CorruptData, "Archive handle session is unusable; close and reopen the archive"));
        }

        let factory = if let Some(factory) = &self.cached_session {
            factory.clone()
        } else {
            let factory = self.engine_registry.resolve(self.detected.format, ArchiveOperation::List).ok_or_else(|| {
                ArchiveError::usable(ErrorKind::UnsupportedOperation, format!("No listing adapter registered for format '{}'", self.detected.format))
            })?;
            self.cached_session = Some(factory.clone());
            factory
        };

        match factory.list(&self.detected, &self.options) {
            Ok(listing) => Ok(listing),
            Err(error) => {
                if error.disposition == SessionDisposition::Unusable {
                    self.disposition = SessionDisposition::Unusable;
                }
                Err(error)
            }
        }
    }

    /// Verifies archive data using the adapter bound to this session.
    pub fn test(&mut self, options: &TestOptions) -> Result<TestReport, ArchiveError> {
        if self.disposition == SessionDisposition::Unusable {
            return Err(ArchiveError::unusable(ErrorKind::CorruptData, "Archive handle session is unusable; close and reopen the archive"));
        }
        if options.is_cancelled() {
            return Err(ArchiveError::usable(ErrorKind::Cancelled, "Archive test was cancelled"));
        }

        let factory = if let Some(factory) = &self.cached_test_session {
            factory.clone()
        } else {
            let factory = self.engine_registry.resolve(self.detected.format, ArchiveOperation::Test).ok_or_else(|| {
                ArchiveError::usable(ErrorKind::UnsupportedOperation, format!("No data-test adapter registered for format '{}'", self.detected.format))
            })?;
            self.cached_test_session = Some(factory.clone());
            factory
        };

        match factory.test(&self.detected, &self.options, options) {
            Ok(report) => Ok(report),
            Err(error) => {
                if error.disposition == SessionDisposition::Unusable {
                    self.disposition = SessionDisposition::Unusable;
                }
                Err(error)
            }
        }
    }

    /// Extracts the complete archive using the adapter bound to this session.
    pub fn extract<'a>(&mut self, options: &'a mut ExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        if self.disposition == SessionDisposition::Unusable {
            return Err(ArchiveError::unusable(ErrorKind::CorruptData, "Archive handle session is unusable; close and reopen the archive"));
        }
        if options.destination.as_os_str().is_empty() {
            return Err(ArchiveError::usable(ErrorKind::Io, "Extraction destination must not be empty"));
        }
        if options.is_cancelled() {
            return Err(ArchiveError::usable(ErrorKind::Cancelled, "Archive extraction was cancelled"));
        }

        // Keep credentials bound to the opened session available to the
        // normalized extraction request without borrowing the handle while an
        // overwrite resolver is active.
        if options.recipient_key.is_none() {
            options.recipient_key.clone_from(&self.options.recipient_key);
        }
        if options.tzap_password.is_none() {
            options.tzap_password.clone_from(&self.options.password);
        }

        let factory = if let Some(factory) = &self.cached_extract_session {
            factory.clone()
        } else {
            let factory = self.engine_registry.resolve(self.detected.format, ArchiveOperation::Extract).ok_or_else(|| {
                ArchiveError::usable(ErrorKind::UnsupportedOperation, format!("No extraction adapter registered for format '{}'", self.detected.format))
            })?;
            self.cached_extract_session = Some(factory.clone());
            factory
        };

        match factory.extract(&self.detected, &self.options, options) {
            Ok(report) => Ok(report),
            Err(error) => {
                if error.disposition == SessionDisposition::Unusable {
                    self.disposition = SessionDisposition::Unusable;
                }
                Err(error)
            }
        }
    }

    /// Extracts one retained entry by its session-scoped ID.
    pub fn extract_selected<'a>(&mut self, entry_id: EntryId, options: &'a mut SelectedExtractOptions<'a>) -> Result<ExtractReport, ArchiveError> {
        if self.disposition == SessionDisposition::Unusable {
            return Err(ArchiveError::unusable(ErrorKind::CorruptData, "Archive handle session is unusable; close and reopen the archive"));
        }
        if options.destination.as_os_str().is_empty() {
            return Err(ArchiveError::usable(ErrorKind::Io, "Extraction destination must not be empty"));
        }
        if options.cancellation.as_ref().is_some_and(crate::jobs::CancellationToken::is_cancelled) {
            return Err(ArchiveError::usable(ErrorKind::Cancelled, "Archive extraction was cancelled"));
        }
        let factory = if let Some(factory) = &self.cached_selected_extract_session {
            factory.clone()
        } else {
            let factory = self.engine_registry.resolve(self.detected.format, ArchiveOperation::SelectedExtract).ok_or_else(|| {
                ArchiveError::usable(
                    ErrorKind::UnsupportedOperation,
                    format!("No selected extraction adapter registered for format '{}'", self.detected.format),
                )
            })?;
            self.cached_selected_extract_session = Some(factory.clone());
            factory
        };
        match factory.selected_extract(&self.detected, &self.options, entry_id, options) {
            Ok(report) => Ok(report),
            Err(error) => {
                if error.disposition == SessionDisposition::Unusable {
                    self.disposition = SessionDisposition::Unusable;
                }
                Err(error)
            }
        }
    }

    /// Copies one retained regular-file entry to a caller-owned writer.
    pub fn copy_entry(&mut self, entry_id: EntryId, writer: &mut dyn Write) -> Result<CopyReport, ArchiveError> {
        if self.disposition == SessionDisposition::Unusable {
            return Err(ArchiveError::unusable(ErrorKind::CorruptData, "Archive handle session is unusable; close and reopen the archive"));
        }
        let factory = if let Some(factory) = &self.cached_copy_session {
            factory.clone()
        } else {
            let factory = self.engine_registry.resolve(self.detected.format, ArchiveOperation::CopyToWriter).ok_or_else(|| {
                ArchiveError::usable(ErrorKind::UnsupportedOperation, format!("No writer-copy adapter registered for format '{}'", self.detected.format))
            })?;
            self.cached_copy_session = Some(factory.clone());
            factory
        };
        match factory.copy_to_writer(&self.detected, &self.options, entry_id, writer) {
            Ok(report) => Ok(report),
            Err(error) => {
                if error.disposition == SessionDisposition::Unusable {
                    self.disposition = SessionDisposition::Unusable;
                }
                Err(error)
            }
        }
    }

    /// Consumes the handle and explicitly closes the archive session (ARC-105).
    ///
    /// # Errors
    ///
    /// Returns `Ok(())` on clean close or `ArchiveError` on cleanup failure.
    pub fn close(mut self) -> Result<(), ArchiveError> {
        self.cached_session = None;
        self.cached_test_session = None;
        self.cached_extract_session = None;
        self.cached_selected_extract_session = None;
        self.cached_copy_session = None;
        Ok(())
    }
}
