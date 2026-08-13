//! Stateful archive handle lifecycle and engine entry points (ARC-105).

use std::sync::Arc;

use crate::archive_format::detect_archive_format;
use crate::engine::format::FormatId;
use crate::engine::registry::{AdapterRegistry, ReadAdapterFactory};
use crate::engine::source::ArchiveSource;
use crate::engine::types::{ArchiveError, ArchiveListing, ArchiveOperation, DetectedArchive, ErrorKind, HandleCapabilities, SessionDisposition};

/// Options supplied when opening an archive handle.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct OpenOptions {
    /// Optional password for encrypted headers or entries.
    pub password: Option<String>,
}

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

    /// Opens an archive handle for the given source path or volume set (ARC-105).
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError`] if format detection fails or no adapter is registered.
    pub fn open(&self, source: ArchiveSource, options: OpenOptions) -> Result<ArchiveHandle, ArchiveError> {
        let primary_path = source.primary_path();
        if !primary_path.exists() {
            return Err(ArchiveError::usable(ErrorKind::Io, format!("Archive path does not exist: {}", primary_path.display())).with_path(primary_path));
        }

        let kind = detect_archive_format(primary_path);
        let format_id: Option<FormatId> = kind.into();
        let format = format_id.ok_or_else(|| {
            ArchiveError::usable(ErrorKind::InvalidFormat, format!("Unsupported or unrecognized archive format for {}", primary_path.display()))
                .with_path(primary_path)
        })?;

        let detected = DetectedArchive { format, source };

        Ok(ArchiveHandle { engine_registry: self.registry.clone(), detected, options, cached_session: None, disposition: SessionDisposition::Usable })
    }
}

/// Stateful handle representing an opened archive session (ARC-105).
pub struct ArchiveHandle {
    engine_registry: AdapterRegistry,
    detected: DetectedArchive,
    options: OpenOptions,
    cached_session: Option<Arc<dyn ReadAdapterFactory>>,
    disposition: SessionDisposition,
}

impl std::fmt::Debug for ArchiveHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArchiveHandle")
            .field("detected", &self.detected)
            .field("disposition", &self.disposition)
            .finish_non_exhaustive()
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

        match factory.list(&self.detected, self.options.password.as_deref()) {
            Ok(listing) => Ok(listing),
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
        Ok(())
    }
}
