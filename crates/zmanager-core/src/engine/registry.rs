//! Immutable operation registry and engine builder (ARC-104).

use crate::engine::format::FormatId;
use crate::engine::source::SourceAccess;
use crate::engine::types::{
    ArchiveError, ArchiveListing, ArchiveOperation, CopyReport, DetectedArchive, EntryId, ErrorKind, ExtractOptions, ExtractReport, FormatCapabilities,
    HandleCapabilities, OpenOptions, SelectedExtractOptions, TestOptions, TestReport,
};
use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;

/// Static metadata descriptor for an archive adapter.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct AdapterDescriptor {
    /// Opaque name/identifier for the adapter implementation.
    pub name: &'static str,
    /// Supported format identifier.
    pub format: FormatId,
    /// Supported operation set.
    pub operations: &'static [ArchiveOperation],
    /// Required source access capability.
    pub required_source_access: SourceAccess,
    /// Whether encryption is supported by this adapter.
    pub supports_encryption: bool,
}

/// Abstract factory trait implemented by read archive adapters.
pub trait ReadAdapterFactory: Send + Sync {
    /// Returns static metadata descriptor for this adapter.
    fn descriptor(&self) -> &'static AdapterDescriptor;

    /// Lists entries for the given detected archive and optional password.
    fn list(&self, archive: &DetectedArchive, options: &OpenOptions) -> Result<ArchiveListing, ArchiveError>;

    /// Verifies selected entry payloads and integrity metadata.
    fn test(&self, _archive: &DetectedArchive, _open_options: &OpenOptions, _test_options: &TestOptions) -> Result<TestReport, ArchiveError> {
        Err(ArchiveError::usable(ErrorKind::UnsupportedOperation, "archive adapter does not provide data verification"))
    }

    /// Extracts the complete archive through the adapter's safety pipeline.
    fn extract<'a>(
        &self,
        _archive: &DetectedArchive,
        _open_options: &OpenOptions,
        _options: &'a mut ExtractOptions<'a>,
    ) -> Result<ExtractReport, ArchiveError> {
        Err(ArchiveError::usable(ErrorKind::UnsupportedOperation, "archive adapter does not provide full extraction"))
    }

    /// Extracts one entry selected by its retained session ID.
    fn selected_extract<'a>(
        &self,
        _archive: &DetectedArchive,
        _open_options: &OpenOptions,
        _entry_id: EntryId,
        _options: &'a mut SelectedExtractOptions<'a>,
    ) -> Result<ExtractReport, ArchiveError> {
        Err(ArchiveError::usable(ErrorKind::UnsupportedOperation, "archive adapter does not provide selected extraction"))
    }

    /// Copies one regular-file entry selected by its retained session ID.
    fn copy_to_writer(
        &self,
        _archive: &DetectedArchive,
        _open_options: &OpenOptions,
        _entry_id: EntryId,
        _writer: &mut dyn Write,
    ) -> Result<CopyReport, ArchiveError> {
        Err(ArchiveError::usable(ErrorKind::UnsupportedOperation, "archive adapter does not provide writer copy"))
    }
}

/// Immutable registry mapping `(FormatId, ArchiveOperation)` to an adapter factory.
#[derive(Clone)]
pub struct AdapterRegistry {
    registrations: HashMap<(FormatId, ArchiveOperation), Arc<dyn ReadAdapterFactory>>,
}

impl fmt::Debug for AdapterRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdapterRegistry").field("registration_count", &self.registrations.len()).finish()
    }
}

use std::fmt;

impl AdapterRegistry {
    /// Resolves an adapter factory for `(FormatId, ArchiveOperation)` deterministically.
    #[must_use]
    pub fn resolve(&self, format: FormatId, operation: ArchiveOperation) -> Option<Arc<dyn ReadAdapterFactory>> {
        self.registrations.get(&(format, operation)).cloned()
    }

    /// Derives capabilities for a given format from registered adapters.
    #[must_use]
    pub fn capabilities_for_format(&self, format: FormatId) -> Option<HandleCapabilities> {
        let mut ops = Vec::new();
        let mut source_access = SourceAccess::Seekable;
        let mut encryption = false;
        let mut found = false;

        for ((reg_format, op), factory) in &self.registrations {
            if *reg_format == format {
                found = true;
                ops.push(*op);
                let desc = factory.descriptor();
                source_access = desc.required_source_access;
                if desc.supports_encryption {
                    encryption = true;
                }
            }
        }

        if found { Some(HandleCapabilities { format, source_access, operations: ops, encryption_supported: encryption }) } else { None }
    }

    /// Returns one capability row for every canonical recognized format.
    #[must_use]
    pub fn capability_snapshot(&self) -> Vec<FormatCapabilities> {
        crate::archive_format::FORMAT_CAPABILITIES
            .iter()
            .filter_map(|capability| {
                let format = FormatId::from_archive_format_kind(capability.kind)?;
                let registered = self.capabilities_for_format(format);
                let (platform_available, unavailable_reason) = match crate::archive_format::format_status(capability.kind) {
                    crate::archive_format::BackendStatus::Available => (registered.is_some(), None),
                    crate::archive_format::BackendStatus::UnsupportedPlatform => (false, Some("unsupported platform".to_owned())),
                    crate::archive_format::BackendStatus::Unavailable { reason } => (false, Some(reason.to_owned())),
                };
                let unavailable_reason = unavailable_reason.or_else(|| (!platform_available).then(|| "no registered operation adapter".to_owned()));
                Some(FormatCapabilities {
                    format,
                    recognized: true,
                    platform_available,
                    unavailable_reason,
                    operations: registered.as_ref().map_or_else(Vec::new, |value| value.operations.clone()),
                    source_access: registered.as_ref().map(|value| value.source_access),
                    encryption_supported: registered.is_some_and(|value| value.encryption_supported),
                })
            })
            .collect()
    }
}

/// Builder for constructing an immutable `AdapterRegistry` (ARC-104).
#[derive(Default)]
pub struct ArchiveEngineBuilder {
    registrations: HashMap<(FormatId, ArchiveOperation), Arc<dyn ReadAdapterFactory>>,
}

impl ArchiveEngineBuilder {
    /// Creates a new empty `ArchiveEngineBuilder`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a read adapter factory for all operations declared in its descriptor.
    ///
    /// # Errors
    ///
    /// Returns `ArchiveError` if an operation claim for `(FormatId, ArchiveOperation)` is ambiguous / duplicated.
    #[allow(clippy::needless_pass_by_value)]
    pub fn register_read_adapter(&mut self, factory: Arc<dyn ReadAdapterFactory>) -> Result<(), ArchiveError> {
        let desc = factory.descriptor();
        for &op in desc.operations {
            let key = (desc.format, op);
            if self.registrations.contains_key(&key) {
                return Err(ArchiveError::usable(
                    ErrorKind::InvalidFormat,
                    format!("Ambiguous registration: operation '{op:?}' for format '{}' is already claimed", desc.format),
                ));
            }
            self.registrations.insert(key, factory.clone());
        }
        Ok(())
    }

    /// Builds the immutable `AdapterRegistry`.
    #[must_use]
    pub fn build(self) -> AdapterRegistry {
        AdapterRegistry { registrations: self.registrations }
    }
}
