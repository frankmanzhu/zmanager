//! Immutable operation registry and engine builder (ARC-104).

use crate::engine::format::FormatId;
use crate::engine::source::SourceAccess;
use crate::engine::types::{ArchiveError, ArchiveOperation, DetectedArchive, ErrorKind, HandleCapabilities};
use std::collections::HashMap;
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
    fn list(&self, archive: &DetectedArchive, password: Option<&str>) -> Result<crate::engine::types::ArchiveListing, ArchiveError>;
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
