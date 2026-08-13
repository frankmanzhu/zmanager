//! Stateful archive engine and adapter seam (ARC-100 to ARC-111).

pub mod adapters;
pub mod format;
pub mod handle;
pub mod plugins;
pub mod registry;
pub mod source;
pub mod types;

use std::sync::Arc;

pub use format::FormatId;
pub use handle::{ArchiveEngine, ArchiveHandle, OpenOptions};
pub use plugins::{ArchivePlugin, build_engine_with_plugins};
pub use registry::{AdapterDescriptor, AdapterRegistry, ArchiveEngineBuilder, ReadAdapterFactory};
pub use source::{ArchiveSource, SourceAccess, discover_split_zip_volumes, is_split_zip_archive_path};
pub use types::{ArchiveError, ArchiveListing, ArchiveOperation, DetectedArchive, EngineEntry, EntryId, ErrorKind, HandleCapabilities, SessionDisposition};

/// Default compile-time plugin packaging for Phase 1 listing.
#[derive(Debug, Default)]
pub struct DefaultArchivePlugin;

impl ArchivePlugin for DefaultArchivePlugin {
    fn name(&self) -> &'static str {
        "default_archive_plugin"
    }

    fn register(&self, builder: &mut ArchiveEngineBuilder) -> Result<(), ArchiveError> {
        // Native ZIP adapters
        builder.register_read_adapter(Arc::new(adapters::zip::ZipListAdapter::single_volume()))?;
        builder.register_read_adapter(Arc::new(adapters::zip::ZipListAdapter::split_volume()))?;

        // Libarchive compatibility listing adapters for allow-listed formats
        for &format in adapters::libarchive::LIBARCHIVE_ALLOW_LIST {
            if let Ok(adapter) = adapters::libarchive::LibarchiveListAdapter::new(format) {
                builder.register_read_adapter(Arc::new(adapter))?;
            }
        }

        Ok(())
    }
}

/// Creates a default pre-configured `ArchiveEngine` containing Phase 1 listing adapters.
///
/// # Errors
///
/// Returns `ArchiveError` if plugin registration fails.
pub fn create_default_engine() -> Result<ArchiveEngine, ArchiveError> {
    build_engine_with_plugins(&[&DefaultArchivePlugin])
}
