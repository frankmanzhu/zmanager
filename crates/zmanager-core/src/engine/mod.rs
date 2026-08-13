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
pub use handle::{ArchiveEngine, ArchiveHandle};
pub use plugins::{ArchivePlugin, build_engine_with_plugins};
pub use registry::{AdapterDescriptor, AdapterRegistry, ArchiveEngineBuilder, CreateAdapterFactory, ReadAdapterFactory};
pub use source::{ArchiveSource, SourceAccess, discover_split_zip_volumes, is_split_zip_archive_path};
pub use types::{
    ArchiveError, ArchiveListing, ArchiveOperation, ArchivePluginRole, CopyReport, CreateOptions, CreateReport, CreateRequest, DetectedArchive, EngineEntry,
    EntryId, ErrorKind, ExtractOptions, ExtractReport, FormatCapabilities, HandleCapabilities, OpenOptions, SelectedExtractOptions, SessionDisposition,
    TestOptions, TestReport,
};

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

        // Native adapters for 7z, TAR.ZST, TZAP, RAR, RawStreams, Apple Archive, DMG, PKG, MSI, VirtualDisks
        builder.register_read_adapter(Arc::new(adapters::native::SevenZListAdapter))?;
        builder.register_read_adapter(Arc::new(adapters::native::TarZstListAdapter))?;
        builder.register_read_adapter(Arc::new(adapters::native::TarGzListAdapter))?;
        builder.register_read_adapter(Arc::new(adapters::native::TarListAdapter))?;
        builder.register_read_adapter(Arc::new(adapters::native::FilteredTarAdapter::new(
            FormatId::TAR_BZ2,
            crate::raw_stream_backend::RawStreamFormat::Bzip2,
            "bzip2",
        )))?;
        builder.register_read_adapter(Arc::new(adapters::native::FilteredTarAdapter::new(
            FormatId::TAR_XZ,
            crate::raw_stream_backend::RawStreamFormat::Xz,
            "xz",
        )))?;
        builder.register_read_adapter(Arc::new(adapters::native::FilteredTarAdapter::new(
            FormatId::TAR_LZMA,
            crate::raw_stream_backend::RawStreamFormat::Lzma,
            "lzma",
        )))?;
        builder.register_read_adapter(Arc::new(adapters::native::ArListAdapter))?;
        builder.register_read_adapter(Arc::new(adapters::native::CpioListAdapter))?;
        builder.register_read_adapter(Arc::new(adapters::native::TzapListAdapter))?;
        builder.register_read_adapter(Arc::new(adapters::native::RarListAdapter))?;
        builder.register_read_adapter(Arc::new(adapters::native::RawStreamListAdapter))?;
        builder.register_read_adapter(Arc::new(adapters::native::AppleArchiveListAdapter))?;
        builder.register_read_adapter(Arc::new(adapters::native::DmgListAdapter))?;
        builder.register_read_adapter(Arc::new(adapters::native::PkgListAdapter))?;
        builder.register_read_adapter(Arc::new(adapters::native::MsiListAdapter))?;
        builder.register_read_adapter(Arc::new(adapters::native::VirtualDiskListAdapter::new(FormatId::VHD)))?;
        builder.register_read_adapter(Arc::new(adapters::native::VirtualDiskListAdapter::new(FormatId::VMDK)))?;
        builder.register_read_adapter(Arc::new(adapters::native::VirtualDiskListAdapter::new(FormatId::UDF)))?;

        // Native one-shot creation adapters.
        builder.register_create_adapter(Arc::new(adapters::create::ZipCreateAdapter))?;
        builder.register_create_adapter(Arc::new(adapters::create::SplitZipCreateAdapter))?;
        builder.register_create_adapter(Arc::new(adapters::create::SevenZCreateAdapter))?;
        builder.register_create_adapter(Arc::new(adapters::create::TarZstdCreateAdapter))?;
        builder.register_create_adapter(Arc::new(adapters::create::TarGzCreateAdapter))?;
        builder.register_create_adapter(Arc::new(adapters::create::TzapCreateAdapter))?;
        builder.register_create_adapter(Arc::new(adapters::create::AppleArchiveCreateAdapter))?;

        // Libarchive compatibility listing adapters for allow-listed formats.
        #[cfg(feature = "libarchive-fallback")]
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

/// Runs a complete extraction through the default engine and returns its
/// normalized report.
pub fn extract_with_default_engine<'a>(
    source: ArchiveSource,
    open_options: OpenOptions,
    options: &'a mut ExtractOptions<'a>,
) -> Result<ExtractReport, ArchiveError> {
    let engine = create_default_engine()?;
    let mut handle = engine.open(source, open_options)?;
    handle.extract(options)
}
