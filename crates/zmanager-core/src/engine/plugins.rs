//! Compile-time archive plugin packaging (ARC-111).

use crate::engine::registry::ArchiveEngineBuilder;
use crate::engine::types::ArchiveError;

/// Trait implemented by compile-time archive plugin descriptors (ARC-111).
pub trait ArchivePlugin: Send + Sync {
    /// Returns the display name of this compile-time plugin packaging module.
    fn name(&self) -> &'static str;

    /// Registers the plugin's adapter factories with an `ArchiveEngineBuilder`.
    ///
    /// # Errors
    ///
    /// Returns `ArchiveError` if registration fails or claims duplicate existing entries.
    fn register(&self, builder: &mut ArchiveEngineBuilder) -> Result<(), ArchiveError>;
}

/// Helper function to build an engine pre-populated with a list of plugins.
///
/// # Errors
///
/// Returns `ArchiveError` if any plugin fails to register.
pub fn build_engine_with_plugins(plugins: &[&dyn ArchivePlugin]) -> Result<crate::engine::handle::ArchiveEngine, ArchiveError> {
    let mut builder = ArchiveEngineBuilder::new();
    for plugin in plugins {
        plugin.register(&mut builder)?;
    }
    Ok(crate::engine::handle::ArchiveEngine::new(builder.build()))
}
