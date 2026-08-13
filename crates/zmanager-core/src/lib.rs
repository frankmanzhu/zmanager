//! Core engine primitives for `ZManager`.

// The public API predates the workspace-wide pedantic lint policy. Error
// documentation is tracked separately from behavioral and structural cleanup.
#![allow(clippy::missing_errors_doc)]

/// Generates the standard `From` impls shared by the archive-backend error
/// enums: planning, extraction safety, and cooperative cancellation (the
/// latter as a unit `Cancelled` variant). Backends without one of the
/// variants (for example the create-only tar.gz backend) keep their impls
/// written out.
#[macro_export]
macro_rules! backend_error_from_impls {
    ($error:ty) => {
        impl From<$crate::manifest::PlanError> for $error {
            fn from(source: $crate::manifest::PlanError) -> Self {
                Self::Plan(source)
            }
        }
        impl From<$crate::safety::ExtractionSafetyError> for $error {
            fn from(source: $crate::safety::ExtractionSafetyError) -> Self {
                Self::Safety(source)
            }
        }
        impl From<$crate::jobs::JobCancelled> for $error {
            fn from(_source: $crate::jobs::JobCancelled) -> Self {
                Self::Cancelled
            }
        }
    };
}

pub mod archive_format;
mod archive_split;
mod atomic_file;
mod extract_loop;
mod extract_materialize;
mod gitignore;
mod multi_volume;
mod segmented_reader;
mod sevenz_volume;
mod strings;
mod tar_metadata;
mod temp_names;
#[cfg(test)]
mod test_support;
mod tzap;
mod wire_profile;
mod zip_split;

pub mod apple_archive_backend;
pub mod apple_dmg_backend;
pub mod apple_pkg_backend;
pub mod archive_browser;
pub mod deb_backend;
pub mod engine;
pub mod jobs;
#[cfg(feature = "libarchive-fallback")]
pub mod libarchive_backend;
#[cfg(not(feature = "libarchive-fallback"))]
#[path = "libarchive_backend_stub.rs"]
pub mod libarchive_backend;
pub mod manifest;
pub mod msi_backend;
pub mod rar_backend;
pub mod raw_stream_backend;
pub mod safety;
pub mod secrets;
pub mod sevenz_backend;
pub mod tar_gz_backend;
pub mod tar_zst_backend;
pub mod trust;
pub mod tzap_backend;
pub mod virtual_disk_backend;
pub mod x509_format;
pub mod zip_backend;

// The online/identity surface is one gated unit: everything under `auth`
// (see auth/mod.rs). The public re-exports keep the historical flat paths
// (`zmanager_core::auth_client`, …) working for the CLI, FFI, and tests; the
// crate-private re-exports cover the helpers the auth modules share.
#[cfg(feature = "auth")]
mod auth;
#[cfg(feature = "auth")]
pub use auth::{
    auth_client, certificate_lifecycle, contact_card, crl, device_identity, document_envelope, document_signing, document_verification, enrollment_client,
    identity_catalog, jcs, local_identity_store, local_tzap_service, p256_signature, status_client, tzap_service, tzap_service_auth,
};
#[cfg(feature = "auth")]
pub(crate) use auth::{http_client, identity_migration, json_util};

mod hex;

/// The stable engine name used in diagnostics and health checks.
pub const ENGINE_NAME: &str = "zmanager-core";

pub(crate) const DEFAULT_IO_BUFFER_BYTES: usize = 128 * 1024;
pub(crate) const MEBIBYTE_BYTES: u64 = 1024 * 1024;

/// A minimal report proving that the Rust engine can be called.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct HealthReport {
    /// Engine component that produced the report.
    pub engine: &'static str,
    /// Core crate version.
    pub version: &'static str,
    /// Whether the core crate considers itself ready to accept jobs.
    pub ready: bool,
}

impl HealthReport {
    /// Returns a human-readable one-line summary for CLI output.
    #[must_use]
    pub fn summary(&self) -> String {
        let status = if self.ready { "ready" } else { "not ready" };
        format!("{} {} ({status})", self.engine, self.version)
    }
}

/// Runs a lightweight engine health check.
#[must_use]
pub fn healthcheck() -> HealthReport {
    HealthReport { engine: ENGINE_NAME, version: env!("CARGO_PKG_VERSION"), ready: true }
}

#[cfg(test)]
mod tests {
    use super::{ENGINE_NAME, healthcheck};

    #[test]
    fn healthcheck_reports_ready_core() {
        let report = healthcheck();

        assert_eq!(report.engine, ENGINE_NAME);
        assert_eq!(report.version, env!("CARGO_PKG_VERSION"));
        assert!(report.ready);
    }

    #[test]
    fn healthcheck_summary_is_stable() {
        let report = healthcheck();
        let expected = format!("zmanager-core {} (ready)", env!("CARGO_PKG_VERSION"));

        assert_eq!(report.summary(), expected);
    }
}
