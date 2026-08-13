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
pub mod tar_backend;
mod tar_metadata;
mod temp_names;
#[cfg(test)]
mod test_support;
mod tzap;
mod wire_profile;
mod zip_split;

// Offline identity, catalog, signing, and verification remain part of the
// core contract in every profile. The files stay under the historical auth
// directory while their ownership is now explicit at the crate root.
#[path = "auth/auth_client.rs"]
pub mod auth_client;
#[path = "auth/certificate_lifecycle.rs"]
pub mod certificate_lifecycle;
#[path = "auth/contact_card.rs"]
pub mod contact_card;
#[path = "auth/crl.rs"]
pub mod crl;
#[path = "auth/device_identity.rs"]
pub mod device_identity;
#[path = "auth/document_envelope.rs"]
pub mod document_envelope;
#[path = "auth/document_signing.rs"]
pub mod document_signing;
#[path = "auth/document_verification.rs"]
pub mod document_verification;
#[path = "auth/enrollment_client.rs"]
pub mod enrollment_client;
#[path = "auth/http_client.rs"]
pub(crate) mod http_client;
#[path = "auth/identity_catalog.rs"]
pub mod identity_catalog;
#[path = "auth/identity_migration.rs"]
pub(crate) mod identity_migration;
#[path = "auth/jcs.rs"]
pub mod jcs;
#[path = "auth/json_util.rs"]
pub(crate) mod json_util;
#[path = "auth/local_identity_store.rs"]
pub mod local_identity_store;
#[path = "auth/local_tzap_service.rs"]
pub mod local_tzap_service;
#[path = "auth/p256_signature.rs"]
pub mod p256_signature;
#[path = "auth/status_client.rs"]
pub mod status_client;
#[path = "auth/tzap_service.rs"]
pub mod tzap_service;
#[path = "auth/tzap_service_auth.rs"]
pub mod tzap_service_auth;

pub mod apple_archive_backend;
pub mod apple_dmg_backend;
pub mod apple_pkg_backend;
pub mod ar_backend;
pub mod archive_browser;
pub mod cab_backend;
pub mod cpio_backend;
pub mod deb_backend;
pub mod engine;
pub mod jobs;
pub mod lha_backend;
pub mod manifest;
pub mod msi_backend;
pub mod mtree_backend;
pub mod rar_backend;
pub mod raw_stream_backend;
pub mod rpm_backend;
pub mod safety;
pub mod secrets;
pub mod sevenz_backend;
pub mod tar_gz_backend;
pub mod tar_zst_backend;
pub mod trust;
pub mod tzap_backend;
pub mod virtual_disk_backend;
pub mod warc_backend;
pub mod x509_format;
pub mod xar_backend;
pub mod zip_backend;

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
