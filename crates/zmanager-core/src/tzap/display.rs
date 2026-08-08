//! Bounded public display summary for shell surfaces (QuickLook/Spotlight).
//!
//! Only the volume header, crypto header, and terminal (footer) region are
//! read from the first volume; archive contents are never loaded and the
//! whole-archive Merkle is never recomputed. The signature status is the
//! footer-only assertion: "the embedded certificate's key really signed this
//! footer". Content integrity and trust-chain validation stay explicit
//! app-side operations (`verify_tzap_x509_public_no_key`), so this path is
//! bounded regardless of archive size.

use std::fs::File;
use std::io;
use std::path::Path;

use tzap_core::{PublicNoKeyFooterStatus, ReaderOptions, public_no_key_inspect_footer};
use tzap_plugin_signing::x509_chain::X509_AUTHENTICATOR_ID;

use super::open::{TzapPublicMetadataSummary, discover_tzap_input_volume_paths, summarize_tzap_public_metadata};
use super::x509::{TzapX509SignerInspection, inspect_x509_root_auth_footer};
use super::{TzapError, io_error};

/// Bounded public display summary: header/trailer metadata plus a footer-only
/// signature status. Never reads archive contents.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TzapPublicDisplaySummary {
    /// Header and volume-level details.
    pub metadata: TzapPublicMetadataSummary,
    /// Footer-derived signature status.
    pub signature: TzapPublicSignatureStatus,
}

/// Footer-only signature status for display surfaces.
///
/// This is assertion 1 of verification only (the embedded certificate's key
/// really signed the footer, including the *claimed* content hash). Content
/// integrity and trust-chain validation are explicit app-side operations.
#[derive(Debug, Clone, Eq, PartialEq)]
// The inspection is produced once per call and moved, never cloned; boxing
// would only add an allocation for a single-value result.
#[allow(clippy::large_enum_variant)]
pub enum TzapPublicSignatureStatus {
    /// X.509 `RootAuth` footer recovered and the embedded-key signature is
    /// authentic.
    Signed { signer: TzapX509SignerInspection },
    /// Valid archive with no `RootAuth` footer.
    Unsigned,
    /// X.509 `RootAuth` footer recovered, but the embedded-key signature is
    /// not authentic (forged, truncated, or corrupt).
    NotAuthentic { reason: String },
    /// Footer could not be recovered, or it is not an X.509 `RootAuth`
    /// profile.
    Unavailable { reason: String },
}

/// Inspects the first volume's terminal with bounded reads and returns the
/// footer-only signature status.
///
/// # Errors
///
/// Returns an error when no TZAP volume can be found, the volume cannot be
/// opened, or the terminal cannot be recovered. (`Unsigned` archives are a
/// status, not an error.)
pub fn inspect_tzap_public_footer_signature(archive_path: &Path) -> Result<TzapPublicSignatureStatus, TzapError> {
    let volume_paths = discover_tzap_input_volume_paths(archive_path);
    let first_volume = volume_paths
        .iter()
        .find(|path| path.exists())
        .ok_or_else(|| io_error(archive_path, io::ErrorKind::NotFound, "no TZAP input volumes found"))?;
    let file = File::open(first_volume).map_err(|source| TzapError::Io { path: first_volume.clone(), source })?;
    let status = public_no_key_inspect_footer(&file, ReaderOptions::default()).map_err(TzapError::from)?;
    match status {
        PublicNoKeyFooterStatus::Unsigned => Ok(TzapPublicSignatureStatus::Unsigned),
        PublicNoKeyFooterStatus::Signed(inspection) => {
            let footer = &inspection.root_auth_footer;
            if footer.authenticator_id != X509_AUTHENTICATOR_ID {
                return Ok(TzapPublicSignatureStatus::Unavailable {
                    reason: format!(
                        "signed with a non-X.509 root-auth profile (authenticator id {})",
                        footer.authenticator_id
                    ),
                });
            }
            match inspect_x509_root_auth_footer(footer, &inspection.archive_root) {
                Ok(signer) => Ok(TzapPublicSignatureStatus::Signed { signer }),
                Err(error) => Ok(TzapPublicSignatureStatus::NotAuthentic { reason: error.to_string() }),
            }
        }
    }
}

/// Returns the bounded display summary for a `.tzap` archive.
///
/// Metadata errors propagate (the path does not look like a TZAP archive);
/// footer inspection failures degrade to
/// [`TzapPublicSignatureStatus::Unavailable`] so the metadata is still
/// displayed.
///
/// # Errors
///
/// Returns an error when no TZAP volume can be found or the public headers
/// are malformed.
pub fn summarize_tzap_public_display(archive_path: &Path) -> Result<TzapPublicDisplaySummary, TzapError> {
    let metadata = summarize_tzap_public_metadata(archive_path)?;
    let signature = match inspect_tzap_public_footer_signature(archive_path) {
        Ok(status) => status,
        Err(error) => TzapPublicSignatureStatus::Unavailable { reason: error.to_string() },
    };
    Ok(TzapPublicDisplaySummary { metadata, signature })
}
