//! Bounded public display summary for shell surfaces (QuickLook/Spotlight).
//!
//! Only the volume headers, crypto headers, and terminal (footer) regions are
//! read; archive contents are never loaded and the whole-archive Merkle is
//! never recomputed. The signature status is the footer-only assertion: "the
//! embedded certificate's key really signed this footer", evaluated across
//! the complete expected volume set (a missing or divergent volume can never
//! claim `Signed`/`Unsigned`). Content integrity and trust-chain validation
//! stay explicit app-side operations (`verify_tzap_x509_public_no_key`), so
//! this path is bounded regardless of archive size.

use std::fs::File;
use std::io::{self, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use tzap_core::format::FormatError;
use tzap_core::{PublicNoKeyFooterStatus, ReaderOptions, public_no_key_inspect_footer};
use tzap_plugin_signing::x509_chain::{X509_AUTHENTICATOR_ID, X509_SIGNER_IDENTITY_TYPE_DER_CERT};

use super::open::{
    TzapPublicMetadataSummary, discover_tzap_input_volume_paths, expected_tzap_input_volume_paths,
    read_public_tzap_header_from, summarize_tzap_public_metadata_from,
};
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
    /// Every expected volume is present and carries an identical X.509
    /// `RootAuth` footer, and the embedded-key signature is authentic
    /// (footer-only scope).
    Signed { signer: TzapX509SignerInspection },
    /// Valid archive(s) with no `RootAuth` footer. Pre-v45 archives, which
    /// predate `RootAuth`, also report `Unsigned`.
    Unsigned,
    /// X.509 `RootAuth` footer recovered, but the embedded-key signature is
    /// not authentic (forged, truncated, or corrupt).
    NotAuthentic { reason: String },
    /// The footer could not be recovered, it is not an X.509 `RootAuth`
    /// profile, or the volume set cannot confirm a status (missing or
    /// divergent volumes).
    Unavailable { reason: String },
}

/// Per-volume footer status collected during a single inspection pass.
#[derive(Clone)]
struct PerVolumeSignatureStatus {
    status: TzapPublicSignatureStatus,
    /// Present only when the volume carried a signed `RootAuth` footer, so
    /// the aggregate can detect divergent footers across volumes.
    footer_bytes: Option<Vec<u8>>,
}

/// Combines per-volume footer statuses into one display status.
///
/// Deterministic rules:
/// 1. An incomplete volume set is always `Unavailable` — a missing volume
///    could have carried a footer.
/// 2. Any per-volume `Unavailable` dominates.
/// 3. Otherwise the present volumes must agree: identical `Signed` footers
///    verify, differing `Signed` footers or a status mix are `Unavailable`,
///    all `Unsigned` stays `Unsigned`, all `NotAuthentic` stays
///    `NotAuthentic`.
fn aggregate_public_footer_status(
    volumes: &[PerVolumeSignatureStatus],
    missing_volume_indices: &[usize],
    expected_volume_count: usize,
) -> TzapPublicSignatureStatus {
    if let Some(first_missing) = missing_volume_indices.first() {
        return TzapPublicSignatureStatus::Unavailable {
            reason: format!(
                "volume set is incomplete: missing volume {first_missing} of {expected_volume_count}; \
                 the root-auth footer cannot be confirmed"
            ),
        };
    }
    if volumes.is_empty() {
        return TzapPublicSignatureStatus::Unavailable { reason: "no present volumes to inspect".to_owned() };
    }
    if let Some(TzapPublicSignatureStatus::Unavailable { reason }) = volumes
        .iter()
        .find(|volume| matches!(volume.status, TzapPublicSignatureStatus::Unavailable { .. }))
        .map(|volume| &volume.status)
    {
        return TzapPublicSignatureStatus::Unavailable { reason: reason.clone() };
    }

    let all_signed = volumes.iter().all(|volume| matches!(volume.status, TzapPublicSignatureStatus::Signed { .. }));
    let all_unsigned = volumes.iter().all(|volume| matches!(volume.status, TzapPublicSignatureStatus::Unsigned));
    let all_not_authentic =
        volumes.iter().all(|volume| matches!(volume.status, TzapPublicSignatureStatus::NotAuthentic { .. }));

    if all_signed {
        let first = &volumes[0];
        if volumes.iter().all(|volume| volume.footer_bytes == first.footer_bytes) {
            match &first.status {
                TzapPublicSignatureStatus::Signed { signer } => {
                    TzapPublicSignatureStatus::Signed { signer: signer.clone() }
                }
                _ => unreachable!("all_signed implies a Signed first volume"),
            }
        } else {
            TzapPublicSignatureStatus::Unavailable {
                reason: "present volumes carry different root-auth footers".to_owned(),
            }
        }
    } else if all_unsigned {
        TzapPublicSignatureStatus::Unsigned
    } else if all_not_authentic {
        match &volumes[0].status {
            TzapPublicSignatureStatus::NotAuthentic { reason } => {
                TzapPublicSignatureStatus::NotAuthentic { reason: reason.clone() }
            }
            _ => unreachable!("all_not_authentic implies a NotAuthentic first volume"),
        }
    } else {
        TzapPublicSignatureStatus::Unavailable { reason: "present volumes disagree on root-auth status".to_owned() }
    }
}

/// Maps a per-volume footer read failure to a display status where the
/// failure itself is meaningful; returns `None` for failures the caller
/// reports as generic `Unavailable`.
fn map_footer_read_error(error: &FormatError) -> Option<TzapPublicSignatureStatus> {
    match error {
        FormatError::UnsupportedVolumeFormatRevision { volume_format_rev, reader_max_supported_revision, .. } => {
            if *volume_format_rev < *reader_max_supported_revision {
                // Pre-v45 archives predate the RootAuth footer entirely.
                Some(TzapPublicSignatureStatus::Unsigned)
            } else {
                Some(TzapPublicSignatureStatus::Unavailable {
                    reason: format!(
                        "archive uses volume format revision {volume_format_rev}, newer than this build supports \
                         ({reader_max_supported_revision})"
                    ),
                })
            }
        }
        _ => None,
    }
}

/// Inspects one volume's terminal with bounded reads and reduces it to a
/// per-volume status.
fn inspect_volume_footer(file: &mut File) -> PerVolumeSignatureStatus {
    match public_no_key_inspect_footer(file, ReaderOptions::default()) {
        Ok(PublicNoKeyFooterStatus::Unsigned) => {
            PerVolumeSignatureStatus { status: TzapPublicSignatureStatus::Unsigned, footer_bytes: None }
        }
        Ok(PublicNoKeyFooterStatus::Signed(inspection)) => {
            let footer = &inspection.root_auth_footer;
            let status = if footer.authenticator_id != X509_AUTHENTICATOR_ID {
                TzapPublicSignatureStatus::Unavailable {
                    reason: format!(
                        "signed with a non-X.509 root-auth profile (authenticator id {})",
                        footer.authenticator_id
                    ),
                }
            } else if footer.signer_identity_type != X509_SIGNER_IDENTITY_TYPE_DER_CERT {
                TzapPublicSignatureStatus::Unavailable {
                    reason: format!(
                        "signed with an unsupported X.509 signer identity type ({})",
                        footer.signer_identity_type
                    ),
                }
            } else {
                match inspect_x509_root_auth_footer(footer, &inspection.archive_root) {
                    Ok(signer) => TzapPublicSignatureStatus::Signed { signer },
                    Err(error) => TzapPublicSignatureStatus::NotAuthentic { reason: error.to_string() },
                }
            };
            PerVolumeSignatureStatus { status, footer_bytes: Some(inspection.root_auth_footer_bytes) }
        }
        Err(error) => PerVolumeSignatureStatus {
            status: map_footer_read_error(&error)
                .unwrap_or_else(|| TzapPublicSignatureStatus::Unavailable { reason: error.to_string() }),
            footer_bytes: None,
        },
    }
}

/// Inspects every expected volume's terminal and returns the aggregate
/// footer-only signature status.
///
/// Caller contract: `volume_paths` is the output of
/// [`discover_tzap_input_volume_paths`] for `requested_path`, and
/// `first_volume_file` is a handle to the first existing path in it (its
/// header is read through this handle so the caller's single open serves both
/// display passes).
pub(crate) fn inspect_tzap_public_footer_signature_from(
    requested_path: &Path,
    volume_paths: &[PathBuf],
    first_volume_file: &mut File,
) -> Result<TzapPublicSignatureStatus, TzapError> {
    let first_volume_path = volume_paths
        .iter()
        .find(|path| path.exists())
        .expect("caller contract: first_volume_file is a handle to the first existing volume path");
    let first_header = read_public_tzap_header_from(first_volume_file, first_volume_path)?;
    let expected_volume_count = usize::try_from(first_header.volume_header.stripe_width)
        .map_err(|_| TzapError::Format(FormatError::InvalidArchive("TZAP volume count overflow")))?;
    let expected_paths = expected_tzap_input_volume_paths(requested_path, first_volume_path, expected_volume_count);

    let mut volumes = Vec::new();
    let mut missing_volume_indices = Vec::new();

    for (expected_index, volume_path) in expected_paths.iter().enumerate() {
        if !volume_path.exists() {
            missing_volume_indices.push(expected_index);
            continue;
        }

        let status = if volume_path == first_volume_path {
            inspect_volume_footer(first_volume_file)
        } else {
            let mut file =
                File::open(volume_path).map_err(|source| TzapError::Io { path: volume_path.clone(), source })?;
            inspect_volume_footer(&mut file)
        };
        volumes.push(status);
    }

    Ok(aggregate_public_footer_status(&volumes, &missing_volume_indices, expected_volume_count))
}

/// Inspects the volume set's terminals with bounded reads and returns the
/// aggregate footer-only signature status.
///
/// The status covers the complete expected volume set: an incomplete set, a
/// per-volume read failure, or divergent footers degrade to
/// [`TzapPublicSignatureStatus::Unavailable`] rather than claiming a status
/// from the first volume alone.
///
/// # Errors
///
/// Returns an error when no TZAP volume can be found or the first volume's
/// public headers are malformed. (`Unsigned` archives are a status, not an
/// error.)
pub fn inspect_tzap_public_footer_signature(archive_path: &Path) -> Result<TzapPublicSignatureStatus, TzapError> {
    let volume_paths = discover_tzap_input_volume_paths(archive_path);
    let first_volume_path = volume_paths
        .iter()
        .find(|path| path.exists())
        .ok_or_else(|| io_error(archive_path, io::ErrorKind::NotFound, "no TZAP input volumes found"))?;
    let mut file =
        File::open(first_volume_path).map_err(|source| TzapError::Io { path: first_volume_path.clone(), source })?;
    inspect_tzap_public_footer_signature_from(archive_path, &volume_paths, &mut file)
}

/// Returns the bounded display summary for a `.tzap` archive.
///
/// Metadata errors propagate (the path does not look like a TZAP archive);
/// footer inspection failures degrade to
/// [`TzapPublicSignatureStatus::Unavailable`] so the metadata is still
/// displayed. Metadata and footer passes share one discovery and one open of
/// the first volume.
///
/// # Errors
///
/// Returns an error when no TZAP volume can be found or the public headers
/// are malformed.
pub fn summarize_tzap_public_display(archive_path: &Path) -> Result<TzapPublicDisplaySummary, TzapError> {
    let volume_paths = discover_tzap_input_volume_paths(archive_path);
    let first_volume_path = volume_paths
        .iter()
        .find(|path| path.exists())
        .ok_or_else(|| io_error(archive_path, io::ErrorKind::NotFound, "no TZAP input volumes found"))?;
    let mut first_volume_file =
        File::open(first_volume_path).map_err(|source| TzapError::Io { path: first_volume_path.clone(), source })?;
    let metadata = summarize_tzap_public_metadata_from(archive_path, &volume_paths, &mut first_volume_file)?;
    // The metadata pass read the first volume's headers through this handle
    // with seek-based reads, so rewind it before the footer pass reuses it.
    first_volume_file
        .seek(SeekFrom::Start(0))
        .map_err(|source| TzapError::Io { path: first_volume_path.clone(), source })?;
    let signature = match inspect_tzap_public_footer_signature_from(archive_path, &volume_paths, &mut first_volume_file)
    {
        Ok(status) => status,
        Err(error) => TzapPublicSignatureStatus::Unavailable { reason: error.to_string() },
    };
    Ok(TzapPublicDisplaySummary { metadata, signature })
}

#[cfg(test)]
mod tests {
    use tzap_core::format::FormatError;

    use super::{
        PerVolumeSignatureStatus, TzapPublicSignatureStatus, aggregate_public_footer_status, map_footer_read_error,
    };
    use crate::tzap::x509::TzapX509SignerInspection;

    fn signed_per_volume(footer_bytes: Option<Vec<u8>>) -> PerVolumeSignatureStatus {
        PerVolumeSignatureStatus { status: TzapPublicSignatureStatus::Signed { signer: test_signer() }, footer_bytes }
    }

    fn test_signer() -> TzapX509SignerInspection {
        TzapX509SignerInspection {
            archive_root: [0u8; 32],
            authenticator_id: 0x1001,
            signer_identity_type: 2,
            total_data_block_count: 1,
            signed_at_unix_seconds: 0,
            subject: "CN=Test Signer".to_owned(),
            issuer: "CN=Test Root CA".to_owned(),
            serial_number_hex: "01".to_owned(),
            certificate_sha256: [0u8; 32],
            diagnostics: Vec::new(),
        }
    }

    #[test]
    fn aggregate_status_treats_missing_volume_as_unavailable() {
        let status = aggregate_public_footer_status(&[signed_per_volume(Some(vec![1]))], &[2], 4);
        let TzapPublicSignatureStatus::Unavailable { reason } = status else {
            panic!("expected unavailable status, got {status:?}");
        };
        assert!(reason.contains("missing volume 2 of 4"), "unexpected reason: {reason}");
    }

    #[test]
    fn aggregate_status_reports_divergent_signed_footers_as_unavailable() {
        let status = aggregate_public_footer_status(
            &[signed_per_volume(Some(vec![1])), signed_per_volume(Some(vec![2]))],
            &[],
            2,
        );
        let TzapPublicSignatureStatus::Unavailable { reason } = status else {
            panic!("expected unavailable status, got {status:?}");
        };
        assert!(reason.contains("different root-auth footers"), "unexpected reason: {reason}");
    }

    #[test]
    fn aggregate_status_rule_table() {
        // Identical signed footers verify.
        let status = aggregate_public_footer_status(
            &[signed_per_volume(Some(vec![1])), signed_per_volume(Some(vec![1]))],
            &[],
            2,
        );
        assert!(matches!(status, TzapPublicSignatureStatus::Signed { .. }), "got {status:?}");

        // Any per-volume unavailable dominates.
        let volume_with_failure = PerVolumeSignatureStatus {
            status: TzapPublicSignatureStatus::Unavailable { reason: "read failed".to_owned() },
            footer_bytes: None,
        };
        let status = aggregate_public_footer_status(&[signed_per_volume(Some(vec![1])), volume_with_failure], &[], 2);
        let TzapPublicSignatureStatus::Unavailable { reason } = status else {
            panic!("expected unavailable status, got {status:?}");
        };
        assert_eq!(reason, "read failed");

        // All unsigned stays unsigned.
        let unsigned = PerVolumeSignatureStatus { status: TzapPublicSignatureStatus::Unsigned, footer_bytes: None };
        let status = aggregate_public_footer_status(&[unsigned.clone(), unsigned.clone()], &[], 2);
        assert_eq!(status, TzapPublicSignatureStatus::Unsigned);

        // A status mix is unavailable.
        let status = aggregate_public_footer_status(&[signed_per_volume(Some(vec![1])), unsigned], &[], 2);
        let TzapPublicSignatureStatus::Unavailable { reason } = status else {
            panic!("expected unavailable status, got {status:?}");
        };
        assert_eq!(reason, "present volumes disagree on root-auth status");
    }

    #[test]
    fn map_footer_read_error_treats_pre_v45_revision_as_unsigned() {
        let error = FormatError::UnsupportedVolumeFormatRevision {
            format_version: 1,
            volume_format_rev: 44,
            reader_max_supported_revision: 45,
        };
        assert_eq!(map_footer_read_error(&error), Some(TzapPublicSignatureStatus::Unsigned));
    }

    #[test]
    fn map_footer_read_error_reports_future_revision_as_unavailable() {
        let error = FormatError::UnsupportedVolumeFormatRevision {
            format_version: 1,
            volume_format_rev: 46,
            reader_max_supported_revision: 45,
        };
        let Some(TzapPublicSignatureStatus::Unavailable { reason }) = map_footer_read_error(&error) else {
            panic!("expected unavailable status, got {:?}", map_footer_read_error(&error));
        };
        assert!(reason.contains("newer"), "unexpected reason: {reason}");
        assert!(reason.contains("46"), "unexpected reason: {reason}");
        assert!(!reason.contains("reader_max_supported_revision"), "internal field leaked into reason: {reason}");
    }
}
