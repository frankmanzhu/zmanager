//! Owned archive source access descriptors and discovery (ARC-101, ARC-102).

use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Access capabilities supported by an archive source.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum SourceAccess {
    /// Source is seekable (supports random access and position rewind).
    Seekable,
    /// Source is sequential-only (stream cannot seek backwards).
    SequentialOnly,
    /// Source consists of an ordered set of volume files.
    MultiVolumeSet,
}

/// Provenance of an engine-owned archive source.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum SourceProvenance {
    /// A caller supplied one path and the engine owns its reopenable file source.
    Path,
    /// A caller supplied an ordered set of physical volume paths.
    ExplicitVolumeSet,
}

/// A session-owned cursor capability for path-backed and explicit-volume
/// sources. The source module owns how a cursor is created; adapters only
/// receive the capability and never rediscover source paths themselves.
#[derive(Debug, Clone)]
pub(crate) struct SourceCursorFactory {
    source: ArchiveSource,
}

impl SourceCursorFactory {
    pub(crate) fn new(source: &ArchiveSource) -> Self {
        Self { source: source.clone() }
    }

    pub(crate) fn source(&self) -> &ArchiveSource {
        &self.source
    }

    pub(crate) fn open_primary_file(&self) -> std::io::Result<std::fs::File> {
        std::fs::OpenOptions::new().read(true).open(self.source().primary_path())
    }
}

/// A snapshot of the file metadata that backs an opened archive source.
///
/// The engine uses this value to reject stale entry identities before an
/// operation can be dispatched to an adapter. It includes filesystem identity
/// where the platform exposes it, but it is not a content hash or a substitute
/// for adapter-owned parser/cursor state; the handle uses it to reject a
/// replaced or truncated path before dispatching a subsequent operation.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SourceFingerprint {
    files: Vec<SourceFileFingerprint>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct SourceFileFingerprint {
    path: PathBuf,
    exists: bool,
    identity: Option<(u64, u64)>,
    length: Option<u64>,
    modified: Option<SystemTime>,
}

#[allow(clippy::unnecessary_wraps)]
fn source_file_identity(metadata: &std::fs::Metadata) -> Option<(u64, u64)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        Some((metadata.dev(), metadata.ino()))
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;

        Some((u64::from(metadata.volume_serial_number()?), metadata.file_index()?))
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = metadata;
        None
    }
}

/// Owned archive source description.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ArchiveSource {
    /// Single archive file path.
    Path(PathBuf),
    /// Explicit ordered multi-volume file set (e.g. `.z01`, `.z02`, ..., `.zip`).
    VolumeSet(Vec<PathBuf>),
}

impl ArchiveSource {
    /// Returns the explicitly owned paths that make up this source.
    #[must_use]
    pub fn paths(&self) -> &[PathBuf] {
        match self {
            Self::Path(path) => std::slice::from_ref(path),
            Self::VolumeSet(paths) => paths,
        }
    }

    /// Captures the current metadata of every explicitly owned source path.
    ///
    /// Missing paths are represented as missing entries so callers can use
    /// the fingerprint for source-change detection while retaining the
    /// existing format-specific handling for sidecar-based inputs.
    pub fn fingerprint(&self) -> std::io::Result<SourceFingerprint> {
        self.fingerprint_with_additional_paths(&[])
    }

    /// Captures the source paths plus format-owned sibling paths discovered
    /// while opening a path-backed multi-volume format.
    pub(crate) fn fingerprint_with_additional_paths(&self, additional_paths: &[PathBuf]) -> std::io::Result<SourceFingerprint> {
        let mut paths = self.paths().to_vec();
        for path in additional_paths {
            if !paths.contains(path) {
                paths.push(path.clone());
            }
        }

        let mut files = Vec::with_capacity(paths.len());
        for path in &paths {
            match std::fs::metadata(path) {
                Ok(metadata) => {
                    files.push(SourceFileFingerprint {
                        path: path.clone(),
                        exists: true,
                        identity: source_file_identity(&metadata),
                        length: Some(metadata.len()),
                        modified: metadata.modified().ok(),
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    files.push(SourceFileFingerprint { path: path.clone(), exists: false, identity: None, length: None, modified: None });
                }
                Err(error) => return Err(error),
            }
        }
        Ok(SourceFingerprint { files })
    }

    /// Returns whether the explicitly owned source paths still match a
    /// previously captured fingerprint.
    pub fn matches_fingerprint(&self, expected: &SourceFingerprint) -> std::io::Result<bool> {
        Ok(self.fingerprint()? == *expected)
    }

    /// Returns whether the source and its format-owned sibling paths still
    /// match a previously captured fingerprint.
    pub(crate) fn matches_fingerprint_with_additional_paths(&self, expected: &SourceFingerprint, additional_paths: &[PathBuf]) -> std::io::Result<bool> {
        Ok(self.fingerprint_with_additional_paths(additional_paths)? == *expected)
    }

    /// Returns the primary path associated with this source.
    #[must_use]
    pub fn primary_path(&self) -> &Path {
        match self {
            Self::Path(path) => path,
            Self::VolumeSet(volumes) => volumes.last().map_or_else(|| Path::new(""), |p| p.as_path()),
        }
    }

    /// Returns the source access capability.
    #[must_use]
    pub fn access_capability(&self) -> SourceAccess {
        match self {
            Self::Path(_) => SourceAccess::Seekable,
            Self::VolumeSet(_) => SourceAccess::MultiVolumeSet,
        }
    }

    /// Returns how the caller supplied this source.
    #[must_use]
    pub const fn provenance(&self) -> SourceProvenance {
        match self {
            Self::Path(_) => SourceProvenance::Path,
            Self::VolumeSet(_) => SourceProvenance::ExplicitVolumeSet,
        }
    }

    /// Returns a stable display-name hint derived from the primary path.
    #[must_use]
    pub fn name_hint(&self) -> Option<&str> {
        self.primary_path().file_name().and_then(|name| name.to_str())
    }

    /// Returns the aggregate byte length when every owned source path exists.
    ///
    /// `None` means that at least one source path is not present yet. This is
    /// intentionally a hint; the engine still performs its normal source
    /// existence and format validation before opening an adapter.
    pub fn length_hint(&self) -> std::io::Result<Option<u64>> {
        self.length_hint_with_additional_paths(&[])
    }

    /// Returns the aggregate byte length including format-owned sibling paths.
    pub(crate) fn length_hint_with_additional_paths(&self, additional_paths: &[PathBuf]) -> std::io::Result<Option<u64>> {
        let mut paths = self.paths().to_vec();
        for path in additional_paths {
            if !paths.contains(path) {
                paths.push(path.clone());
            }
        }
        if paths.is_empty() {
            return Ok(None);
        }
        let mut length = 0u64;
        for path in &paths {
            let metadata = match std::fs::metadata(path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    // A format-owned volume set may be addressed by a
                    // logical base path that is not itself a physical file
                    // (for example `archive.tzap` beside
                    // `archive.vol000.tzap`). The discovered physical paths
                    // still need to contribute to the source-size limit.
                    let logical_base_is_missing = matches!(self, Self::Path(primary) if primary == path && !additional_paths.is_empty());
                    if logical_base_is_missing {
                        continue;
                    }
                    return Ok(None);
                }
                Err(error) => return Err(error),
            };
            length =
                length.checked_add(metadata.len()).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "archive source length overflow"))?;
        }
        Ok(Some(length))
    }

    /// Returns whether this source can create another independent cursor.
    #[must_use]
    pub const fn is_reopenable(&self) -> bool {
        // All source forms currently supported by the product are path-backed
        // and can be reopened through SourceCursorFactory. A future
        // sequential stream source must add an explicit non-reopenable form.
        true
    }

    /// Returns the session-owned cursor capability for this source.
    pub(crate) fn cursor_factory(&self) -> SourceCursorFactory {
        SourceCursorFactory::new(self)
    }

    /// Creates an `ArchiveSource` from a path, automatically discovering multi-volume sidecars if present.
    #[must_use]
    pub fn from_path_autodetect(path: impl AsRef<Path>) -> Self {
        let path = path.as_ref();
        if is_split_zip_archive_path(path)
            && let Some(volumes) = discover_split_zip_volumes(path)
        {
            return Self::VolumeSet(volumes);
        }
        Self::Path(path.to_path_buf())
    }
}

/// Returns true if `path` points to a split-ZIP volume or the final `.zip` of a split set (ARC-102).
///
/// This consolidated predicate is shared by core and CLI.
#[must_use]
pub fn is_split_zip_archive_path(path: &Path) -> bool {
    let filename = match path.file_name().and_then(|n| n.to_str()) {
        Some(name) => name.to_lowercase(),
        None => return false,
    };

    if crate::multi_volume::is_split_zip_path(path) {
        return true;
    }

    // Case 1: sidecar volume like archive.z01, archive.z02
    if is_split_zip_sidecar_extension(&filename) {
        return true;
    }

    if is_numbered_zip_volume_name(&filename) {
        return true;
    }

    // Case 2: final .zip with sibling .z01 present
    if path.extension().is_some_and(|ext| ext.eq_ignore_ascii_case("zip")) {
        let parent = path.parent().unwrap_or_else(|| Path::new(""));
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        let z01 = parent.join(format!("{stem}.z01"));
        if z01.is_file() {
            return true;
        }
    }

    false
}

fn is_split_zip_sidecar_extension(filename: &str) -> bool {
    if let Some(dot_idx) = filename.rfind('.') {
        let ext = &filename[dot_idx + 1..];
        if ext.len() == 3 && (ext.starts_with('z') || ext.starts_with('Z')) {
            let digits = &ext[1..];
            return digits.chars().all(|c| c.is_ascii_digit());
        }
    }
    false
}

/// Discovers ordered volumes for a split-ZIP set ending in `.zip`.
#[must_use]
pub fn discover_split_zip_volumes(path: &Path) -> Option<Vec<PathBuf>> {
    let discovered = crate::multi_volume::discover_multi_volume_paths(path);
    if discovered.len() > 1
        && discovered.iter().any(|volume| volume.file_name().and_then(|name| name.to_str()).is_some_and(|name| name.to_ascii_lowercase().contains(".zip")))
    {
        return Some(discovered);
    }

    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    let stem = path.file_stem()?.to_str()?;

    let mut volumes = Vec::new();
    let mut index = 1u32;
    loop {
        let sidecar = parent.join(format!("{stem}.z{index:02}"));
        if sidecar.is_file() {
            volumes.push(sidecar);
            index += 1;
        } else {
            break;
        }
    }

    if volumes.is_empty() {
        return None;
    }

    // Append final .zip
    let final_zip = parent.join(format!("{stem}.zip"));
    if final_zip.is_file() {
        volumes.push(final_zip);
        Some(volumes)
    } else {
        None
    }
}

fn is_numbered_zip_volume_name(filename: &str) -> bool {
    let Some((base, suffix)) = filename.rsplit_once('.') else {
        return false;
    };
    base.to_ascii_lowercase().ends_with(".zip") && suffix.len() == 3 && suffix.bytes().all(|byte| byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::{ArchiveSource, SourceProvenance};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn source_fingerprint_records_filesystem_identity() {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("zmanager-source-fingerprint-{unique}"));
        std::fs::write(&path, b"source").unwrap();

        let fingerprint = ArchiveSource::Path(path.clone()).fingerprint().unwrap();

        #[cfg(any(unix, windows))]
        assert!(fingerprint.files[0].identity.is_some());
        #[cfg(not(any(unix, windows)))]
        assert!(fingerprint.files[0].identity.is_none());

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn source_fingerprint_includes_format_owned_sibling_paths() {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let primary = std::env::temp_dir().join(format!("zmanager-source-primary-{unique}"));
        let sibling = std::env::temp_dir().join(format!("zmanager-source-sibling-{unique}"));
        std::fs::write(&primary, b"primary").unwrap();
        std::fs::write(&sibling, b"sibling").unwrap();

        let source = ArchiveSource::Path(primary.clone());
        let additional = vec![sibling.clone()];
        let fingerprint = source.fingerprint_with_additional_paths(&additional).unwrap();
        std::fs::write(&sibling, b"changed sibling").unwrap();

        assert!(!source.matches_fingerprint_with_additional_paths(&fingerprint, &additional).unwrap());

        std::fs::remove_file(primary).unwrap();
        std::fs::remove_file(sibling).unwrap();
    }

    #[test]
    fn source_exposes_provenance_name_length_and_reopenability() {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let primary = std::env::temp_dir().join(format!("zmanager-source-metadata-primary-{unique}"));
        let sibling = std::env::temp_dir().join(format!("zmanager-source-metadata-sibling-{unique}"));
        std::fs::write(&primary, b"primary").unwrap();
        std::fs::write(&sibling, b"sibling").unwrap();

        let path_source = ArchiveSource::Path(primary.clone());
        assert_eq!(path_source.provenance(), SourceProvenance::Path);
        assert_eq!(path_source.name_hint(), primary.file_name().and_then(|name| name.to_str()));
        assert_eq!(path_source.length_hint().unwrap(), Some(7));
        assert_eq!(path_source.length_hint_with_additional_paths(std::slice::from_ref(&sibling)).unwrap(), Some(14));
        assert!(path_source.is_reopenable());

        let volume_source = ArchiveSource::VolumeSet(vec![primary.clone(), sibling.clone()]);
        assert_eq!(volume_source.provenance(), SourceProvenance::ExplicitVolumeSet);
        assert_eq!(volume_source.length_hint().unwrap(), Some(14));
        assert!(volume_source.is_reopenable());

        std::fs::remove_file(primary).unwrap();
        std::fs::remove_file(sibling).unwrap();
    }
}
