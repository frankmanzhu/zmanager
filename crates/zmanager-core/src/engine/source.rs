//! Owned archive source access descriptors and discovery (ARC-101, ARC-102).

use std::path::{Path, PathBuf};

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

/// Owned archive source description.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ArchiveSource {
    /// Single archive file path.
    Path(PathBuf),
    /// Explicit ordered multi-volume file set (e.g. `.z01`, `.z02`, ..., `.zip`).
    VolumeSet(Vec<PathBuf>),
}

impl ArchiveSource {
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
