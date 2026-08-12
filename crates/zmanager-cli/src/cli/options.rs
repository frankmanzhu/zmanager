use crate::cli::app::ArchiveFormat;
use crate::cli::create::prompt_password_from_stdin;
#[cfg(any(target_os = "macos", target_os = "ios"))]
use crate::cli::format::{APPLE_ARCHIVE_FORMAT_ALIASES, is_apple_archive};
use crate::cli::format::{
    FORMAT_SEVEN_Z, FORMAT_ZIP, SEVEN_Z_EXTENSIONS, SIZE_UNIT_GIB, SIZE_UNIT_KIB, SIZE_UNIT_MIB, SIZE_UNIT_TIB, TAR_ZST_FORMAT_ALIASES, TGZ_FORMAT_ALIASES, TZAP_FORMAT_ALIASES, is_tar_zst_archive,
    is_tgz_archive, is_tzap_archive, is_zip_family_archive, path_has_known_extension,
};
use crate::cli::usage::usage_failure;
use crate::output::OutputMode;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use zmanager_core::secrets::SecretString;
#[derive(Debug, Clone, Default)]
pub(crate) struct GlobalOptions {
    pub(crate) json: bool,
    pub(crate) quiet: bool,
    pub(crate) verbose: u8,
    pub(crate) color: OutputMode,
    pub(crate) progress: OutputMode,
    pub(crate) no_password_prompt: bool,
}
pub(crate) fn parse_global_option(args: &[String], index: &mut usize, global: &mut GlobalOptions) -> Result<bool, String> {
    match args[*index].as_str() {
        "--json" => global.json = true,
        "-q" | "--quiet" => global.quiet = true,
        "-v" | "--verbose" => global.verbose = global.verbose.saturating_add(1),
        "--no-color" => global.color = OutputMode::Never,
        "--no-progress" => global.progress = OutputMode::Never,
        "--no-password-prompt" => global.no_password_prompt = true,
        "--color" | "--progress" => {
            let option = args[*index].clone();
            let mode = parse_output_mode(&take_value(args, index, &option)?, &option)?;
            if option == "--color" {
                global.color = mode;
            } else {
                global.progress = mode;
            }
            return Ok(true);
        }
        _ => return Ok(false),
    }
    *index += 1;
    Ok(true)
}

pub(crate) fn parse_output_mode(value: &str, option: &str) -> Result<OutputMode, String> {
    match value {
        "auto" => Ok(OutputMode::Auto),
        "always" => Ok(OutputMode::Always),
        "never" => Ok(OutputMode::Never),
        _ => Err(format!("invalid value for {option}: {value}; expected auto, always, or never")),
    }
}

pub(crate) fn take_value(args: &[String], index: &mut usize, option: &str) -> Result<String, String> {
    let value_index = index.saturating_add(1);
    let Some(value) = args.get(value_index) else {
        return Err(format!("missing value for {option}"));
    };
    *index += 2;
    Ok(value.clone())
}

pub(crate) fn parse_i32(value: &str, option: &str) -> Result<i32, String> {
    value.parse::<i32>().map_err(|_| format!("invalid integer for {option}: {value}"))
}

pub(crate) fn parse_usize(value: &str, option: &str) -> Result<usize, String> {
    value.parse::<usize>().map_err(|_| format!("invalid integer for {option}: {value}"))
}

pub(crate) fn parse_volume_size(value: &str, option: &str) -> Result<u64, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("invalid size for {option}: {value}"));
    }

    let split_at = trimmed.find(|character: char| !character.is_ascii_digit()).unwrap_or(trimmed.len());
    let (digits, unit) = trimmed.split_at(split_at);
    if digits.is_empty() {
        return Err(format!("invalid size for {option}: {value}"));
    }
    let amount = digits.parse::<u64>().map_err(|_| format!("invalid size for {option}: {value}"))?;
    if amount == 0 {
        return Err(format!("invalid size for {option}: size must be greater than zero"));
    }

    let multiplier = match unit.to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" | "kib" => SIZE_UNIT_KIB,
        "m" | "mb" | "mib" => SIZE_UNIT_MIB,
        "g" | "gb" | "gib" => SIZE_UNIT_GIB,
        "t" | "tb" | "tib" => SIZE_UNIT_TIB,
        _ => return Err(format!("invalid size unit for {option}: {value}")),
    };

    amount.checked_mul(multiplier).ok_or_else(|| format!("size for {option} is too large: {value}"))
}

pub(crate) fn parse_archive_format(raw: &str) -> Result<ArchiveFormat, String> {
    match raw {
        FORMAT_ZIP => Ok(ArchiveFormat::Zip),
        raw if TAR_ZST_FORMAT_ALIASES.contains(&raw) => Ok(ArchiveFormat::TarZst),
        raw if TZAP_FORMAT_ALIASES.contains(&raw) => Ok(ArchiveFormat::Tzap),
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        raw if APPLE_ARCHIVE_FORMAT_ALIASES.contains(&raw) => Ok(ArchiveFormat::AppleArchive),
        FORMAT_SEVEN_Z => Ok(ArchiveFormat::SevenZ),
        raw if TGZ_FORMAT_ALIASES.contains(&raw) => Ok(ArchiveFormat::Tgz),
        _ => Err(format!("unsupported archive format: {raw}")),
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn infer_apple_archive_create_format(path: &str) -> Option<ArchiveFormat> {
    if is_apple_archive(path) { Some(ArchiveFormat::AppleArchive) } else { None }
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
fn infer_apple_archive_create_format(_path: &str) -> Option<ArchiveFormat> {
    None
}

pub(crate) fn infer_create_format(path: &str) -> Option<ArchiveFormat> {
    if path == "-" {
        return None;
    }
    if is_zip_family_archive(path) {
        Some(ArchiveFormat::Zip)
    } else if is_tar_zst_archive(path) {
        Some(ArchiveFormat::TarZst)
    } else if is_tgz_archive(path) {
        Some(ArchiveFormat::Tgz)
    } else if is_tzap_archive(path) {
        Some(ArchiveFormat::Tzap)
    } else if let Some(format) = infer_apple_archive_create_format(path) {
        Some(format)
    } else if path_has_known_extension(path, SEVEN_Z_EXTENSIONS) {
        Some(ArchiveFormat::SevenZ)
    } else {
        None
    }
}

pub(crate) fn resolve_input_path(value: &str, current_dir: Option<&Path>) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        path
    } else if let Some(current_dir) = current_dir {
        current_dir.join(path)
    } else {
        path
    }
}
pub(crate) fn read_optional_password_stdin(enabled: bool, global: &GlobalOptions) -> Result<Option<SecretString>, ExitCode> {
    if enabled { prompt_password_from_stdin(Some(global)).map(Some) } else { Ok(None) }
}

pub(crate) fn validate_recipient_key_open_option(command: &str, archive: &str, password_stdin: bool, recipient_key: Option<&PathBuf>, global: &GlobalOptions) -> Option<ExitCode> {
    recipient_key?;
    if !is_tzap_archive(archive) {
        return Some(usage_failure(global, format_args!("{command} failed: --recipient-key is supported only for TZAP archives")));
    }
    if password_stdin {
        return Some(usage_failure(global, format_args!("{command} failed: --recipient-key cannot be combined with --password-stdin")));
    }
    None
}
