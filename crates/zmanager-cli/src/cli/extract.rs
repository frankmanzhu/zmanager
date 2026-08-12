use crate::cli::app::{
    ExtractOutcome, ExtractRequest, InteractiveOverwriteResolver, ProgressReporter, default_extract_destination, default_raw_stream_destination,
    expand_short_options,
};
use crate::cli::format::FORMAT_APPLE_ARCHIVE;
use crate::cli::format::{
    BACKEND_DEB_NESTED, FORMAT_DEB, FORMAT_DMG, FORMAT_LIBARCHIVE, FORMAT_PKG, FORMAT_RAR, FORMAT_SEVEN_Z, FORMAT_TAR_ZST, FORMAT_TZAP, FORMAT_ZIP,
    is_deb_archive,
};
use crate::cli::open::entry_selected;
use crate::cli::options::{GlobalOptions, parse_global_option, parse_usize, read_optional_password_stdin, take_value, validate_recipient_key_open_option};
use crate::cli::usage::{
    EXTRACT_HELP, command_usage_error, print_error_line, print_extract_summary, print_help_stdout, print_raw_stream_extract_summary, retry_password_required,
    usage_failure, wants_help,
};
use crate::output::{self, StyleRole};
use std::env;
use std::io::{self, IsTerminal as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use zmanager_core::archive_format::{ArchiveFormatKind, detect_archive_format};
use zmanager_core::jobs::{CancellationToken, JobContext, JobEvent, JobKind};
use zmanager_core::safety::OverwritePolicy;
pub(crate) fn extract_command(args: &[String], global: GlobalOptions) -> ExitCode {
    if wants_help(args) {
        print_help_stdout(EXTRACT_HELP, &global);
        return ExitCode::SUCCESS;
    }
    let expanded = expand_short_options(args);
    extract_command_from_expanded(&expanded, global)
}

pub(crate) fn extract_command_from_expanded(args: &[String], mut global: GlobalOptions) -> ExitCode {
    if wants_help(args) {
        print_help_stdout(EXTRACT_HELP, &global);
        return ExitCode::SUCCESS;
    }
    let mut request = ExtractRequest::default();
    match parse_extract_request(args, &mut global, &mut request) {
        Ok(()) => run_extract_request(request, &global),
        Err(error) => command_usage_error("extract", &error, &global),
    }
}

pub(crate) fn parse_extract_request(args: &[String], global: &mut GlobalOptions, request: &mut ExtractRequest) -> Result<(), String> {
    let mut index = 0usize;
    let mut positional = Vec::new();
    let mut after_double_dash = false;
    while index < args.len() {
        let arg = &args[index];
        if after_double_dash {
            positional.push(arg.clone());
            index += 1;
            continue;
        }
        if arg == "--" {
            after_double_dash = true;
            index += 1;
            continue;
        }
        if parse_global_option(args, &mut index, global)? {
            continue;
        }
        match arg.as_str() {
            "-x" | "--extract" => index += 1,
            "-f" | "--file" => request.archive = take_value(args, &mut index, arg)?,
            "-C" | "-d" | "--directory" => {
                request.destination = Some(PathBuf::from(take_value(args, &mut index, arg)?));
            }
            "--here" => {
                request.destination = Some(env::current_dir().map_err(|error| error.to_string())?);
                index += 1;
            }
            "--overwrite" => {
                request.overwrite = Some(take_value(args, &mut index, arg)?);
            }
            "--strip-components" => {
                let value = take_value(args, &mut index, arg)?;
                request.strip_components = parse_usize(&value, arg)?;
            }
            "-i" | "--include" => {
                request.include.push(take_value(args, &mut index, arg)?);
            }
            "--exclude" => {
                request.exclude.push(take_value(args, &mut index, arg)?);
            }
            "--to-stdout" => {
                request.to_stdout = true;
                index += 1;
            }
            "--extract-nested" => {
                request.extract_nested = true;
                index += 1;
            }
            "--password-stdin" => {
                request.password_stdin = true;
                index += 1;
            }
            "--recipient-key" => {
                request.recipient_key = Some(PathBuf::from(take_value(args, &mut index, arg)?));
            }
            "--restore" => {
                let value = take_value(args, &mut index, arg)?;
                request.tzap_restore_policy = parse_tzap_restore_policy(&value)?;
            }
            "--allow-degraded" => {
                request.tzap_allow_degraded = true;
                index += 1;
            }
            _ if arg.starts_with('-') => return Err(format!("unknown extract option: {arg}")),
            _ => {
                positional.push(arg.clone());
                index += 1;
            }
        }
    }
    if request.archive.is_empty()
        && let Some(archive) = positional.first()
    {
        request.archive.clone_from(archive);
    }
    if request.destination.is_none()
        && let Some(destination) = positional.get(1)
    {
        request.destination = Some(PathBuf::from(destination));
    }
    if request.archive.is_empty() {
        return Err("missing archive path".to_owned());
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn run_extract_request(request: ExtractRequest, global: &GlobalOptions) -> ExitCode {
    if let Some(code) = validate_recipient_key_open_option("extract", &request.archive, request.password_stdin, request.recipient_key.as_ref(), global) {
        return code;
    }
    if request.to_stdout {
        return run_extract_to_stdout(&request, global);
    }
    let policy = match extraction_policy(&request) {
        Ok(policy) => policy,
        Err(error) => return command_usage_error("extract", &error, global),
    };
    if request.extract_nested {
        if request.password_stdin {
            return usage_failure(global, format_args!("extract failed: nested package extraction does not use passwords"));
        }
        if !is_deb_archive(&request.archive) {
            return usage_failure(global, format_args!("extract failed: --extract-nested is currently supported only for .deb packages"));
        }
        let destination = request.destination.unwrap_or_else(|| default_extract_destination(&request.archive));
        return run_deb_nested_extract(&request.archive, &destination, policy, global);
    }
    if let Some(format) = zmanager_core::raw_stream_backend::detect_raw_stream_format(&request.archive) {
        if request.password_stdin {
            return usage_failure(global, format_args!("extract failed: raw streams are not encrypted; remove --password-stdin"));
        }
        let destination = request.destination.unwrap_or_else(|| default_raw_stream_destination(&request.archive));
        return run_raw_stream_extract(&request.archive, format, &destination, policy, global);
    }
    let destination = request.destination.unwrap_or_else(|| default_extract_destination(&request.archive));
    let password = match read_optional_password_stdin(request.password_stdin, global) {
        Ok(password) => password,
        Err(code) => return code,
    };
    match detect_archive_format(&request.archive) {
        // Raw streams are handled before the policy match above.
        ArchiveFormatKind::RawStream => unreachable!("raw streams handled before format dispatch"),
        ArchiveFormatKind::Zip => run_zip_extract_with_policy(request.archive, destination, password.as_deref(), policy, global),
        ArchiveFormatKind::SevenZ => run_7z_extract_with_policy(request.archive, destination, password.as_deref(), policy, global),
        // RAR needs a password; without --password-stdin it falls through to
        // the libarchive backend, which can read unencrypted RAR.
        ArchiveFormatKind::Rar if request.password_stdin => run_rar_extract_with_policy(request.archive, destination, policy, password.as_deref(), global),
        ArchiveFormatKind::TarZst => run_tar_zst_extract_with_policy(request.archive, destination, policy, global),
        ArchiveFormatKind::AppleArchive => run_apple_archive_extract_with_policy(request.archive, destination, policy, password.as_deref(), global),
        ArchiveFormatKind::Dmg => run_apple_dmg_extract_with_policy(request.archive, destination, policy, global),
        ArchiveFormatKind::Pkg => run_apple_pkg_extract_with_policy(request.archive, destination, policy, global),
        ArchiveFormatKind::Tzap => run_tzap_extract_with_policy(
            request.archive,
            destination,
            policy,
            password.as_deref(),
            request.recipient_key.as_deref(),
            zmanager_core::tzap_backend::TzapRestoreOptions {
                policy: request.tzap_restore_policy,
                allow_degraded: request.tzap_allow_degraded,
                allow_absolute_symlinks: false,
            },
            global,
        ),
        // Split ZIP volume sets and the remaining formats are read through
        // libarchive, matching the pre-CR-114 fallthrough behavior.
        ArchiveFormatKind::SplitZip
        | ArchiveFormatKind::TarGz
        | ArchiveFormatKind::Deb
        | ArchiveFormatKind::Unknown
        | ArchiveFormatKind::Rar
        | ArchiveFormatKind::Tar
        | ArchiveFormatKind::TarBz2
        | ArchiveFormatKind::TarXz
        | ArchiveFormatKind::TarLzma
        | ArchiveFormatKind::Iso
        | ArchiveFormatKind::Cab
        | ArchiveFormatKind::Cpio
        | ArchiveFormatKind::Rpm
        | ArchiveFormatKind::Xar
        | ArchiveFormatKind::Lha
        | ArchiveFormatKind::Ar
        | ArchiveFormatKind::Warc
        | ArchiveFormatKind::Mtree => run_libarchive_extract_with_policy(request.archive, destination, policy, password.as_deref(), global),
    }
}
fn run_deb_nested_extract(archive: &str, destination: &Path, policy: zmanager_core::safety::ExtractionPolicy, global: &GlobalOptions) -> ExitCode {
    let result = if matches!(policy.overwrite, OverwritePolicy::Ask) {
        let stdin = io::stdin();
        let stderr = io::stderr();
        let mut overwrite_resolver = InteractiveOverwriteResolver::new(stdin.lock(), stderr.lock());
        zmanager_core::deb_backend::extract_deb_nested_with_overwrite_resolver(archive, destination, policy, &mut overwrite_resolver)
    } else {
        zmanager_core::deb_backend::extract_deb_nested(archive, destination, policy)
    };
    match result {
        Ok(report) => {
            let outcome = ExtractOutcome {
                label: "deb nested",
                format: FORMAT_DEB,
                backend: BACKEND_DEB_NESTED,
                written_entries: report.written_entries,
                skipped_entries: report.skipped_entries,
                written_bytes: report.written_bytes,
                warnings: report.warnings,
            };
            print_extract_summary(Path::new(archive), destination, &outcome, global);
            ExitCode::SUCCESS
        }
        Err(error) => {
            print_error_line(global, format_args!("extract failed: {error}"));
            ExitCode::FAILURE
        }
    }
}

fn run_raw_stream_extract(
    archive: &str,
    format: zmanager_core::raw_stream_backend::RawStreamFormat,
    destination: &Path,
    policy: zmanager_core::safety::ExtractionPolicy,
    global: &GlobalOptions,
) -> ExitCode {
    let result = if matches!(policy.overwrite, OverwritePolicy::Ask) {
        let stdin = io::stdin();
        let stderr = io::stderr();
        let mut overwrite_resolver = InteractiveOverwriteResolver::new(stdin.lock(), stderr.lock());
        zmanager_core::raw_stream_backend::extract_raw_stream_with_overwrite_resolver(archive, format, destination, policy, &mut overwrite_resolver)
    } else {
        zmanager_core::raw_stream_backend::extract_raw_stream(archive, format, destination, policy)
    };
    match result {
        Ok(report) => {
            print_raw_stream_extract_summary(Path::new(archive), format, &report, global);
            ExitCode::SUCCESS
        }
        Err(error) => {
            print_error_line(global, format_args!("extract failed: {error}"));
            ExitCode::FAILURE
        }
    }
}
#[allow(clippy::too_many_lines)]
fn run_extract_to_stdout(request: &ExtractRequest, global: &GlobalOptions) -> ExitCode {
    if request.extract_nested {
        print_error_line(global, format_args!("extract failed: --extract-nested cannot be combined with --to-stdout"));
        return ExitCode::from(2);
    }
    if request.destination.is_some() {
        print_error_line(global, format_args!("extract failed: --to-stdout cannot be combined with an extraction directory"));
        return ExitCode::from(2);
    }
    if request.strip_components > 0 {
        print_error_line(global, format_args!("extract failed: --strip-components is not meaningful with --to-stdout"));
        return ExitCode::from(2);
    }

    // Raw streams are handled before the format dispatch, mirroring
    // `run_extract_request`.
    if let Some(format) = zmanager_core::raw_stream_backend::detect_raw_stream_format(&request.archive) {
        if request.password_stdin {
            print_error_line(global, format_args!("extract to stdout failed: raw streams are not encrypted; remove --password-stdin"));
            return ExitCode::from(2);
        }
        let Some(output_name) = zmanager_core::raw_stream_backend::output_name_for_raw_stream(&request.archive, format) else {
            print_error_line(global, format_args!("extract to stdout failed: could not derive raw stream output name"));
            return ExitCode::FAILURE;
        };
        if !entry_selected(&output_name, &request.include, &request.exclude) {
            print_extract_stdout_ok(global, "extract", "0 entries", 1, 0);
            return ExitCode::SUCCESS;
        }
        let mut stdout = io::stdout().lock();
        match zmanager_core::raw_stream_backend::copy_raw_stream_to_writer(&request.archive, format, &mut stdout) {
            Ok(written_bytes) => {
                print_extract_stdout_ok(global, "extract", "1 entry", 0, written_bytes);
                ExitCode::SUCCESS
            }
            Err(error) => {
                print_error_line(global, format_args!("extract to stdout failed: {error}"));
                ExitCode::FAILURE
            }
        }
    } else {
        let password = match read_optional_password_stdin(request.password_stdin, global) {
            Ok(password) => password,
            Err(code) => return code,
        };
        match detect_archive_format(&request.archive) {
            // Raw streams are handled before the format dispatch.
            ArchiveFormatKind::RawStream => unreachable!("raw streams handled before format dispatch"),
            ArchiveFormatKind::Zip => copy_zip_archive_to_stdout(request, password.as_deref(), global),
            ArchiveFormatKind::SevenZ => copy_7z_archive_to_stdout(request, password.as_deref(), global),
            ArchiveFormatKind::TarZst => copy_tar_zst_archive_to_stdout(request, global),
            ArchiveFormatKind::Tzap => copy_tzap_archive_to_stdout(request, password.as_deref(), global),
            ArchiveFormatKind::AppleArchive => extract_apple_archive_stdout(&request.archive, &request.include, &request.exclude, password.as_deref(), global),
            ArchiveFormatKind::Dmg | ArchiveFormatKind::Pkg => {
                print_error_line(global, format_args!("extract to stdout failed: DMG and PKG formats do not currently support extracting to stdout"));
                ExitCode::FAILURE
            }
            // Split ZIP volume sets, tgz, .deb, RAR, and unrecognized formats
            // are read through libarchive, matching the pre-CR-114
            // fallthrough behavior.
            ArchiveFormatKind::SplitZip
            | ArchiveFormatKind::TarGz
            | ArchiveFormatKind::Deb
            | ArchiveFormatKind::Rar
            | ArchiveFormatKind::Tar
            | ArchiveFormatKind::TarBz2
            | ArchiveFormatKind::TarXz
            | ArchiveFormatKind::TarLzma
            | ArchiveFormatKind::Iso
            | ArchiveFormatKind::Cab
            | ArchiveFormatKind::Cpio
            | ArchiveFormatKind::Rpm
            | ArchiveFormatKind::Xar
            | ArchiveFormatKind::Lha
            | ArchiveFormatKind::Ar
            | ArchiveFormatKind::Warc
            | ArchiveFormatKind::Mtree
            | ArchiveFormatKind::Unknown => {
                copy_archive_to_stdout(&request.include, &request.exclude, password.as_deref(), "extract", global, None, |password, selected, stdout| {
                    zmanager_core::libarchive_backend::copy_archive_files_to_writer(&request.archive, password, selected, stdout)
                        .map(|report| (report.written_entries, report.skipped_entries, report.written_bytes))
                        .map_err(|error| StdoutCopyError::Message(error.to_string()))
                })
            }
        }
    }
}

fn copy_zip_archive_to_stdout(request: &ExtractRequest, password: Option<&str>, global: &GlobalOptions) -> ExitCode {
    copy_archive_to_stdout(&request.include, &request.exclude, password, "extract", global, Some("ZIP password: "), |password, selected, stdout| {
        zmanager_core::zip_backend::copy_zip_files_to_writer(&request.archive, password, selected, stdout)
            .map(|report| (report.written_entries, report.skipped_entries, report.written_bytes))
            .map_err(|error| match error {
                zmanager_core::zip_backend::ZipBackendError::PasswordRequired => StdoutCopyError::PasswordRequired(error.to_string()),
                error => StdoutCopyError::Message(error.to_string()),
            })
    })
}

fn copy_7z_archive_to_stdout(request: &ExtractRequest, password: Option<&str>, global: &GlobalOptions) -> ExitCode {
    copy_archive_to_stdout(&request.include, &request.exclude, password, "extract", global, Some("7z password: "), |password, selected, stdout| {
        zmanager_core::sevenz_backend::copy_7z_files_to_writer(&request.archive, password, selected, stdout)
            .map(|report| (report.written_entries, report.skipped_entries, report.written_bytes))
            .map_err(|error| match error {
                zmanager_core::sevenz_backend::SevenZError::PasswordRequired => StdoutCopyError::PasswordRequired(error.to_string()),
                error => StdoutCopyError::Message(error.to_string()),
            })
    })
}

fn copy_tar_zst_archive_to_stdout(request: &ExtractRequest, global: &GlobalOptions) -> ExitCode {
    copy_archive_to_stdout(&request.include, &request.exclude, None, "extract", global, None, |_password, selected, stdout| {
        zmanager_core::tar_zst_backend::copy_tar_zst_files_to_writer(&request.archive, selected, stdout)
            .map(|report| (report.written_entries, report.skipped_entries, report.written_bytes))
            .map_err(|error| StdoutCopyError::Message(error.to_string()))
    })
}

fn copy_tzap_archive_to_stdout(request: &ExtractRequest, password: Option<&str>, global: &GlobalOptions) -> ExitCode {
    copy_archive_to_stdout(&request.include, &request.exclude, password, "extract", global, None, |password, _selected, stdout| {
        zmanager_core::tzap_backend::copy_tzap_files_to_writer(
            &request.archive,
            tzap_extract_key(request.recipient_key.as_deref(), password),
            |name| entry_selected(name, &request.include, &request.exclude),
            stdout,
        )
        .map(|report| (report.written_entries, report.skipped_entries, report.written_bytes))
        .map_err(|error| StdoutCopyError::Message(error.to_string()))
    })
}

fn tzap_extract_key<'a>(recipient_key: Option<&'a Path>, password: Option<&'a str>) -> zmanager_core::tzap_backend::TzapExtractKeySource<'a> {
    match recipient_key {
        Some(recipient_key) => zmanager_core::tzap_backend::TzapExtractKeySource::RecipientKeyPath(recipient_key),
        None => match password {
            Some(password) => zmanager_core::tzap_backend::TzapExtractKeySource::Password(password),
            None => zmanager_core::tzap_backend::TzapExtractKeySource::None,
        },
    }
}

fn print_extract_stdout_ok(global: &GlobalOptions, label: &str, entries_label: &str, skipped: usize, bytes: u64) {
    if global.verbose > 0 && !global.quiet {
        output::stderr_line(
            global.color,
            format_args!("{} to stdout ok: {entries_label}, {} skipped, {} bytes", output::styled(StyleRole::Success, format_args!("{label}")), skipped, bytes),
        );
    }
}

enum StdoutCopyError {
    PasswordRequired(String),
    Message(String),
}

#[allow(clippy::too_many_arguments)]
fn copy_archive_to_stdout(
    include: &[String],
    exclude: &[String],
    password: Option<&str>,
    label: &str,
    global: &GlobalOptions,
    password_prompt: Option<&str>,
    mut copy: impl FnMut(Option<&str>, &mut dyn Fn(&str) -> bool, &mut io::StdoutLock<'_>) -> Result<(usize, usize, u64), StdoutCopyError>,
) -> ExitCode {
    let mut stdout = io::stdout().lock();
    let selected = |name: &str| entry_selected(name, include, exclude);
    match copy(password, &mut &selected, &mut stdout) {
        Ok((entries, skipped, bytes)) => {
            print_extract_stdout_ok(global, label, &format!("{entries} entries"), skipped, bytes);
            ExitCode::SUCCESS
        }
        Err(StdoutCopyError::PasswordRequired(_)) if password.is_none() => retry_password_required(
            global,
            "extract to stdout failed: ",
            password_prompt,
            |message| print_error_line(global, format_args!("{message}")),
            |prompted| match copy(Some(prompted.expose_secret()), &mut &selected, &mut stdout) {
                Ok(_) => ExitCode::SUCCESS,
                Err(StdoutCopyError::PasswordRequired(message) | StdoutCopyError::Message(message)) => {
                    print_error_line(global, format_args!("extract to stdout failed: {message}"));
                    ExitCode::FAILURE
                }
            },
        ),
        Err(StdoutCopyError::PasswordRequired(message) | StdoutCopyError::Message(message)) => {
            print_error_line(global, format_args!("extract to stdout failed: {message}"));
            ExitCode::FAILURE
        }
    }
}
fn parse_tzap_restore_policy(value: &str) -> Result<zmanager_core::tzap_backend::TzapRestorePolicy, String> {
    match value {
        "content" => Ok(zmanager_core::tzap_backend::TzapRestorePolicy::Content),
        "portable" => Ok(zmanager_core::tzap_backend::TzapRestorePolicy::Portable),
        "same-os" => Ok(zmanager_core::tzap_backend::TzapRestorePolicy::SameOs),
        "system" => Ok(zmanager_core::tzap_backend::TzapRestorePolicy::System),
        _ => Err(format!("unsupported TZAP restore policy: {value}; expected content, portable, same-os, or system")),
    }
}

fn extraction_policy(request: &ExtractRequest) -> Result<zmanager_core::safety::ExtractionPolicy, String> {
    let overwrite = match request.overwrite.as_deref().unwrap_or("never") {
        "never" => OverwritePolicy::Refuse,
        "always" => OverwritePolicy::Replace,
        "rename" => OverwritePolicy::Rename,
        "ask" if io::stdin().is_terminal() => OverwritePolicy::Ask,
        "ask" => return Err("--overwrite ask requires an interactive terminal".to_owned()),
        value => return Err(format!("unsupported overwrite policy: {value}")),
    };

    Ok(zmanager_core::safety::ExtractionPolicy {
        overwrite,
        include_patterns: request.include.clone(),
        exclude_patterns: request.exclude.clone(),
        strip_components: request.strip_components,
        ..zmanager_core::safety::ExtractionPolicy::default()
    })
}
fn extract_apple_archive_stdout(archive: &str, include: &[String], exclude: &[String], password: Option<&str>, global: &GlobalOptions) -> ExitCode {
    copy_archive_to_stdout(include, exclude, password, FORMAT_APPLE_ARCHIVE, global, None, |password, selected, stdout| {
        zmanager_core::apple_archive_backend::copy_apple_archive_files_to_writer(archive, selected, stdout, password)
            .map(|report| (report.written_entries, report.skipped_entries, report.written_bytes))
            .map_err(|error| StdoutCopyError::Message(error.to_string()))
    })
}

struct CliExtractReport {
    written_entries: usize,
    skipped_entries: usize,
    written_bytes: u64,
    warnings: Vec<String>,
}

impl From<zmanager_core::zip_backend::ZipExtractReport> for CliExtractReport {
    fn from(report: zmanager_core::zip_backend::ZipExtractReport) -> Self {
        Self {
            written_entries: report.written_entries,
            skipped_entries: report.skipped_entries,
            written_bytes: report.written_bytes,
            warnings: report.warnings,
        }
    }
}

impl From<zmanager_core::tar_zst_backend::TarZstdExtractReport> for CliExtractReport {
    fn from(report: zmanager_core::tar_zst_backend::TarZstdExtractReport) -> Self {
        Self {
            written_entries: report.written_entries,
            skipped_entries: report.skipped_entries,
            written_bytes: report.written_bytes,
            warnings: report.warnings,
        }
    }
}

impl From<zmanager_core::sevenz_backend::SevenZExtractReport> for CliExtractReport {
    fn from(report: zmanager_core::sevenz_backend::SevenZExtractReport) -> Self {
        Self {
            written_entries: report.written_entries,
            skipped_entries: report.skipped_entries,
            written_bytes: report.written_bytes,
            warnings: report.warnings,
        }
    }
}

impl From<zmanager_core::rar_backend::RarExtractReport> for CliExtractReport {
    fn from(report: zmanager_core::rar_backend::RarExtractReport) -> Self {
        Self {
            written_entries: report.written_entries,
            skipped_entries: report.skipped_entries,
            written_bytes: report.written_bytes,
            warnings: report.warnings,
        }
    }
}

impl From<zmanager_core::libarchive_backend::LibarchiveExtractReport> for CliExtractReport {
    fn from(report: zmanager_core::libarchive_backend::LibarchiveExtractReport) -> Self {
        Self {
            written_entries: report.written_entries,
            skipped_entries: report.skipped_entries,
            written_bytes: report.written_bytes,
            warnings: report.warnings,
        }
    }
}

impl From<zmanager_core::apple_archive_backend::AppleArchiveExtractReport> for CliExtractReport {
    fn from(report: zmanager_core::apple_archive_backend::AppleArchiveExtractReport) -> Self {
        Self {
            written_entries: report.written_entries,
            skipped_entries: report.skipped_entries,
            written_bytes: report.written_bytes,
            warnings: report.warnings,
        }
    }
}

impl From<zmanager_core::apple_dmg_backend::DmgExtractReport> for CliExtractReport {
    fn from(report: zmanager_core::apple_dmg_backend::DmgExtractReport) -> Self {
        Self {
            written_entries: report.written_entries,
            skipped_entries: report.skipped_entries,
            written_bytes: report.written_bytes,
            warnings: report.warnings,
        }
    }
}

impl From<zmanager_core::apple_pkg_backend::PkgExtractReport> for CliExtractReport {
    fn from(report: zmanager_core::apple_pkg_backend::PkgExtractReport) -> Self {
        Self {
            written_entries: report.written_entries,
            skipped_entries: report.skipped_entries,
            written_bytes: report.written_bytes,
            warnings: report.warnings,
        }
    }
}

impl From<zmanager_core::tzap_backend::TzapExtractReport> for CliExtractReport {
    fn from(report: zmanager_core::tzap_backend::TzapExtractReport) -> Self {
        Self {
            written_entries: report.written_entries,
            skipped_entries: report.skipped_entries,
            written_bytes: report.written_bytes,
            warnings: report.warnings,
        }
    }
}

enum CliExtractError {
    PasswordRequired(String),
    Message(String),
}

type CliOverwriteResolver = InteractiveOverwriteResolver<io::StdinLock<'static>, io::StderrLock<'static>>;
type ExtractAskClosure<'a> =
    dyn Fn(&Path, &Path, zmanager_core::safety::ExtractionPolicy, Option<&str>, &mut CliOverwriteResolver) -> Result<CliExtractReport, CliExtractError> + 'a;
type ExtractPlainClosure<'a> = dyn for<'ctx> Fn(&Path, &Path, zmanager_core::safety::ExtractionPolicy, Option<&str>, &mut JobContext<'ctx>) -> Result<CliExtractReport, CliExtractError>
    + 'a;

#[derive(Clone, Copy)]
struct ExtractBackendSpec<'a> {
    label: &'static str,
    kind: JobKind,
    error_prefix: &'static str,
    password_prompt: Option<&'static str>,
    progress: bool,
    ask: &'a ExtractAskClosure<'a>,
    plain: &'a ExtractPlainClosure<'a>,
}

fn run_extract_with_policy(
    archive: impl AsRef<std::path::Path>,
    destination: impl AsRef<std::path::Path>,
    policy: zmanager_core::safety::ExtractionPolicy,
    password: Option<&str>,
    global: &GlobalOptions,
    spec: ExtractBackendSpec<'_>,
) -> ExitCode {
    let archive_path = archive.as_ref().to_path_buf();
    let destination_path = destination.as_ref().to_path_buf();
    let mut progress = ProgressReporter::from_global(Some(global));
    if spec.progress {
        progress.emit(JobEvent::Started { kind: spec.kind, total_bytes: None });
    }
    let token = CancellationToken::new();
    let result = if matches!(policy.overwrite, OverwritePolicy::Ask) {
        let stdin = io::stdin();
        let stderr = io::stderr();
        let mut overwrite_resolver = InteractiveOverwriteResolver::new(stdin.lock(), stderr.lock());
        (spec.ask)(&archive_path, &destination_path, policy.clone(), password, &mut overwrite_resolver)
    } else {
        let mut sink = |event| progress.emit(event);
        let mut context = JobContext::new(&token, &mut sink);
        let result = (spec.plain)(&archive_path, &destination_path, policy.clone(), password, &mut context);
        context.flush_progress();
        result
    };
    match result {
        Ok(report) => {
            if spec.progress {
                progress.emit(JobEvent::Completed { entries: report.written_entries, bytes: report.written_bytes });
            }
            let outcome = ExtractOutcome {
                label: spec.label,
                format: spec.label,
                backend: spec.label,
                written_entries: report.written_entries,
                skipped_entries: report.skipped_entries,
                written_bytes: report.written_bytes,
                warnings: report.warnings,
            };
            print_extract_summary(&archive_path, &destination_path, &outcome, global);
            ExitCode::SUCCESS
        }
        Err(CliExtractError::PasswordRequired(_)) if password.is_none() => retry_password_required(
            global,
            spec.error_prefix,
            spec.password_prompt,
            |message| {
                if spec.progress {
                    progress.emit(JobEvent::Failed { message: message.to_owned() });
                }
                eprintln!("{message}");
            },
            |password| run_extract_with_policy(&archive_path, &destination_path, policy, Some(password.expose_secret()), global, spec),
        ),
        Err(CliExtractError::PasswordRequired(message) | CliExtractError::Message(message)) => {
            if spec.progress {
                progress.emit(JobEvent::Failed { message: message.clone() });
            }
            eprintln!("{}{}", spec.error_prefix, message);
            ExitCode::FAILURE
        }
    }
}

fn run_zip_extract_with_policy(
    archive: impl AsRef<std::path::Path>,
    destination: impl AsRef<std::path::Path>,
    password: Option<&str>,
    policy: zmanager_core::safety::ExtractionPolicy,
    global: &GlobalOptions,
) -> ExitCode {
    run_extract_with_policy(
        archive,
        destination,
        policy,
        password,
        global,
        ExtractBackendSpec {
            label: FORMAT_ZIP,
            kind: JobKind::ZipExtract,
            error_prefix: "zip extract failed: ",
            password_prompt: Some("ZIP password: "),
            progress: true,
            ask: &|archive_path, destination_path, policy, password, resolver| {
                zmanager_core::zip_backend::extract_zip_with_overwrite_resolver_and_password(archive_path, destination_path, policy, password, resolver)
                    .map(CliExtractReport::from)
                    .map_err(|error| match error {
                        zmanager_core::zip_backend::ZipBackendError::PasswordRequired => CliExtractError::PasswordRequired(error.to_string()),
                        error => CliExtractError::Message(error.to_string()),
                    })
            },
            plain: &|archive_path, destination_path, policy, password, context| {
                zmanager_core::zip_backend::extract_zip_with_context_and_password(archive_path, destination_path, policy, password, context)
                    .map(CliExtractReport::from)
                    .map_err(|error| match error {
                        zmanager_core::zip_backend::ZipBackendError::PasswordRequired => CliExtractError::PasswordRequired(error.to_string()),
                        error => CliExtractError::Message(error.to_string()),
                    })
            },
        },
    )
}

fn run_tar_zst_extract_with_policy(
    archive: impl AsRef<std::path::Path>,
    destination: impl AsRef<std::path::Path>,
    policy: zmanager_core::safety::ExtractionPolicy,
    global: &GlobalOptions,
) -> ExitCode {
    run_extract_with_policy(
        archive,
        destination,
        policy,
        None,
        global,
        ExtractBackendSpec {
            label: FORMAT_TAR_ZST,
            kind: JobKind::TarZstdExtract,
            error_prefix: "tar.zst extract failed: ",
            password_prompt: None,
            progress: true,
            ask: &|archive_path, destination_path, policy, _password, resolver| {
                zmanager_core::tar_zst_backend::extract_tar_zst_with_overwrite_resolver(archive_path, destination_path, policy, resolver)
                    .map(CliExtractReport::from)
                    .map_err(|error| CliExtractError::Message(error.to_string()))
            },
            plain: &|archive_path, destination_path, policy, _password, context| {
                zmanager_core::tar_zst_backend::extract_tar_zst_with_context(archive_path, destination_path, policy, context)
                    .map(CliExtractReport::from)
                    .map_err(|error| CliExtractError::Message(error.to_string()))
            },
        },
    )
}

fn run_apple_archive_extract_with_policy(
    archive: impl AsRef<std::path::Path>,
    destination: impl AsRef<std::path::Path>,
    policy: zmanager_core::safety::ExtractionPolicy,
    password: Option<&str>,
    global: &GlobalOptions,
) -> ExitCode {
    run_extract_with_policy(
        archive,
        destination,
        policy,
        password,
        global,
        ExtractBackendSpec {
            label: FORMAT_APPLE_ARCHIVE,
            kind: JobKind::AppleArchiveExtract,
            error_prefix: "aar extract failed: ",
            password_prompt: None,
            progress: true,
            ask: &|archive_path, destination_path, policy, password, resolver| {
                zmanager_core::apple_archive_backend::extract_apple_archive_with_overwrite_resolver(archive_path, destination_path, policy, resolver, password)
                    .map(CliExtractReport::from)
                    .map_err(|error| CliExtractError::Message(error.to_string()))
            },
            plain: &|archive_path, destination_path, policy, password, context| {
                zmanager_core::apple_archive_backend::extract_apple_archive_with_context(archive_path, destination_path, policy, password, context)
                    .map(CliExtractReport::from)
                    .map_err(|error| CliExtractError::Message(error.to_string()))
            },
        },
    )
}

fn run_tzap_extract_with_policy(
    archive: impl AsRef<std::path::Path>,
    destination: impl AsRef<std::path::Path>,
    policy: zmanager_core::safety::ExtractionPolicy,
    password: Option<&str>,
    recipient_key: Option<&Path>,
    restore_options: zmanager_core::tzap_backend::TzapRestoreOptions,
    global: &GlobalOptions,
) -> ExitCode {
    run_extract_with_policy(
        archive,
        destination,
        policy,
        password,
        global,
        ExtractBackendSpec {
            label: FORMAT_TZAP,
            kind: JobKind::TzapExtract,
            error_prefix: "tzap extract failed: ",
            password_prompt: None,
            progress: true,
            ask: &|archive_path, destination_path, policy, password, resolver| {
                let key = tzap_extract_key(recipient_key, password);
                zmanager_core::tzap_backend::extract_tzap(
                    zmanager_core::tzap_backend::TzapExtractRequest {
                        key,
                        policy,
                        restore_options,
                        overwrite_resolver: Some(resolver),
                        context: None,
                        fast: false,
                    },
                    archive_path,
                    destination_path,
                )
                .map(|report| CliExtractReport {
                    written_entries: report.written_entries,
                    skipped_entries: report.skipped_entries,
                    written_bytes: report.written_bytes,
                    warnings: report.warnings,
                })
                .map_err(|error| CliExtractError::Message(error.to_string()))
            },
            plain: &|archive_path, destination_path, policy, password, _context| {
                let key = tzap_extract_key(recipient_key, password);
                zmanager_core::tzap_backend::extract_tzap(
                    zmanager_core::tzap_backend::TzapExtractRequest { key, policy, restore_options, overwrite_resolver: None, context: None, fast: false },
                    archive_path,
                    destination_path,
                )
                .map(CliExtractReport::from)
                .map_err(|error| CliExtractError::Message(error.to_string()))
            },
        },
    )
}

fn run_7z_extract_with_policy(
    archive: impl AsRef<std::path::Path>,
    destination: impl AsRef<std::path::Path>,
    password: Option<&str>,
    policy: zmanager_core::safety::ExtractionPolicy,
    global: &GlobalOptions,
) -> ExitCode {
    run_extract_with_policy(
        archive,
        destination,
        policy,
        password,
        global,
        ExtractBackendSpec {
            label: FORMAT_SEVEN_Z,
            kind: JobKind::SevenZExtract,
            error_prefix: "7z extract failed: ",
            password_prompt: Some("7z password: "),
            progress: true,
            ask: &|archive_path, destination_path, policy, password, resolver| {
                zmanager_core::sevenz_backend::extract_7z_with_overwrite_resolver(archive_path, destination_path, password, policy, resolver)
                    .map(CliExtractReport::from)
                    .map_err(|error| match error {
                        zmanager_core::sevenz_backend::SevenZError::PasswordRequired => CliExtractError::PasswordRequired(error.to_string()),
                        error => CliExtractError::Message(error.to_string()),
                    })
            },
            plain: &|archive_path, destination_path, policy, password, _context| {
                zmanager_core::sevenz_backend::extract_7z(archive_path, destination_path, password, policy)
                    .map(|report| CliExtractReport {
                        written_entries: report.written_entries,
                        skipped_entries: report.skipped_entries,
                        written_bytes: report.written_bytes,
                        warnings: report.warnings,
                    })
                    .map_err(|error| match error {
                        zmanager_core::sevenz_backend::SevenZError::PasswordRequired => CliExtractError::PasswordRequired(error.to_string()),
                        error => CliExtractError::Message(error.to_string()),
                    })
            },
        },
    )
}

fn run_rar_extract_with_policy(
    archive: impl AsRef<std::path::Path>,
    destination: impl AsRef<std::path::Path>,
    policy: zmanager_core::safety::ExtractionPolicy,
    password: Option<&str>,
    global: &GlobalOptions,
) -> ExitCode {
    run_extract_with_policy(
        archive,
        destination,
        policy,
        password,
        global,
        ExtractBackendSpec {
            label: FORMAT_RAR,
            kind: JobKind::RarExtract,
            error_prefix: "rar extract failed: ",
            password_prompt: None,
            progress: false,
            ask: &|archive_path, destination_path, policy, password, resolver| {
                zmanager_core::rar_backend::extract_rar_with_overwrite_resolver_and_password(archive_path, destination_path, policy, password, resolver)
                    .map(CliExtractReport::from)
                    .map_err(|error| CliExtractError::Message(error.to_string()))
            },
            plain: &|archive_path, destination_path, policy, password, _context| {
                zmanager_core::rar_backend::extract_rar_with_password(archive_path, destination_path, policy, password)
                    .map(|report| CliExtractReport {
                        written_entries: report.written_entries,
                        skipped_entries: report.skipped_entries,
                        written_bytes: report.written_bytes,
                        warnings: report.warnings,
                    })
                    .map_err(|error| CliExtractError::Message(error.to_string()))
            },
        },
    )
}

fn run_libarchive_extract_with_policy(
    archive: impl AsRef<std::path::Path>,
    destination: impl AsRef<std::path::Path>,
    policy: zmanager_core::safety::ExtractionPolicy,
    password: Option<&str>,
    global: &GlobalOptions,
) -> ExitCode {
    run_extract_with_policy(
        archive,
        destination,
        policy,
        password,
        global,
        ExtractBackendSpec {
            label: FORMAT_LIBARCHIVE,
            kind: JobKind::ArchiveExtract,
            error_prefix: "libarchive extract failed: ",
            password_prompt: None,
            progress: true,
            ask: &|archive_path, destination_path, policy, password, resolver| {
                zmanager_core::libarchive_backend::extract_archive_with_overwrite_resolver_and_password(
                    archive_path,
                    destination_path,
                    policy,
                    password,
                    resolver,
                )
                .map(CliExtractReport::from)
                .map_err(|error| CliExtractError::Message(error.to_string()))
            },
            plain: &|archive_path, destination_path, policy, password, _context| {
                zmanager_core::libarchive_backend::extract_archive_with_password(archive_path, destination_path, policy, password)
                    .map(CliExtractReport::from)
                    .map_err(|error| CliExtractError::Message(error.to_string()))
            },
        },
    )
}

fn run_apple_dmg_extract_with_policy(
    archive: impl AsRef<std::path::Path>,
    destination: impl AsRef<std::path::Path>,
    policy: zmanager_core::safety::ExtractionPolicy,
    global: &GlobalOptions,
) -> ExitCode {
    run_extract_with_policy(
        archive,
        destination,
        policy,
        None,
        global,
        ExtractBackendSpec {
            label: FORMAT_DMG,
            kind: JobKind::ArchiveExtract,
            error_prefix: "dmg extract failed: ",
            password_prompt: None,
            progress: true,
            ask: &|archive_path, destination_path, policy, _password, resolver| {
                zmanager_core::apple_dmg_backend::extract_dmg_with_overwrite_resolver(archive_path, destination_path, policy, resolver)
                    .map(CliExtractReport::from)
                    .map_err(|error| CliExtractError::Message(error.to_string()))
            },
            plain: &|archive_path, destination_path, policy, _password, context| {
                zmanager_core::apple_dmg_backend::extract_dmg_with_context(archive_path, destination_path, policy, context)
                    .map(CliExtractReport::from)
                    .map_err(|error| CliExtractError::Message(error.to_string()))
            },
        },
    )
}

fn run_apple_pkg_extract_with_policy(
    archive: impl AsRef<std::path::Path>,
    destination: impl AsRef<std::path::Path>,
    policy: zmanager_core::safety::ExtractionPolicy,
    global: &GlobalOptions,
) -> ExitCode {
    run_extract_with_policy(
        archive,
        destination,
        policy,
        None,
        global,
        ExtractBackendSpec {
            label: FORMAT_PKG,
            kind: JobKind::ArchiveExtract,
            error_prefix: "pkg extract failed: ",
            password_prompt: None,
            progress: true,
            ask: &|archive_path, destination_path, policy, _password, resolver| {
                zmanager_core::apple_pkg_backend::extract_pkg_with_overwrite_resolver(archive_path, destination_path, policy, resolver)
                    .map(CliExtractReport::from)
                    .map_err(|error| CliExtractError::Message(error.to_string()))
            },
            plain: &|archive_path, destination_path, policy, _password, context| {
                zmanager_core::apple_pkg_backend::extract_pkg_with_context(archive_path, destination_path, policy, context)
                    .map(CliExtractReport::from)
                    .map_err(|error| CliExtractError::Message(error.to_string()))
            },
        },
    )
}
