use crate::cli::app::{
    ExtractOutcome, ExtractRequest, InteractiveOverwriteResolver, default_extract_destination, default_raw_stream_destination, expand_short_options,
};
use crate::cli::format::FORMAT_APPLE_ARCHIVE;
use crate::cli::format::{BACKEND_DEB_NESTED, FORMAT_DEB, is_deb_archive};
use crate::cli::open::entry_selected;
use crate::cli::options::{GlobalOptions, parse_global_option, parse_usize, read_optional_password_stdin, take_value, validate_recipient_key_open_option};
use crate::cli::usage::{
    EXTRACT_HELP, command_usage_error, print_error_line, print_extract_summary, print_help_stdout, retry_password_required, usage_failure, wants_help,
};
use crate::output::{self, StyleRole};
use std::env;
use std::io::{self, IsTerminal as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use zmanager_core::archive_format::{ArchiveFormatKind, detect_archive_format};
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
    if zmanager_core::raw_stream_backend::detect_raw_stream_format(&request.archive).is_some() && request.password_stdin {
        return usage_failure(global, format_args!("extract failed: raw streams are not encrypted; remove --password-stdin"));
    }
    let destination = request.destination.unwrap_or_else(|| {
        if zmanager_core::raw_stream_backend::detect_raw_stream_format(&request.archive).is_some() {
            default_raw_stream_destination(&request.archive)
        } else {
            default_extract_destination(&request.archive)
        }
    });
    let password = match read_optional_password_stdin(request.password_stdin, global) {
        Ok(password) => password,
        Err(code) => return code,
    };
    run_engine_extract(
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
    )
}

fn run_engine_extract(
    archive: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    policy: zmanager_core::safety::ExtractionPolicy,
    password: Option<&str>,
    recipient_key: Option<&Path>,
    tzap_restore_options: zmanager_core::tzap_backend::TzapRestoreOptions,
    global: &GlobalOptions,
) -> ExitCode {
    let archive_path = archive.as_ref().to_path_buf();
    let destination_path = destination.as_ref().to_path_buf();
    let format_label = match detect_archive_format(&archive_path) {
        ArchiveFormatKind::Zip | ArchiveFormatKind::SplitZip => "zip",
        ArchiveFormatKind::SevenZ => "7z",
        ArchiveFormatKind::TarZst => "tar.zst",
        ArchiveFormatKind::TarGz => "tgz",
        ArchiveFormatKind::Tzap => "tzap",
        ArchiveFormatKind::Rar => "rar",
        ArchiveFormatKind::RawStream => "raw-stream",
        ArchiveFormatKind::AppleArchive => "aar",
        ArchiveFormatKind::Dmg => "dmg",
        ArchiveFormatKind::Pkg => "pkg",
        ArchiveFormatKind::Msi => "msi",
        ArchiveFormatKind::Vhd => "vhd",
        ArchiveFormatKind::Vmdk => "vmdk",
        ArchiveFormatKind::Udf => "udf",
        _ => "archive",
    };
    let mut progress = crate::cli::app::ProgressReporter::from_global(Some(global));
    let progress_kind = match format_label {
        "zip" => zmanager_core::jobs::JobKind::ZipExtract,
        "7z" => zmanager_core::jobs::JobKind::SevenZExtract,
        "tar.zst" => zmanager_core::jobs::JobKind::TarZstdExtract,
        "tzap" => zmanager_core::jobs::JobKind::TzapExtract,
        "rar" => zmanager_core::jobs::JobKind::RarExtract,
        "aar" => zmanager_core::jobs::JobKind::AppleArchiveExtract,
        "raw-stream" => zmanager_core::jobs::JobKind::RawStreamExtract,
        _ => zmanager_core::jobs::JobKind::ArchiveExtract,
    };
    progress.emit(zmanager_core::jobs::JobEvent::Started { kind: progress_kind, total_bytes: None });
    let mut options = zmanager_core::engine::ExtractOptions {
        destination: destination_path.clone(),
        policy: policy.clone(),
        recipient_key: recipient_key.map(Path::to_path_buf),
        tzap_password: password.map(str::to_owned),
        tzap_restore_options: Some(tzap_restore_options),
        ..Default::default()
    };
    let result = if matches!(policy.overwrite, zmanager_core::safety::OverwritePolicy::Ask) {
        let stdin = io::stdin();
        let stderr = io::stderr();
        let mut resolver = InteractiveOverwriteResolver::new(stdin.lock(), stderr.lock());
        options.overwrite_resolver = Some(&mut resolver);
        zmanager_core::engine::extract_with_default_engine(
            zmanager_core::engine::ArchiveSource::from_path_autodetect(&archive_path),
            zmanager_core::engine::OpenOptions { password: password.map(str::to_owned), recipient_key: recipient_key.map(Path::to_path_buf) },
            &mut options,
        )
    } else {
        zmanager_core::engine::extract_with_default_engine(
            zmanager_core::engine::ArchiveSource::from_path_autodetect(&archive_path),
            zmanager_core::engine::OpenOptions { password: password.map(str::to_owned), recipient_key: recipient_key.map(Path::to_path_buf) },
            &mut options,
        )
    };
    match result {
        Ok(report) => {
            progress.emit(zmanager_core::jobs::JobEvent::Completed {
                entries: usize::try_from(report.written_entries).unwrap_or(usize::MAX),
                bytes: report.written_bytes,
            });
            let outcome = ExtractOutcome {
                label: format_label,
                format: format_label,
                backend: format_label,
                written_entries: usize::try_from(report.written_entries).unwrap_or(usize::MAX),
                skipped_entries: usize::try_from(report.skipped_entries).unwrap_or(usize::MAX),
                written_bytes: report.written_bytes,
                warnings: report.warnings,
            };
            print_extract_summary(&archive_path, &destination_path, &outcome, global);
            ExitCode::SUCCESS
        }
        Err(error) if error.kind == zmanager_core::engine::ErrorKind::PasswordRequired && password.is_none() => retry_password_required(
            global,
            "extract",
            Some("Archive password: "),
            |message| eprintln!("{message}"),
            |password| {
                run_engine_extract(&archive_path, &destination_path, policy, Some(password.expose_secret()), recipient_key, tzap_restore_options, global)
            },
        ),
        Err(error) => {
            progress.emit(zmanager_core::jobs::JobEvent::Failed { message: error.message.clone() });
            print_error_line(global, format_args!("extract failed: {}", error.message));
            ExitCode::FAILURE
        }
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
            ArchiveFormatKind::Zip | ArchiveFormatKind::SplitZip => copy_zip_archive_to_stdout(request, password.as_deref(), global),
            ArchiveFormatKind::SevenZ => copy_7z_archive_to_stdout(request, password.as_deref(), global),
            ArchiveFormatKind::TarZst => copy_tar_zst_archive_to_stdout(request, global),
            ArchiveFormatKind::Tzap => copy_tzap_archive_to_stdout(request, password.as_deref(), global),
            ArchiveFormatKind::AppleArchive => extract_apple_archive_stdout(&request.archive, &request.include, &request.exclude, password.as_deref(), global),
            ArchiveFormatKind::Dmg
            | ArchiveFormatKind::Pkg
            | ArchiveFormatKind::Msi
            | ArchiveFormatKind::Vhd
            | ArchiveFormatKind::Vmdk
            | ArchiveFormatKind::Udf => {
                print_error_line(
                    global,
                    format_args!("extract to stdout failed: DMG, PKG, MSI, VHD, VMDK, and UDF formats do not currently support extracting to stdout"),
                );
                ExitCode::FAILURE
            }
            // TAR.GZ stdout and the remaining formats are still read through
            // libarchive until native stream-to-stdout adapters are added.
            ArchiveFormatKind::TarGz
            | ArchiveFormatKind::Deb
            | ArchiveFormatKind::Rar
            | ArchiveFormatKind::Tar
            | ArchiveFormatKind::TarBz2
            | ArchiveFormatKind::TarXz
            | ArchiveFormatKind::TarLzma
            | ArchiveFormatKind::TarLz
            | ArchiveFormatKind::TarLzo
            | ArchiveFormatKind::TarCompress
            | ArchiveFormatKind::TarLz4
            | ArchiveFormatKind::TarLrz
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
