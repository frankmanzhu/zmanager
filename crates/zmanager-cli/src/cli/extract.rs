use crate::cli::app::{
    ExtractOutcome, ExtractRequest, InteractiveOverwriteResolver, ProgressReporter, default_extract_destination,
    default_raw_stream_destination, expand_short_options,
};
#[cfg(any(target_os = "macos", target_os = "ios"))]
use crate::cli::format::FORMAT_APPLE_ARCHIVE;
use crate::cli::format::{
    BACKEND_DEB_NESTED, FORMAT_DEB, FORMAT_LIBARCHIVE, FORMAT_RAR, FORMAT_SEVEN_Z, FORMAT_TAR_ZST, FORMAT_TZAP,
    FORMAT_ZIP, is_7z_archive, is_apple_archive, is_deb_archive, is_rar_archive, is_split_zip_archive_path,
    is_tar_zst_archive, is_tzap_archive, is_zip_family_archive,
};
use crate::cli::open::entry_selected;
use crate::cli::options::{
    GlobalOptions, parse_global_option, parse_usize, read_optional_password_stdin, take_value,
    validate_recipient_key_open_option,
};
use crate::cli::usage::{
    EXTRACT_HELP, command_usage_error, print_error_line, print_extract_summary, print_help_stdout,
    print_raw_stream_extract_summary, prompt_password, usage_failure, wants_help,
};
use crate::output::{self, StyleRole};
use std::env;
use std::io::{self, IsTerminal as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
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

pub(crate) fn parse_extract_request(
    args: &[String],
    global: &mut GlobalOptions,
    request: &mut ExtractRequest,
) -> Result<(), String> {
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
    if let Some(code) = validate_recipient_key_open_option(
        "extract",
        &request.archive,
        request.password_stdin,
        request.recipient_key.as_ref(),
        global,
    ) {
        return code;
    }
    if request.to_stdout {
        return run_extract_to_stdout(request, global);
    }
    let policy = match extraction_policy(&request) {
        Ok(policy) => policy,
        Err(error) => return command_usage_error("extract", &error, global),
    };
    if request.extract_nested {
        if request.password_stdin {
            return usage_failure(
                global,
                format_args!("extract failed: nested package extraction does not use passwords"),
            );
        }
        if !is_deb_archive(&request.archive) {
            return usage_failure(
                global,
                format_args!("extract failed: --extract-nested is currently supported only for .deb packages"),
            );
        }
        let destination = request.destination.unwrap_or_else(|| default_extract_destination(&request.archive));
        return run_deb_nested_extract(&request.archive, &destination, policy, global);
    }
    if let Some(format) = zmanager_core::raw_stream_backend::detect_raw_stream_format(&request.archive) {
        if request.password_stdin {
            return usage_failure(
                global,
                format_args!("extract failed: raw streams are not encrypted; remove --password-stdin"),
            );
        }
        let destination = request.destination.unwrap_or_else(|| default_raw_stream_destination(&request.archive));
        return run_raw_stream_extract(&request.archive, format, &destination, policy, global);
    }
    let destination = request.destination.unwrap_or_else(|| default_extract_destination(&request.archive));
    if is_zip_family_archive(&request.archive) && !is_split_zip_archive_path(&request.archive) {
        let password = match read_optional_password_stdin(request.password_stdin, "ZIP", global) {
            Ok(password) => password,
            Err(code) => return code,
        };
        run_zip_extract_with_policy(
            request.archive,
            destination,
            password.as_deref(),
            policy,
            global.no_password_prompt,
            Some(global),
        )
    } else if is_7z_archive(&request.archive) {
        let password = match read_optional_password_stdin(request.password_stdin, "7z", global) {
            Ok(password) => password,
            Err(code) => return code,
        };
        run_7z_extract_with_policy(
            request.archive,
            destination,
            password.as_deref(),
            policy,
            global.no_password_prompt,
            Some(global),
        )
    } else if is_rar_archive(&request.archive) && request.password_stdin {
        let password = match read_optional_password_stdin(request.password_stdin, "RAR", global) {
            Ok(password) => password,
            Err(code) => return code,
        };
        run_rar_extract_with_policy(request.archive, destination, policy, password.as_deref(), Some(global))
    } else if is_tar_zst_archive(&request.archive) {
        run_tar_zst_extract_with_policy(request.archive, destination, policy, Some(global))
    } else if is_apple_archive(&request.archive) {
        let password = match read_optional_password_stdin(request.password_stdin, "AAR", global) {
            Ok(password) => password,
            Err(code) => return code,
        };
        run_apple_archive_extract_with_policy(request.archive, destination, policy, password.as_deref(), Some(global))
    } else if is_tzap_archive(&request.archive) {
        let password = match read_optional_password_stdin(request.password_stdin, "TZAP", global) {
            Ok(password) => password,
            Err(code) => return code,
        };
        run_tzap_extract_with_policy(
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
            Some(global),
        )
    } else {
        let password = match read_optional_password_stdin(request.password_stdin, "archive", global) {
            Ok(password) => password,
            Err(code) => return code,
        };
        run_libarchive_extract_with_policy(request.archive, destination, policy, password.as_deref(), Some(global))
    }
}
fn run_deb_nested_extract(
    archive: &str,
    destination: &Path,
    policy: zmanager_core::safety::ExtractionPolicy,
    global: &GlobalOptions,
) -> ExitCode {
    let result = if matches!(policy.overwrite, OverwritePolicy::Ask) {
        let stdin = io::stdin();
        let stderr = io::stderr();
        let mut overwrite_resolver = InteractiveOverwriteResolver::new(stdin.lock(), stderr.lock());
        zmanager_core::deb_backend::extract_deb_nested_with_overwrite_resolver(
            archive,
            destination,
            policy,
            &mut overwrite_resolver,
        )
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
            print_extract_summary(Path::new(archive), destination, &outcome, Some(global));
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
        zmanager_core::raw_stream_backend::extract_raw_stream_with_overwrite_resolver(
            archive,
            format,
            destination,
            policy,
            &mut overwrite_resolver,
        )
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
fn run_extract_to_stdout(request: ExtractRequest, global: &GlobalOptions) -> ExitCode {
    if request.extract_nested {
        print_error_line(global, format_args!("extract failed: --extract-nested cannot be combined with --to-stdout"));
        return ExitCode::from(2);
    }
    if request.destination.is_some() {
        print_error_line(
            global,
            format_args!("extract failed: --to-stdout cannot be combined with an extraction directory"),
        );
        return ExitCode::from(2);
    }
    if request.strip_components > 0 {
        print_error_line(global, format_args!("extract failed: --strip-components is not meaningful with --to-stdout"));
        return ExitCode::from(2);
    }

    let mut stdout = io::stdout().lock();
    if is_zip_family_archive(&request.archive) && !is_split_zip_archive_path(&request.archive) {
        let password = match read_optional_password_stdin(request.password_stdin, "ZIP", global) {
            Ok(password) => password,
            Err(code) => return code,
        };
        match zmanager_core::zip_backend::copy_zip_files_to_writer(
            &request.archive,
            password.as_deref(),
            |name| entry_selected(name, &request.include, &request.exclude),
            &mut stdout,
        ) {
            Ok(report) => {
                if global.verbose > 0 && !global.quiet {
                    output::stderr_line(
                        global.color,
                        format_args!(
                            "{} to stdout ok: {} entries, {} skipped, {} bytes",
                            output::styled(StyleRole::Success, format_args!("extract")),
                            report.written_entries,
                            report.skipped_entries,
                            report.written_bytes
                        ),
                    );
                }
                ExitCode::SUCCESS
            }
            Err(zmanager_core::zip_backend::ZipBackendError::PasswordRequired) if password.is_none() => {
                if global.no_password_prompt {
                    print_error_line(
                        global,
                        format_args!("extract to stdout failed: password required and prompts are disabled"),
                    );
                    return ExitCode::from(2);
                }
                let password = match prompt_password("ZIP password: ") {
                    Ok(password) => password,
                    Err(code) => return code,
                };
                let retry = ExtractRequest { password_stdin: false, ..request };
                match zmanager_core::zip_backend::copy_zip_files_to_writer(
                    &retry.archive,
                    Some(password.expose_secret()),
                    |name| entry_selected(name, &retry.include, &retry.exclude),
                    &mut stdout,
                ) {
                    Ok(_) => ExitCode::SUCCESS,
                    Err(error) => {
                        print_error_line(global, format_args!("extract to stdout failed: {error}"));
                        ExitCode::FAILURE
                    }
                }
            }
            Err(error) => {
                print_error_line(global, format_args!("extract to stdout failed: {error}"));
                ExitCode::FAILURE
            }
        }
    } else if is_tar_zst_archive(&request.archive) {
        match zmanager_core::tar_zst_backend::copy_tar_zst_files_to_writer(
            &request.archive,
            |name| entry_selected(name, &request.include, &request.exclude),
            &mut stdout,
        ) {
            Ok(report) => {
                if global.verbose > 0 && !global.quiet {
                    output::stderr_line(
                        global.color,
                        format_args!(
                            "{} to stdout ok: {} entries, {} skipped, {} bytes",
                            output::styled(StyleRole::Success, format_args!("extract")),
                            report.written_entries,
                            report.skipped_entries,
                            report.written_bytes
                        ),
                    );
                }
                ExitCode::SUCCESS
            }
            Err(error) => {
                print_error_line(global, format_args!("extract to stdout failed: {error}"));
                ExitCode::FAILURE
            }
        }
    } else if is_7z_archive(&request.archive) {
        let password = match read_optional_password_stdin(request.password_stdin, "7z", global) {
            Ok(password) => password,
            Err(code) => return code,
        };
        match zmanager_core::sevenz_backend::copy_7z_files_to_writer(
            &request.archive,
            password.as_deref(),
            |name| entry_selected(name, &request.include, &request.exclude),
            &mut stdout,
        ) {
            Ok(report) => {
                if global.verbose > 0 && !global.quiet {
                    output::stderr_line(
                        global.color,
                        format_args!(
                            "{} to stdout ok: {} entries, {} skipped, {} bytes",
                            output::styled(StyleRole::Success, format_args!("extract")),
                            report.written_entries,
                            report.skipped_entries,
                            report.written_bytes
                        ),
                    );
                }
                ExitCode::SUCCESS
            }
            Err(zmanager_core::sevenz_backend::SevenZError::PasswordRequired) if password.is_none() => {
                if global.no_password_prompt {
                    print_error_line(
                        global,
                        format_args!("extract to stdout failed: password required and prompts are disabled"),
                    );
                    return ExitCode::from(2);
                }
                let password = match prompt_password("7z password: ") {
                    Ok(password) => password,
                    Err(code) => return code,
                };
                let retry = ExtractRequest { password_stdin: false, ..request };
                match zmanager_core::sevenz_backend::copy_7z_files_to_writer(
                    &retry.archive,
                    Some(password.expose_secret()),
                    |name| entry_selected(name, &retry.include, &retry.exclude),
                    &mut stdout,
                ) {
                    Ok(_) => ExitCode::SUCCESS,
                    Err(error) => {
                        print_error_line(global, format_args!("extract to stdout failed: {error}"));
                        ExitCode::FAILURE
                    }
                }
            }
            Err(error) => {
                print_error_line(global, format_args!("extract to stdout failed: {error}"));
                ExitCode::FAILURE
            }
        }
    } else if is_tzap_archive(&request.archive) {
        let password = match read_optional_password_stdin(request.password_stdin, "TZAP", global) {
            Ok(password) => password,
            Err(code) => return code,
        };
        let result = if let Some(recipient_key) = request.recipient_key.as_deref() {
            zmanager_core::tzap_backend::copy_tzap_files_to_writer_with_recipient_key(
                &request.archive,
                recipient_key,
                |name| entry_selected(name, &request.include, &request.exclude),
                &mut stdout,
            )
        } else {
            zmanager_core::tzap_backend::copy_tzap_files_to_writer_with_optional_password(
                &request.archive,
                password.as_deref(),
                |name| entry_selected(name, &request.include, &request.exclude),
                &mut stdout,
            )
        };
        match result {
            Ok(report) => {
                if global.verbose > 0 && !global.quiet {
                    output::stderr_line(
                        global.color,
                        format_args!(
                            "{} to stdout ok: {} entries, {} skipped, {} bytes",
                            output::styled(StyleRole::Success, format_args!("extract")),
                            report.written_entries,
                            report.skipped_entries,
                            report.written_bytes
                        ),
                    );
                }
                ExitCode::SUCCESS
            }
            Err(error) => {
                print_error_line(global, format_args!("extract to stdout failed: {error}"));
                ExitCode::FAILURE
            }
        }
    } else if is_apple_archive(&request.archive) {
        let password = match read_optional_password_stdin(request.password_stdin, "AAR", global) {
            Ok(password) => password,
            Err(code) => return code,
        };
        extract_apple_archive_stdout(
            &request.archive,
            &request.include,
            &request.exclude,
            password.as_deref(),
            &mut stdout,
            global,
        )
    } else if let Some(format) = zmanager_core::raw_stream_backend::detect_raw_stream_format(&request.archive) {
        if request.password_stdin {
            print_error_line(
                global,
                format_args!("extract to stdout failed: raw streams are not encrypted; remove --password-stdin"),
            );
            return ExitCode::from(2);
        }
        let Some(output_name) = zmanager_core::raw_stream_backend::output_name_for_raw_stream(&request.archive, format)
        else {
            print_error_line(global, format_args!("extract to stdout failed: could not derive raw stream output name"));
            return ExitCode::FAILURE;
        };
        if !entry_selected(&output_name, &request.include, &request.exclude) {
            if global.verbose > 0 && !global.quiet {
                output::stderr_line(
                    global.color,
                    format_args!(
                        "{} to stdout ok: 0 entries, 1 skipped, 0 bytes",
                        output::styled(StyleRole::Success, format_args!("extract"))
                    ),
                );
            }
            return ExitCode::SUCCESS;
        }
        match zmanager_core::raw_stream_backend::copy_raw_stream_to_writer(&request.archive, format, &mut stdout) {
            Ok(written_bytes) => {
                if global.verbose > 0 && !global.quiet {
                    output::stderr_line(
                        global.color,
                        format_args!(
                            "{} to stdout ok: 1 entry, 0 skipped, {written_bytes} bytes",
                            output::styled(StyleRole::Success, format_args!("extract"))
                        ),
                    );
                }
                ExitCode::SUCCESS
            }
            Err(error) => {
                print_error_line(global, format_args!("extract to stdout failed: {error}"));
                ExitCode::FAILURE
            }
        }
    } else {
        let password = match read_optional_password_stdin(request.password_stdin, "archive", global) {
            Ok(password) => password,
            Err(code) => return code,
        };
        match zmanager_core::libarchive_backend::copy_archive_files_to_writer(
            &request.archive,
            password.as_deref(),
            |name| entry_selected(name, &request.include, &request.exclude),
            &mut stdout,
        ) {
            Ok(report) => {
                if global.verbose > 0 && !global.quiet {
                    output::stderr_line(
                        global.color,
                        format_args!(
                            "{} to stdout ok: {} entries, {} skipped, {} bytes",
                            output::styled(StyleRole::Success, format_args!("extract")),
                            report.written_entries,
                            report.skipped_entries,
                            report.written_bytes
                        ),
                    );
                }
                ExitCode::SUCCESS
            }
            Err(error) => {
                print_error_line(global, format_args!("extract to stdout failed: {error}"));
                ExitCode::FAILURE
            }
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
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn extract_apple_archive_stdout(
    archive: &str,
    include: &[String],
    exclude: &[String],
    password: Option<&str>,
    stdout: &mut impl io::Write,
    global: &GlobalOptions,
) -> ExitCode {
    match zmanager_core::apple_archive_backend::copy_apple_archive_files_to_writer(
        archive,
        |name| entry_selected(name, include, exclude),
        stdout,
        password,
    ) {
        Ok(report) => {
            if global.verbose > 0 && !global.quiet {
                output::stderr_line(
                    global.color,
                    format_args!(
                        "{} to stdout ok: {} entries, {} skipped, {} bytes",
                        FORMAT_APPLE_ARCHIVE, report.written_entries, report.skipped_entries, report.written_bytes
                    ),
                );
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            print_error_line(global, format_args!("extract to stdout failed: {error}"));
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
fn extract_apple_archive_stdout(
    _archive: &str,
    _include: &[String],
    _exclude: &[String],
    _password: Option<&str>,
    _stdout: &mut impl io::Write,
    _global: &GlobalOptions,
) -> ExitCode {
    unreachable!()
}
fn run_zip_extract_with_policy(
    archive: impl AsRef<std::path::Path>,
    destination: impl AsRef<std::path::Path>,
    password: Option<&str>,
    policy: zmanager_core::safety::ExtractionPolicy,
    no_password_prompt: bool,
    global: Option<&GlobalOptions>,
) -> ExitCode {
    let archive_path = archive.as_ref().to_path_buf();
    let destination_path = destination.as_ref().to_path_buf();
    let mut progress = ProgressReporter::from_global(global);
    progress.emit(JobEvent::Started { kind: JobKind::ZipExtract, total_bytes: None });
    let token = CancellationToken::new();
    let result = if matches!(policy.overwrite, OverwritePolicy::Ask) {
        let stdin = io::stdin();
        let stderr = io::stderr();
        let mut overwrite_resolver = InteractiveOverwriteResolver::new(stdin.lock(), stderr.lock());
        zmanager_core::zip_backend::extract_zip_with_overwrite_resolver_and_password(
            &archive_path,
            &destination_path,
            policy.clone(),
            password,
            &mut overwrite_resolver,
        )
    } else {
        let mut sink = |event| progress.emit(event);
        let mut context = JobContext::new(&token, &mut sink);
        let result = zmanager_core::zip_backend::extract_zip_with_context_and_password(
            &archive_path,
            &destination_path,
            policy.clone(),
            password,
            &mut context,
        );
        context.flush_progress();
        result
    };

    match result {
        Ok(report) => {
            progress.emit(JobEvent::Completed { entries: report.written_entries, bytes: report.written_bytes });
            let outcome = ExtractOutcome {
                label: FORMAT_ZIP,
                format: FORMAT_ZIP,
                backend: FORMAT_ZIP,
                written_entries: report.written_entries,
                skipped_entries: report.skipped_entries,
                written_bytes: report.written_bytes,
                warnings: report.warnings,
            };
            print_extract_summary(&archive_path, &destination_path, &outcome, global);
            ExitCode::SUCCESS
        }
        Err(zmanager_core::zip_backend::ZipBackendError::PasswordRequired) if password.is_none() => {
            if no_password_prompt {
                let message = "zip extract failed: password required and prompts are disabled";
                progress.emit(JobEvent::Failed { message: message.to_owned() });
                eprintln!("{message}");
                return ExitCode::from(2);
            }
            let password = match prompt_password("ZIP password: ") {
                Ok(password) => password,
                Err(code) => return code,
            };
            run_zip_extract_with_policy(
                archive,
                destination,
                Some(password.expose_secret()),
                policy,
                no_password_prompt,
                global,
            )
        }
        Err(error) => {
            progress.emit(JobEvent::Failed { message: error.to_string() });
            eprintln!("zip extract failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_tar_zst_extract_with_policy(
    archive: impl AsRef<std::path::Path>,
    destination: impl AsRef<std::path::Path>,
    policy: zmanager_core::safety::ExtractionPolicy,
    global: Option<&GlobalOptions>,
) -> ExitCode {
    let archive_path = archive.as_ref().to_path_buf();
    let destination_path = destination.as_ref().to_path_buf();
    let mut progress = ProgressReporter::from_global(global);
    progress.emit(JobEvent::Started { kind: JobKind::TarZstdExtract, total_bytes: None });
    let token = CancellationToken::new();
    let result = if matches!(policy.overwrite, OverwritePolicy::Ask) {
        let stdin = io::stdin();
        let stderr = io::stderr();
        let mut overwrite_resolver = InteractiveOverwriteResolver::new(stdin.lock(), stderr.lock());
        zmanager_core::tar_zst_backend::extract_tar_zst_with_overwrite_resolver(
            &archive_path,
            &destination_path,
            policy,
            &mut overwrite_resolver,
        )
    } else {
        let mut sink = |event| progress.emit(event);
        let mut context = JobContext::new(&token, &mut sink);
        let result = zmanager_core::tar_zst_backend::extract_tar_zst_with_context(
            &archive_path,
            &destination_path,
            policy,
            &mut context,
        );
        context.flush_progress();
        result
    };

    match result {
        Ok(report) => {
            progress.emit(JobEvent::Completed { entries: report.written_entries, bytes: report.written_bytes });
            let outcome = ExtractOutcome {
                label: FORMAT_TAR_ZST,
                format: FORMAT_TAR_ZST,
                backend: FORMAT_TAR_ZST,
                written_entries: report.written_entries,
                skipped_entries: report.skipped_entries,
                written_bytes: report.written_bytes,
                warnings: report.warnings,
            };
            print_extract_summary(&archive_path, &destination_path, &outcome, global);
            ExitCode::SUCCESS
        }
        Err(error) => {
            progress.emit(JobEvent::Failed { message: error.to_string() });
            eprintln!("tar.zst extract failed: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn run_apple_archive_extract_with_policy(
    archive: impl AsRef<std::path::Path>,
    destination: impl AsRef<std::path::Path>,
    policy: zmanager_core::safety::ExtractionPolicy,
    password: Option<&str>,
    global: Option<&GlobalOptions>,
) -> ExitCode {
    let archive_path = archive.as_ref().to_path_buf();
    let destination_path = destination.as_ref().to_path_buf();
    let mut progress = ProgressReporter::from_global(global);
    progress.emit(JobEvent::Started { kind: JobKind::AppleArchiveExtract, total_bytes: None });
    let token = CancellationToken::new();
    let result = if matches!(policy.overwrite, OverwritePolicy::Ask) {
        let stdin = io::stdin();
        let stderr = io::stderr();
        let mut overwrite_resolver = InteractiveOverwriteResolver::new(stdin.lock(), stderr.lock());
        zmanager_core::apple_archive_backend::extract_apple_archive_with_overwrite_resolver(
            &archive_path,
            &destination_path,
            policy,
            &mut overwrite_resolver,
            password,
        )
    } else {
        let mut sink = |event| progress.emit(event);
        let mut context = JobContext::new(&token, &mut sink);
        let result = zmanager_core::apple_archive_backend::extract_apple_archive_with_context(
            &archive_path,
            &destination_path,
            policy,
            password,
            &mut context,
        );
        context.flush_progress();
        result
    };

    match result {
        Ok(report) => {
            progress.emit(JobEvent::Completed { entries: report.written_entries, bytes: report.written_bytes });
            let outcome = ExtractOutcome {
                label: FORMAT_APPLE_ARCHIVE,
                format: FORMAT_APPLE_ARCHIVE,
                backend: FORMAT_APPLE_ARCHIVE,
                written_entries: report.written_entries,
                skipped_entries: report.skipped_entries,
                written_bytes: report.written_bytes,
                warnings: report.warnings,
            };
            print_extract_summary(&archive_path, &destination_path, &outcome, global);
            ExitCode::SUCCESS
        }
        Err(error) => {
            progress.emit(JobEvent::Failed { message: error.to_string() });
            eprintln!("aar extract failed: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
fn run_apple_archive_extract_with_policy(
    _archive: impl AsRef<std::path::Path>,
    _destination: impl AsRef<std::path::Path>,
    _policy: zmanager_core::safety::ExtractionPolicy,
    _password: Option<&str>,
    _global: Option<&GlobalOptions>,
) -> ExitCode {
    unreachable!()
}

fn run_tzap_extract_with_policy(
    archive: impl AsRef<std::path::Path>,
    destination: impl AsRef<std::path::Path>,
    policy: zmanager_core::safety::ExtractionPolicy,
    password: Option<&str>,
    recipient_key: Option<&Path>,
    restore_options: zmanager_core::tzap_backend::TzapRestoreOptions,
    global: Option<&GlobalOptions>,
) -> ExitCode {
    let archive_path = archive.as_ref().to_path_buf();
    let destination_path = destination.as_ref().to_path_buf();
    let mut progress = ProgressReporter::from_global(global);
    progress.emit(JobEvent::Started { kind: JobKind::TzapExtract, total_bytes: None });
    let result = if matches!(policy.overwrite, OverwritePolicy::Ask) {
        let stdin = io::stdin();
        let stderr = io::stderr();
        let mut overwrite_resolver = InteractiveOverwriteResolver::new(stdin.lock(), stderr.lock());
        if let Some(recipient_key) = recipient_key {
            zmanager_core::tzap_backend::extract_tzap_with_overwrite_resolver_and_recipient_key_and_restore_options(
                &archive_path,
                &destination_path,
                policy,
                recipient_key,
                restore_options,
                &mut overwrite_resolver,
            )
        } else {
            zmanager_core::tzap_backend::extract_tzap_with_overwrite_resolver_and_optional_password_and_restore_options(
                &archive_path,
                &destination_path,
                policy,
                password,
                restore_options,
                &mut overwrite_resolver,
            )
        }
    } else if let Some(recipient_key) = recipient_key {
        zmanager_core::tzap_backend::extract_tzap_with_recipient_key_and_restore_options(
            &archive_path,
            &destination_path,
            policy,
            recipient_key,
            restore_options,
        )
    } else {
        zmanager_core::tzap_backend::extract_tzap_with_optional_password_and_restore_options(
            &archive_path,
            &destination_path,
            policy,
            password,
            restore_options,
        )
    };

    match result {
        Ok(report) => {
            progress.emit(JobEvent::Completed { entries: report.written_entries, bytes: report.written_bytes });
            let outcome = ExtractOutcome {
                label: FORMAT_TZAP,
                format: FORMAT_TZAP,
                backend: FORMAT_TZAP,
                written_entries: report.written_entries,
                skipped_entries: report.skipped_entries,
                written_bytes: report.written_bytes,
                warnings: report.warnings,
            };
            print_extract_summary(&archive_path, &destination_path, &outcome, global);
            ExitCode::SUCCESS
        }
        Err(error) => {
            progress.emit(JobEvent::Failed { message: error.to_string() });
            eprintln!("tzap extract failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_7z_extract_with_policy(
    archive: impl AsRef<std::path::Path>,
    destination: impl AsRef<std::path::Path>,
    password: Option<&str>,
    policy: zmanager_core::safety::ExtractionPolicy,
    no_password_prompt: bool,
    global: Option<&GlobalOptions>,
) -> ExitCode {
    let archive_path = archive.as_ref().to_path_buf();
    let destination_path = destination.as_ref().to_path_buf();
    let mut progress = ProgressReporter::from_global(global);
    progress.emit(JobEvent::Started { kind: JobKind::SevenZExtract, total_bytes: None });
    let result = if matches!(policy.overwrite, OverwritePolicy::Ask) {
        let stdin = io::stdin();
        let stderr = io::stderr();
        let mut overwrite_resolver = InteractiveOverwriteResolver::new(stdin.lock(), stderr.lock());
        zmanager_core::sevenz_backend::extract_7z_with_overwrite_resolver(
            &archive_path,
            &destination_path,
            password,
            policy.clone(),
            &mut overwrite_resolver,
        )
    } else {
        zmanager_core::sevenz_backend::extract_7z(&archive_path, &destination_path, password, policy.clone())
    };
    match result {
        Ok(report) => {
            progress.emit(JobEvent::Completed { entries: report.written_entries, bytes: report.written_bytes });
            let outcome = ExtractOutcome {
                label: FORMAT_SEVEN_Z,
                format: FORMAT_SEVEN_Z,
                backend: FORMAT_SEVEN_Z,
                written_entries: report.written_entries,
                skipped_entries: report.skipped_entries,
                written_bytes: report.written_bytes,
                warnings: report.warnings,
            };
            print_extract_summary(&archive_path, &destination_path, &outcome, global);
            ExitCode::SUCCESS
        }
        Err(zmanager_core::sevenz_backend::SevenZError::PasswordRequired) if password.is_none() => {
            if no_password_prompt {
                let message = "7z extract failed: password required and prompts are disabled";
                progress.emit(JobEvent::Failed { message: message.to_owned() });
                eprintln!("{message}");
                return ExitCode::from(2);
            }
            let password = match prompt_password("7z password: ") {
                Ok(password) => password,
                Err(code) => return code,
            };
            run_7z_extract_with_policy(
                archive,
                destination,
                Some(password.expose_secret()),
                policy,
                no_password_prompt,
                global,
            )
        }
        Err(error) => {
            progress.emit(JobEvent::Failed { message: error.to_string() });
            eprintln!("7z extract failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_rar_extract_with_policy(
    archive: impl AsRef<std::path::Path>,
    destination: impl AsRef<std::path::Path>,
    policy: zmanager_core::safety::ExtractionPolicy,
    password: Option<&str>,
    global: Option<&GlobalOptions>,
) -> ExitCode {
    let archive_path = archive.as_ref().to_path_buf();
    let destination_path = destination.as_ref().to_path_buf();
    let result = if matches!(policy.overwrite, OverwritePolicy::Ask) {
        let stdin = io::stdin();
        let stderr = io::stderr();
        let mut overwrite_resolver = InteractiveOverwriteResolver::new(stdin.lock(), stderr.lock());
        zmanager_core::rar_backend::extract_rar_with_overwrite_resolver_and_password(
            &archive_path,
            &destination_path,
            policy,
            password,
            &mut overwrite_resolver,
        )
    } else {
        zmanager_core::rar_backend::extract_rar_with_password(&archive_path, &destination_path, policy, password)
    };
    match result {
        Ok(report) => {
            let outcome = ExtractOutcome {
                label: FORMAT_RAR,
                format: FORMAT_RAR,
                backend: FORMAT_RAR,
                written_entries: report.written_entries,
                skipped_entries: report.skipped_entries,
                written_bytes: report.written_bytes,
                warnings: report.warnings,
            };
            print_extract_summary(&archive_path, &destination_path, &outcome, global);
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("rar extract failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_libarchive_extract_with_policy(
    archive: impl AsRef<std::path::Path>,
    destination: impl AsRef<std::path::Path>,
    policy: zmanager_core::safety::ExtractionPolicy,
    password: Option<&str>,
    global: Option<&GlobalOptions>,
) -> ExitCode {
    let archive_path = archive.as_ref().to_path_buf();
    let destination_path = destination.as_ref().to_path_buf();
    let mut progress = ProgressReporter::from_global(global);
    progress.emit(JobEvent::Started { kind: JobKind::ArchiveExtract, total_bytes: None });
    let result = if matches!(policy.overwrite, OverwritePolicy::Ask) {
        let stdin = io::stdin();
        let stderr = io::stderr();
        let mut overwrite_resolver = InteractiveOverwriteResolver::new(stdin.lock(), stderr.lock());
        zmanager_core::libarchive_backend::extract_archive_with_overwrite_resolver_and_password(
            &archive_path,
            &destination_path,
            policy,
            password,
            &mut overwrite_resolver,
        )
    } else {
        zmanager_core::libarchive_backend::extract_archive_with_password(
            &archive_path,
            &destination_path,
            policy,
            password,
        )
    };
    match result {
        Ok(report) => {
            progress.emit(JobEvent::Completed { entries: report.written_entries, bytes: report.written_bytes });
            let outcome = ExtractOutcome {
                label: FORMAT_LIBARCHIVE,
                format: FORMAT_LIBARCHIVE,
                backend: FORMAT_LIBARCHIVE,
                written_entries: report.written_entries,
                skipped_entries: report.skipped_entries,
                written_bytes: report.written_bytes,
                warnings: report.warnings,
            };
            print_extract_summary(&archive_path, &destination_path, &outcome, global);
            ExitCode::SUCCESS
        }
        Err(error) => {
            progress.emit(JobEvent::Failed { message: error.to_string() });
            eprintln!("libarchive extract failed: {error}");
            ExitCode::FAILURE
        }
    }
}
