use crate::cli::app::{
    ArchiveFormat, CreateOutcome, CreateRequest, ProgressReporter, TestRequest, create_progress_kind,
    create_test_archive_path, expand_short_options, publish_archive, temp_archive_path,
};
#[cfg(any(target_os = "macos", target_os = "ios"))]
use crate::cli::format::FORMAT_APPLE_ARCHIVE;
use crate::cli::format::{
    FORMAT_SEVEN_Z, FORMAT_TAR_ZST, FORMAT_TGZ, FORMAT_TZAP, FORMAT_ZIP, TZAP_DEFAULT_RECOVERY_PERCENTAGE,
    ZIP_CREATE_EXTENSIONS, path_has_known_extension,
};
use crate::cli::open::{run_test_request, tzap_default_volume_loss_tolerance};
use crate::cli::options::{
    GlobalOptions, infer_create_format, parse_archive_format, parse_global_option, parse_i32, parse_volume_size,
    resolve_input_path, take_value,
};
use crate::cli::planning::{
    append_files_from, append_stdin_paths, apply_junk_paths, apply_manifest_filters, manifest_has_symlinks,
    plan_sources,
};
use crate::cli::usage::{
    CREATE_HELP, command_usage_error, normalize_prompted_password, print_create_summary, print_error_line,
    print_help_stdout, print_manifest, print_optional_error_line, prompt_password, wants_help,
};
use crate::output::{self, StyleRole};
use std::fs;
use std::io::{self, IsTerminal as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use zmanager_core::jobs::{CancellationToken, JobContext, JobEvent};
use zmanager_core::secrets::SecretString;
pub(crate) fn create_command(args: &[String], global: GlobalOptions) -> ExitCode {
    if wants_help(args) {
        print_help_stdout(CREATE_HELP, &global);
        return ExitCode::SUCCESS;
    }
    let expanded = expand_short_options(args);
    create_command_from_expanded(&expanded, global)
}

pub(crate) fn create_command_from_expanded(args: &[String], mut global: GlobalOptions) -> ExitCode {
    if wants_help(args) {
        print_help_stdout(CREATE_HELP, &global);
        return ExitCode::SUCCESS;
    }
    let mut request = CreateRequest::default();
    match parse_create_request(args, &mut global, &mut request) {
        Ok(()) => run_create_request(&request, &global),
        Err(error) => command_usage_error("create", &error, &global),
    }
}

#[allow(clippy::too_many_lines)]
pub(crate) fn parse_create_request(
    args: &[String],
    global: &mut GlobalOptions,
    request: &mut CreateRequest,
) -> Result<(), String> {
    let mut index = 0usize;
    let mut current_dir: Option<PathBuf> = None;
    let mut positional_after_double_dash = false;

    while index < args.len() {
        let arg = &args[index];
        if positional_after_double_dash {
            push_create_positional(request, arg, current_dir.as_deref());
            index += 1;
            continue;
        }
        if arg == "--" {
            positional_after_double_dash = true;
            index += 1;
            continue;
        }
        if parse_global_option(args, &mut index, global)? {
            continue;
        }

        match arg.as_str() {
            "-c" | "--create" | "-r" | "--recursive" | "--hidden" | "--preserve-metadata" => {
                index += 1;
            }
            "-X" | "--no-metadata" => {
                request.no_metadata = true;
                index += 1;
            }
            "-y" | "--preserve-symlinks" => {
                request.preserve_symlinks = true;
                index += 1;
            }
            "-f" | "--file" => {
                request.archive = take_value(args, &mut index, arg)?;
            }
            "--format" => {
                request.format = Some(parse_archive_format(&take_value(args, &mut index, arg)?)?);
            }
            "--method" => {
                request.method = Some(take_value(args, &mut index, arg)?);
            }
            "--level" => {
                request.level = Some(parse_i32(&take_value(args, &mut index, arg)?, arg)?);
            }
            "-0" => {
                request.compression = zmanager_core::zip_backend::ZipCompression::Store;
                request.level = Some(0);
                index += 1;
            }
            "-1" | "-2" | "-3" | "-4" | "-5" | "-6" | "-7" | "-8" | "-9" => {
                request.level = Some(parse_i32(&arg[1..], arg)?);
                request.compression = zmanager_core::zip_backend::ZipCompression::Deflate;
                index += 1;
            }
            "-C" | "--directory" => {
                current_dir = Some(PathBuf::from(take_value(args, &mut index, arg)?));
            }
            "-@" => {
                request.stdin_paths = true;
                index += 1;
            }
            "--files-from" => {
                request.files_from.push(take_value(args, &mut index, arg)?);
            }
            "--null" => {
                request.null_paths = true;
                index += 1;
            }
            "-i" | "--include" => {
                request.include.push(take_value(args, &mut index, arg)?);
            }
            "--exclude" => {
                request.exclude.push(take_value(args, &mut index, arg)?);
            }
            "--exclude-from" => {
                request.exclude_from.push(PathBuf::from(take_value(args, &mut index, arg)?));
            }
            "--store" => {
                request.compression = zmanager_core::zip_backend::ZipCompression::Store;
                index += 1;
            }
            "--solid" => {
                request.solid = true;
                index += 1;
            }
            "--no-solid" => {
                request.solid = false;
                index += 1;
            }
            "--clean" => {
                request.clean = true;
                index += 1;
            }
            "--no-ignore" => {
                request.no_ignore = true;
                index += 1;
            }
            "--no-hidden" => {
                request.no_hidden = true;
                index += 1;
            }
            "-j" | "--junk-paths" => {
                request.junk_paths = true;
                index += 1;
            }
            "--follow-symlinks" => {
                request.follow_symlinks = true;
                index += 1;
            }
            "--force" => {
                request.force = true;
                index += 1;
            }
            "--encrypt" => {
                request.encrypt = true;
                index += 1;
            }
            "--password-stdin" => {
                request.password_stdin = true;
                index += 1;
            }
            "--volume-size" => {
                request.volume_size = Some(parse_volume_size(&take_value(args, &mut index, arg)?, arg)?);
            }
            "--recipient-cert" => {
                request.tzap_recipient_cert = Some(PathBuf::from(take_value(args, &mut index, arg)?));
            }
            "--signing-cert" => {
                request.tzap_signing_cert = Some(PathBuf::from(take_value(args, &mut index, arg)?));
            }
            "--signing-private-key" => {
                request.tzap_signing_private_key = Some(PathBuf::from(take_value(args, &mut index, arg)?));
            }
            "--signing-chain" => {
                request.tzap_signing_chain.push(PathBuf::from(take_value(args, &mut index, arg)?));
            }
            "--dry-run" => {
                request.dry_run = true;
                index += 1;
            }
            "-T" | "--test-after" | "--test" => {
                request.test_after = true;
                index += 1;
            }
            _ if arg.starts_with('-') && arg != "-" => {
                return Err(format!("unknown create option: {arg}"));
            }
            _ => {
                push_create_positional(request, arg, current_dir.as_deref());
                index += 1;
            }
        }
    }

    append_files_from(&mut request.sources, &request.files_from, request.null_paths)?;
    if request.stdin_paths {
        append_stdin_paths(&mut request.sources, request.null_paths)?;
    }

    if request.archive.is_empty() {
        return Err("missing archive path".to_owned());
    }
    if request.sources.is_empty() {
        return Err("missing source path".to_owned());
    }

    Ok(())
}
fn push_create_positional(request: &mut CreateRequest, value: &str, current_dir: Option<&Path>) {
    if request.archive.is_empty() {
        value.clone_into(&mut request.archive);
    } else {
        request.sources.push(resolve_input_path(value, current_dir));
    }
}

#[allow(clippy::too_many_lines)]
fn run_create_request(request: &CreateRequest, global: &GlobalOptions) -> ExitCode {
    let Some(format) = request.format.or_else(|| infer_create_format(&request.archive)) else {
        print_error_line(
            global,
            format_args!("could not infer archive format; pass --format <zip|tar.zst|tzap|aar|7z|tgz>"),
        );
        return ExitCode::from(2);
    };

    if let Err(error) = validate_create_options(format, request) {
        print_error_line(global, format_args!("{error}"));
        return ExitCode::from(2);
    }

    let password = match create_password(format, request, global) {
        Ok(password) => password,
        Err(code) => return code,
    };
    let follow_symlinks = follow_symlinks_for_create(format, request);
    if request.follow_symlinks && request.preserve_symlinks {
        print_error_line(global, format_args!("create failed: --follow-symlinks conflicts with --preserve-symlinks"));
        return ExitCode::from(2);
    }

    let manifest = match plan_sources(&request.sources, request.clean, request.no_ignore, follow_symlinks) {
        Ok(mut manifest) => {
            if let Err(error) = apply_manifest_filters(
                &mut manifest,
                &request.include,
                &request.exclude,
                &request.exclude_from,
                request.no_hidden,
            ) {
                print_error_line(global, format_args!("create failed: {error}"));
                return ExitCode::FAILURE;
            }
            if request.junk_paths
                && let Err(error) = apply_junk_paths(&mut manifest)
            {
                print_error_line(global, format_args!("create failed: {error}"));
                return ExitCode::FAILURE;
            }
            if format == ArchiveFormat::SevenZ && request.preserve_symlinks && manifest_has_symlinks(&manifest) {
                print_error_line(
                    global,
                    format_args!(
                        "create failed: 7z symlink preservation is not supported by the current backend; use --follow-symlinks"
                    ),
                );
                return ExitCode::from(2);
            }
            manifest
        }
        Err(error) => {
            print_error_line(global, format_args!("create failed: {error}"));
            return ExitCode::FAILURE;
        }
    };

    if request.dry_run {
        print_manifest(&manifest, global);
        return ExitCode::SUCCESS;
    }

    if request.archive == "-" {
        return create_stream(format, &manifest, request, password, global);
    }

    let destination = PathBuf::from(&request.archive);
    if destination.exists() && !request.force {
        print_error_line(
            global,
            format_args!("create failed: destination exists: {}; pass --force to replace it", destination.display()),
        );
        return ExitCode::FAILURE;
    }

    let split_output = request.volume_size.is_some();
    let temp = temp_archive_path(&destination);
    if let Some(parent) = destination.parent()
        && !parent.as_os_str().is_empty()
        && let Err(error) = fs::create_dir_all(parent)
    {
        print_error_line(global, format_args!("create failed: failed to create {}: {error}", parent.display()));
        return ExitCode::FAILURE;
    }

    let mut progress = ProgressReporter::from_global(Some(global));
    progress.emit(JobEvent::Started { kind: create_progress_kind(format), total_bytes: Some(manifest.total_bytes) });
    let token = CancellationToken::new();
    let create_destination = if split_output { destination.as_path() } else { temp.as_path() };
    let backend_replace_existing = split_output && request.force;

    let outcome_result = match format {
        ArchiveFormat::Zip => run_zip_create_backend(
            request,
            &manifest,
            &temp,
            create_destination,
            password,
            backend_replace_existing,
            split_output,
            &mut progress,
            &token,
            global,
        ),
        ArchiveFormat::TarZst => {
            run_tar_zst_create_backend(request, &manifest, &temp, split_output, &mut progress, &token, global)
        }
        ArchiveFormat::Tgz => run_tgz_create_backend(
            request,
            &manifest,
            &temp,
            backend_replace_existing,
            split_output,
            &mut progress,
            &token,
            global,
        ),
        ArchiveFormat::Tzap => run_tzap_create_backend(
            request,
            &manifest,
            &temp,
            create_destination,
            password,
            backend_replace_existing,
            split_output,
            &mut progress,
            &token,
            global,
        ),
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        ArchiveFormat::AppleArchive => run_apple_archive_create_backend(
            request,
            &manifest,
            &temp,
            backend_replace_existing,
            split_output,
            &mut progress,
            &token,
            global,
        ),
        ArchiveFormat::SevenZ => run_seven_z_create_backend(
            request,
            &manifest,
            &temp,
            create_destination,
            password,
            backend_replace_existing,
            split_output,
            &mut progress,
            &token,
            global,
        ),
    };
    let outcome = match outcome_result {
        Ok(outcome) => outcome,
        Err(code) => return code,
    };

    if !split_output && let Err(error) = publish_archive(&temp, &destination, request.force) {
        let _ = fs::remove_file(&temp);
        progress.emit(JobEvent::Failed { message: error.to_string() });
        print_error_line(
            global,
            format_args!("create failed: failed to move {} to {}: {error}", temp.display(), destination.display()),
        );
        return ExitCode::FAILURE;
    }
    progress.emit(JobEvent::Completed { entries: outcome.entries, bytes: outcome.bytes });
    print_create_summary(&destination, &outcome, global);
    if request.test_after {
        let archive = create_test_archive_path(&destination, format, split_output).to_string_lossy().into_owned();
        return run_test_request(&TestRequest { archive, ..TestRequest::default() }, global);
    }
    ExitCode::SUCCESS
}

#[allow(clippy::too_many_arguments)]
fn run_zip_create_backend(
    request: &CreateRequest,
    manifest: &zmanager_core::manifest::ArchiveManifest,
    temp: &Path,
    create_destination: &Path,
    password: Option<SecretString>,
    backend_replace_existing: bool,
    split_output: bool,
    progress: &mut ProgressReporter,
    token: &CancellationToken,
    global: &GlobalOptions,
) -> Result<CreateOutcome, ExitCode> {
    let (compression, level) = match zip_compression_options(request) {
        Ok(options) => options,
        Err(error) => {
            print_error_line(global, format_args!("{error}"));
            return Err(ExitCode::from(2));
        }
    };
    let options = zmanager_core::zip_backend::ZipCreateOptions {
        compression,
        level,
        preserve_metadata: !request.no_metadata,
        replace_existing: backend_replace_existing,
        password,
        volume_size: request.volume_size,
    };
    run_create_backend(
        manifest,
        progress,
        token,
        |context| {
            zmanager_core::zip_backend::create_zip_from_manifest_with_context(
                manifest,
                create_destination,
                &options,
                context,
            )
            .map_err(|error| error.to_string())
        },
        |report| CreateOutcome {
            summary: format!(
                "created zip: {} entries, {} bytes, encrypted {}, {} warnings",
                report.written_entries,
                report.written_bytes,
                report.encrypted,
                report.warnings.len()
            ),
            format: FORMAT_ZIP,
            backend: FORMAT_ZIP,
            entries: report.written_entries,
            bytes: report.written_bytes,
            warnings: report.warnings.len(),
            encrypted: Some(report.encrypted),
            solid: None,
            volume_size: report.volume_size,
            volume_count: report.volume_count,
        },
    )
    .map_err(|error| fail_create(progress, global, temp, split_output, &error))
}

#[allow(clippy::too_many_arguments)]
fn run_tar_zst_create_backend(
    request: &CreateRequest,
    manifest: &zmanager_core::manifest::ArchiveManifest,
    temp: &Path,
    split_output: bool,
    progress: &mut ProgressReporter,
    token: &CancellationToken,
    global: &GlobalOptions,
) -> Result<CreateOutcome, ExitCode> {
    let options = zmanager_core::tar_zst_backend::TarZstdCreateOptions {
        level: request.level.unwrap_or_else(|| zmanager_core::tar_zst_backend::TarZstdCreateOptions::default().level),
        preserve_metadata: !request.no_metadata,
        ..zmanager_core::tar_zst_backend::TarZstdCreateOptions::default()
    };
    run_create_backend(
        manifest,
        progress,
        token,
        |context| {
            zmanager_core::tar_zst_backend::create_tar_zst_from_manifest_with_context(manifest, temp, &options, context)
                .map_err(|error| error.to_string())
        },
        |report| CreateOutcome {
            summary: format!(
                "created tar.zst: {} entries, {} bytes, level {}, threads {:?}, {} warnings",
                report.written_entries,
                report.written_bytes,
                report.level,
                report.threads,
                report.warnings.len()
            ),
            format: FORMAT_TAR_ZST,
            backend: FORMAT_TAR_ZST,
            entries: report.written_entries,
            bytes: report.written_bytes,
            warnings: report.warnings.len(),
            encrypted: None,
            solid: None,
            volume_size: None,
            volume_count: 1,
        },
    )
    .map_err(|error| fail_create(progress, global, temp, split_output, &error))
}

#[allow(clippy::too_many_arguments)]
fn run_tgz_create_backend(
    request: &CreateRequest,
    manifest: &zmanager_core::manifest::ArchiveManifest,
    temp: &Path,
    backend_replace_existing: bool,
    split_output: bool,
    progress: &mut ProgressReporter,
    token: &CancellationToken,
    global: &GlobalOptions,
) -> Result<CreateOutcome, ExitCode> {
    let options = zmanager_core::tar_gz_backend::TarGzCreateOptions {
        level: request.level.unwrap_or_else(|| zmanager_core::tar_gz_backend::TarGzCreateOptions::default().level),
        preserve_metadata: !request.no_metadata,
        replace_existing: backend_replace_existing,
    };
    run_create_backend(
        manifest,
        progress,
        token,
        |context| {
            zmanager_core::tar_gz_backend::create_tar_gz_from_manifest_with_context(manifest, temp, &options, context)
                .map_err(|error| error.to_string())
        },
        |report| CreateOutcome {
            summary: format!(
                "created tar.gz: {} entries, {} bytes, level {}, {} warnings",
                report.written_entries,
                report.written_bytes,
                report.level,
                report.warnings.len()
            ),
            format: FORMAT_TGZ,
            backend: FORMAT_TGZ,
            entries: report.written_entries,
            bytes: report.written_bytes,
            warnings: report.warnings.len(),
            encrypted: None,
            solid: None,
            volume_size: None,
            volume_count: 1,
        },
    )
    .map_err(|error| fail_create(progress, global, temp, split_output, &error))
}

#[allow(clippy::too_many_arguments)]
fn run_tzap_create_backend(
    request: &CreateRequest,
    manifest: &zmanager_core::manifest::ArchiveManifest,
    temp: &Path,
    create_destination: &Path,
    password: Option<SecretString>,
    backend_replace_existing: bool,
    split_output: bool,
    progress: &mut ProgressReporter,
    token: &CancellationToken,
    global: &GlobalOptions,
) -> Result<CreateOutcome, ExitCode> {
    let uses_secret_key = password.is_some() || request.tzap_recipient_cert.is_some();
    let key_source = if let Some(recipient_certificate) = &request.tzap_recipient_cert {
        zmanager_core::tzap_backend::TzapKeySource::RecipientCertificate(recipient_certificate.clone())
    } else {
        password.map_or(
            zmanager_core::tzap_backend::TzapKeySource::NoPassword,
            zmanager_core::tzap_backend::TzapKeySource::Passphrase,
        )
    };
    let x509_signing = match &request.tzap_signing_cert {
        Some(certificate) => {
            let Some(private_key) = &request.tzap_signing_private_key else {
                print_error_line(
                    global,
                    format_args!("create failed: --signing-cert and --signing-private-key must be used together"),
                );
                return Err(ExitCode::from(2));
            };
            Some(zmanager_core::tzap_backend::TzapX509SigningOptions::CertificateAndKey {
                signing_certificate: certificate.clone(),
                signing_private_key: private_key.clone(),
                signing_chain: request.tzap_signing_chain.clone(),
            })
        }
        None => None,
    };
    let options = zmanager_core::tzap_backend::TzapCreateOptions {
        key_source,
        level: request.level.unwrap_or(3),
        preserve_metadata: !request.no_metadata,
        replace_existing: backend_replace_existing,
        volume_size: request.volume_size,
        recovery_percentage: TZAP_DEFAULT_RECOVERY_PERCENTAGE,
        volume_loss_tolerance: tzap_default_volume_loss_tolerance(request.volume_size),
        x509_signing,
    };
    run_create_backend(
        manifest,
        progress,
        token,
        |context| {
            zmanager_core::tzap_backend::create_tzap_from_manifest_with_context(
                manifest,
                create_destination,
                &options,
                context,
            )
            .map_err(|error| error.to_string())
        },
        |report| CreateOutcome {
            summary: format!(
                "created tzap: {} entries, {} bytes, encrypted {}, level {}, {} warnings",
                report.written_entries,
                report.written_bytes,
                uses_secret_key,
                report.level,
                report.warnings.len()
            ),
            format: FORMAT_TZAP,
            backend: FORMAT_TZAP,
            entries: report.written_entries,
            bytes: report.written_bytes,
            warnings: report.warnings.len(),
            encrypted: Some(uses_secret_key),
            solid: None,
            volume_size: report.volume_size,
            volume_count: report.volume_count,
        },
    )
    .map_err(|error| fail_create(progress, global, temp, split_output, &error))
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
#[allow(clippy::too_many_arguments)]
fn run_apple_archive_create_backend(
    request: &CreateRequest,
    manifest: &zmanager_core::manifest::ArchiveManifest,
    temp: &Path,
    backend_replace_existing: bool,
    split_output: bool,
    progress: &mut ProgressReporter,
    token: &CancellationToken,
    global: &GlobalOptions,
) -> Result<CreateOutcome, ExitCode> {
    let compression = match apple_archive_compression(request) {
        Ok(compression) => compression,
        Err(error) => {
            print_error_line(global, format_args!("{error}"));
            return Err(ExitCode::from(2));
        }
    };
    let options = zmanager_core::apple_archive_backend::AppleArchiveCreateOptions {
        compression,
        preserve_metadata: !request.no_metadata,
        replace_existing: backend_replace_existing,
        ..zmanager_core::apple_archive_backend::AppleArchiveCreateOptions::default()
    };
    run_create_backend(
        manifest,
        progress,
        token,
        |context| {
            zmanager_core::apple_archive_backend::create_apple_archive_from_manifest_with_context(
                manifest, temp, &options, context,
            )
            .map_err(|error| error.to_string())
        },
        |report| CreateOutcome {
            summary: format!(
                "created aar: {} entries, {} bytes, compression {:?}, {} warnings",
                report.written_entries,
                report.written_bytes,
                options.compression,
                report.warnings.len()
            ),
            format: FORMAT_APPLE_ARCHIVE,
            backend: FORMAT_APPLE_ARCHIVE,
            entries: report.written_entries,
            bytes: report.written_bytes,
            warnings: report.warnings.len(),
            encrypted: None,
            solid: None,
            volume_size: None,
            volume_count: 1,
        },
    )
    .map_err(|error| fail_create(progress, global, temp, split_output, &error))
}

#[allow(clippy::too_many_arguments)]
fn run_seven_z_create_backend(
    request: &CreateRequest,
    manifest: &zmanager_core::manifest::ArchiveManifest,
    temp: &Path,
    create_destination: &Path,
    password: Option<SecretString>,
    backend_replace_existing: bool,
    split_output: bool,
    progress: &mut ProgressReporter,
    token: &CancellationToken,
    global: &GlobalOptions,
) -> Result<CreateOutcome, ExitCode> {
    let options = zmanager_core::sevenz_backend::SevenZCreateOptions {
        solid: request.solid,
        level: sevenz_level(request),
        preserve_metadata: !request.no_metadata,
        password,
        encrypt_file_names: true,
        replace_existing: backend_replace_existing,
        volume_size: request.volume_size,
        ..zmanager_core::sevenz_backend::SevenZCreateOptions::default()
    };
    run_create_backend(
        manifest,
        progress,
        token,
        |_context| {
            zmanager_core::sevenz_backend::create_7z_from_manifest(manifest, create_destination, &options)
                .map_err(|error| error.to_string())
        },
        |report| CreateOutcome {
            summary: format!(
                "created 7z: {} entries, {} bytes, solid {}, threads {:?}, encrypted {}, {} warnings",
                report.written_entries,
                report.written_bytes,
                report.solid,
                report.threads,
                report.encrypted,
                report.warnings.len()
            ),
            format: FORMAT_SEVEN_Z,
            backend: FORMAT_SEVEN_Z,
            entries: report.written_entries,
            bytes: report.written_bytes,
            warnings: report.warnings.len(),
            encrypted: Some(report.encrypted),
            solid: Some(report.solid),
            volume_size: report.volume_size,
            volume_count: report.volume_count,
        },
    )
    .map_err(|error| fail_create(progress, global, temp, split_output, &error))
}

/// Shared create-failure path: cleans up the temp archive and reports the
/// error (CR-144).
fn fail_create(
    progress: &mut ProgressReporter,
    global: &GlobalOptions,
    temp: &Path,
    split_output: bool,
    error: &str,
) -> ExitCode {
    if !split_output {
        let _ = fs::remove_file(temp);
    }
    progress.emit(JobEvent::Failed { message: error.to_string() });
    print_error_line(global, format_args!("create failed: {error}"));
    ExitCode::FAILURE
}

fn run_create_backend<R>(
    manifest: &zmanager_core::manifest::ArchiveManifest,
    progress: &mut ProgressReporter,
    token: &CancellationToken,
    run: impl FnOnce(&mut JobContext<'_>) -> Result<R, String>,
    map_outcome: impl FnOnce(R) -> CreateOutcome,
) -> Result<CreateOutcome, String> {
    let result = {
        let mut sink = |event| progress.emit(event);
        let mut context = JobContext::new_with_progress_total(token, &mut sink, Some(manifest.total_bytes));
        let result = run(&mut context);
        context.flush_progress();
        result
    };
    result.map(map_outcome)
}

fn create_stream(
    format: ArchiveFormat,
    manifest: &zmanager_core::manifest::ArchiveManifest,
    request: &CreateRequest,
    password: Option<SecretString>,
    global: &GlobalOptions,
) -> ExitCode {
    if format != ArchiveFormat::Zip {
        print_error_line(global, format_args!("create failed: stdout output is currently supported only for ZIP"));
        return ExitCode::from(2);
    }

    let (compression, level) = match zip_compression_options(request) {
        Ok(options) => options,
        Err(error) => {
            print_error_line(global, format_args!("{error}"));
            return ExitCode::from(2);
        }
    };
    let options = zmanager_core::zip_backend::ZipCreateOptions {
        compression,
        level,
        preserve_metadata: !request.no_metadata,
        replace_existing: false,
        password,
        volume_size: None,
    };
    let stdout = io::stdout();
    match zmanager_core::zip_backend::create_zip_stream_from_manifest(manifest, stdout.lock(), &options) {
        Ok((_output, report)) => {
            output::stderr_line(
                global.color,
                format_args!(
                    "{} streaming zip: {} entries, {} bytes, {} warnings",
                    output::styled(StyleRole::Success, format_args!("created")),
                    report.written_entries,
                    report.written_bytes,
                    report.warnings.len()
                ),
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            print_error_line(global, format_args!("create failed: {error}"));
            ExitCode::FAILURE
        }
    }
}
#[allow(clippy::too_many_lines)]
pub(crate) fn validate_create_options(format: ArchiveFormat, request: &CreateRequest) -> Result<(), String> {
    if request.tzap_recipient_cert.is_some() {
        if format != ArchiveFormat::Tzap {
            return Err("recipient certificates are supported only for TZAP archives".to_owned());
        }
        if request.encrypt || request.password_stdin {
            return Err("--recipient-cert cannot be combined with --encrypt or --password-stdin".to_owned());
        }
        if request.tzap_signing_cert.is_some()
            || request.tzap_signing_private_key.is_some()
            || !request.tzap_signing_chain.is_empty()
        {
            return Err("--recipient-cert cannot be combined with X.509 signing options".to_owned());
        }
        if request.volume_size.is_some() {
            return Err("--recipient-cert is supported only for single-volume TZAP create".to_owned());
        }
    }

    if request.tzap_signing_cert.is_some()
        || request.tzap_signing_private_key.is_some()
        || !request.tzap_signing_chain.is_empty()
    {
        if format != ArchiveFormat::Tzap {
            return Err("certificate signing is supported only for TZAP archives".to_owned());
        }
        match (request.tzap_signing_cert.as_ref(), request.tzap_signing_private_key.as_ref()) {
            (Some(_), Some(_)) => {}
            (None, None) if !request.tzap_signing_chain.is_empty() => {
                return Err("--signing-chain requires --signing-cert".to_owned());
            }
            _ => {
                return Err("--signing-cert and --signing-private-key must be used together".to_owned());
            }
        }
    }

    if request.volume_size.is_some() {
        if request.archive == "-" {
            return Err("--volume-size cannot be used with stdout archive output".to_owned());
        }
        match format {
            ArchiveFormat::Zip => {
                if !path_has_known_extension(&request.archive, ZIP_CREATE_EXTENSIONS) {
                    return Err("split ZIP output must use a .zip archive path".to_owned());
                }
            }
            ArchiveFormat::SevenZ | ArchiveFormat::Tzap => {}
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            ArchiveFormat::AppleArchive => {}
            ArchiveFormat::TarZst | ArchiveFormat::Tgz => {
                return Err("--volume-size is supported only for ZIP, TZAP, and 7z archives".to_owned());
            }
        }
    }

    if let Some(method) = request.method.as_deref() {
        match (format, method) {
            (ArchiveFormat::Zip, "deflate" | "store")
            | (ArchiveFormat::TarZst | ArchiveFormat::Tzap, "zstd" | "zst")
            | (ArchiveFormat::SevenZ, "lzma2")
            | (ArchiveFormat::Tgz, "gzip" | "gz") => {}
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            (ArchiveFormat::AppleArchive, "lzfse" | "lz4" | "zlib" | "lzma" | "raw") => {}
            _ => {
                return Err(format!("unsupported method for selected archive format: {method}"));
            }
        }
    }

    if let Some(level) = request.level {
        match format {
            ArchiveFormat::Zip | ArchiveFormat::SevenZ | ArchiveFormat::Tzap | ArchiveFormat::Tgz
                if !(0..=9).contains(&level) =>
            {
                return Err(format!("unsupported compression level for selected archive format: {level}"));
            }
            ArchiveFormat::Zip
                if request.compression == zmanager_core::zip_backend::ZipCompression::Store && level != 0 =>
            {
                return Err(format!("cannot combine ZIP store compression with compression level {level}"));
            }
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            ArchiveFormat::AppleArchive => {
                return Err("compression levels are not supported for AAR archives".to_owned());
            }
            _ => {}
        }
    }

    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn apple_archive_compression(
    request: &CreateRequest,
) -> Result<zmanager_core::apple_archive_backend::AppleArchiveCompression, String> {
    use zmanager_core::apple_archive_backend::AppleArchiveCompression;

    match request.method.as_deref() {
        None => Ok(AppleArchiveCompression::default()),
        Some("lzfse") => Ok(AppleArchiveCompression::Lzfse),
        Some("lz4") => Ok(AppleArchiveCompression::Lz4),
        Some("zlib") => Ok(AppleArchiveCompression::Zlib),
        Some("lzma") => Ok(AppleArchiveCompression::Lzma),
        Some("raw") => Ok(AppleArchiveCompression::None),
        Some(method) => Err(format!("unsupported method for selected archive format: {method}")),
    }
}

fn zip_compression_options(
    request: &CreateRequest,
) -> Result<(zmanager_core::zip_backend::ZipCompression, Option<i64>), String> {
    let mut compression = request.compression;
    if let Some(method) = request.method.as_deref() {
        compression = match method {
            "store" => zmanager_core::zip_backend::ZipCompression::Store,
            "deflate" => zmanager_core::zip_backend::ZipCompression::Deflate,
            _ => compression,
        };
    }

    let Some(level) = request.level else {
        return Ok((compression, None));
    };
    if !(0..=9).contains(&level) {
        return Err(format!("unsupported compression level for selected archive format: {level}"));
    }
    if compression == zmanager_core::zip_backend::ZipCompression::Store {
        if level == 0 {
            return Ok((compression, None));
        }
        return Err(format!("cannot combine ZIP store compression with compression level {level}"));
    }
    if level == 0 {
        return Ok((zmanager_core::zip_backend::ZipCompression::Store, None));
    }

    Ok((compression, Some(i64::from(level))))
}

fn sevenz_level(request: &CreateRequest) -> Option<u32> {
    request.level.and_then(|level| u32::try_from(level).ok())
}

fn follow_symlinks_for_create(format: ArchiveFormat, request: &CreateRequest) -> bool {
    request.follow_symlinks
        || (!request.preserve_symlinks
            && matches!(format, ArchiveFormat::Zip | ArchiveFormat::SevenZ | ArchiveFormat::Tzap))
}

fn create_password(
    format: ArchiveFormat,
    request: &CreateRequest,
    global: &GlobalOptions,
) -> Result<Option<SecretString>, ExitCode> {
    if !request.encrypt && !request.password_stdin {
        return Ok(None);
    }
    if matches!(format, ArchiveFormat::TarZst | ArchiveFormat::Tgz) {
        print_error_line(global, format_args!("encryption is not supported for this archive format"));
        return Err(ExitCode::from(2));
    }
    if request.password_stdin {
        return prompt_password_from_stdin(Some(global)).map(Some);
    }
    if global.no_password_prompt {
        print_error_line(global, format_args!("password prompt disabled; use --password-stdin"));
        return Err(ExitCode::from(2));
    }
    if global.quiet || !io::stdin().is_terminal() {
        print_error_line(
            global,
            format_args!("password prompt requires an interactive terminal; use --password-stdin"),
        );
        return Err(ExitCode::from(2));
    }
    let prompt = match format {
        ArchiveFormat::SevenZ => "7z password: ",
        ArchiveFormat::Tzap => "tzap password: ",
        ArchiveFormat::TarZst | ArchiveFormat::Tgz => "archive password: ",
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        ArchiveFormat::AppleArchive => "archive password: ",
        ArchiveFormat::Zip => "ZIP password: ",
    };
    prompt_password(prompt).map(Some)
}

pub(crate) fn prompt_password_from_stdin(global: Option<&GlobalOptions>) -> Result<SecretString, ExitCode> {
    let mut password = String::new();
    match io::stdin().read_line(&mut password) {
        Ok(bytes_read) => {
            if let Some(password) = normalize_prompted_password(password, bytes_read) {
                Ok(SecretString::from(password))
            } else {
                print_optional_error_line(global, format_args!("password prompt cancelled"));
                Err(ExitCode::FAILURE)
            }
        }
        Err(error) => {
            print_optional_error_line(global, format_args!("failed to read password: {error}"));
            Err(ExitCode::FAILURE)
        }
    }
}
