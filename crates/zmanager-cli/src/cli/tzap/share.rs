use super::support::*;
use super::*;
use crate::cli::app::ProgressReporter;
use crate::cli::format::{TZAP_DEFAULT_RECOVERY_PERCENTAGE, TZAP_SINGLE_VOLUME_LOSS_TOLERANCE};
use crate::cli::options::{GlobalOptions, parse_global_option, take_value};
use crate::cli::planning::plan_sources;
use crate::cli::usage::{
    SHARE_HELP, command_usage_error, json_escape, print_error_line, print_help_stdout, print_success_line, wants_help,
};
use std::path::PathBuf;
use std::process::ExitCode;
use zmanager_core::jobs::{CancellationToken, JobContext};

pub(crate) fn share_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    if wants_help(args) {
        print_help_stdout(SHARE_HELP, &global);
        return ExitCode::SUCCESS;
    }
    let mut context = TzapCliContext::default();
    let mut archive = None;
    let mut sources = Vec::new();
    let mut contact_ids = Vec::new();
    let mut certificate_id = None;
    let mut force = false;
    let mut index = 0usize;
    while index < args.len() {
        match parse_global_option(args, &mut index, &mut global) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(error) => return command_usage_error("share", &error, &global),
        }
        match parse_tzap_context_option(args, &mut index, &mut context, "share", &global) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(code) => return code,
        }
        match args[index].as_str() {
            "--contact" => contact_ids.push(match take_value(args, &mut index, "--contact") {
                Ok(value) => value,
                Err(error) => return command_usage_error("share", &error, &global),
            }),
            "--certificate-id" => {
                certificate_id = Some(match take_value(args, &mut index, "--certificate-id") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("share", &error, &global),
                });
            }
            "--force" => {
                force = true;
                index += 1;
            }
            value if value.starts_with('-') => {
                return command_usage_error("share", &format!("unknown share option: {value}"), &global);
            }
            value if archive.is_none() => {
                archive = Some(PathBuf::from(value));
                index += 1;
            }
            value => {
                sources.push(PathBuf::from(value));
                index += 1;
            }
        }
    }
    let Some(archive) = archive else {
        return command_usage_error("share", "missing archive", &global);
    };
    if sources.is_empty() {
        return command_usage_error("share", "missing source path", &global);
    }
    let Some(certificate_id) = certificate_id else {
        return command_usage_error("share", "missing --certificate-id", &global);
    };
    let store = zmanager_core::local_identity_store::FileTzapLocalIdentityStore::new(&context.state_dir);
    let x509_signing =
        match local_tzap_x509_signing_options(&store, &context.account_key, &certificate_id, current_unix_seconds()) {
            Ok(signing) => signing,
            Err(error) => {
                print_stable_tzap_error("share", &error, &global);
                return ExitCode::FAILURE;
            }
        };
    let recipients = match zmanager_core::contact_card::accepted_contact_recipients(
        &store,
        &context.account_key,
        &contact_ids,
        current_unix_seconds(),
    ) {
        Ok(recipients) => recipients,
        Err(error) => {
            print_stable_tzap_error("share", &error.to_string(), &global);
            return ExitCode::FAILURE;
        }
    };
    let recipient_warning_count = recipients.iter().filter(|recipient| recipient.missing_status_caveat).count();
    let recipient_public_keys = recipients.into_iter().map(|recipient| recipient.recipient_public_key_der).collect();
    let manifest = match plan_sources(&sources, false, false, false) {
        Ok(manifest) => manifest,
        Err(error) => {
            print_error_line(&global, format_args!("share failed: {error}"));
            return ExitCode::FAILURE;
        }
    };
    if archive.exists() && !force {
        print_error_line(&global, format_args!("share failed: destination exists: {}", archive.display()));
        return ExitCode::FAILURE;
    }
    let token = CancellationToken::new();
    let mut progress = ProgressReporter::from_global(Some(&global));
    let options = zmanager_core::tzap_backend::TzapCreateOptions {
        key_source: zmanager_core::tzap_backend::TzapKeySource::RecipientPublicKeys(recipient_public_keys),
        level: 3,
        preserve_metadata: true,
        replace_existing: force,
        volume_size: None,
        recovery_percentage: TZAP_DEFAULT_RECOVERY_PERCENTAGE,
        volume_loss_tolerance: TZAP_SINGLE_VOLUME_LOSS_TOLERANCE,
        x509_signing: Some(x509_signing),
    };
    let result = {
        let mut sink = |event| progress.emit(event);
        let mut job_context = JobContext::new_with_progress_total(&token, &mut sink, Some(manifest.total_bytes));
        let result = zmanager_core::tzap_backend::create_tzap_from_manifest_with_context(
            &manifest,
            &archive,
            &options,
            &mut job_context,
        );
        job_context.flush_progress();
        result
    };
    match result {
        Ok(report) => {
            if global.json {
                println!(
                    "{{\"archive\":\"{}\",\"format\":\"tzap\",\"entries\":{},\"bytes\":{},\"recipients\":{},\"recipient_status_caveats\":{},\"signed\":true,\"certificate_id\":\"{}\"}}",
                    json_escape(&archive.display().to_string()),
                    report.written_entries,
                    report.written_bytes,
                    contact_ids.len(),
                    recipient_warning_count,
                    json_escape(&certificate_id)
                );
            } else {
                if recipient_warning_count > 0 {
                    print_error_line(
                        &global,
                        format_args!("{recipient_warning_count} recipient contact(s) have offline-only status caveats"),
                    );
                }
                print_success_line(&global, format_args!("created shared tzap {}", archive.display()));
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            print_error_line(&global, format_args!("share failed: {error}"));
            ExitCode::FAILURE
        }
    }
}
