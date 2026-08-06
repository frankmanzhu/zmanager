use super::TzapCliContext;
use super::support::{parse_tzap_context_option, service_envelope, service_request};
use crate::cli::options::{GlobalOptions, parse_global_option, take_value};
use crate::cli::usage::{
    SHARE_HELP, command_usage_error, print_error_line, print_help_stdout, print_success_line, wants_help,
};
use serde_json::json;
use std::path::PathBuf;
use std::process::ExitCode;
use zmanager_core::tzap_service::tzap_share_create_json;

#[allow(clippy::too_many_lines)]
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
    if archive.exists() && !force {
        print_error_line(&global, format_args!("share failed: destination exists: {}", archive.display()));
        return ExitCode::FAILURE;
    }
    let request = service_request(
        &context,
        json!({
            "destination": archive.display().to_string(),
            "sources": sources.iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
            "contact_ids": contact_ids,
            "replace_existing": force,
            "certificate_id": certificate_id,
        }),
    );
    match service_envelope(&tzap_share_create_json(&request.to_string())) {
        Ok(response) => {
            let entries = response["entries"].as_u64().unwrap_or(0);
            let bytes = response["bytes"].as_u64().unwrap_or(0);
            let recipients = response["recipients"].as_u64().unwrap_or(0);
            let recipient_warning_count = response["recipient_status_caveats"].as_u64().unwrap_or(0);
            if global.json {
                let mut output = json!({
                    "archive": archive.display().to_string(),
                    "format": "tzap",
                    "entries": entries,
                    "bytes": bytes,
                    "recipients": recipients,
                    "recipient_status_caveats": recipient_warning_count,
                });
                if let Some(signed) = response.get("signed") {
                    output["signed"] = signed.clone();
                    if let Some(certificate_id) = response.get("certificate_id") {
                        output["certificate_id"] = certificate_id.clone();
                    }
                }
                println!("{output}");
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
        Err(message) => {
            print_error_line(&global, format_args!("share failed: {message}"));
            ExitCode::FAILURE
        }
    }
}
