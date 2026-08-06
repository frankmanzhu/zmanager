use super::hosted::*;
use super::support::*;
use super::*;
use crate::cli::options::{GlobalOptions, parse_global_option, take_value};
use crate::cli::usage::{DEVICE_HELP, command_usage_error, print_help_stdout, print_success_line, wants_help};
use serde_json::json;
use std::process::ExitCode;

pub(crate) fn device_command(args: &[String], global: GlobalOptions) -> ExitCode {
    if wants_help(args) || args.is_empty() {
        print_help_stdout(DEVICE_HELP, &global);
        return if args.is_empty() { ExitCode::from(2) } else { ExitCode::SUCCESS };
    }
    match args[0].as_str() {
        "retire" => device_retire_command(&args[1..], global),
        "revoke" => device_revoke_command(&args[1..], global),
        command => command_usage_error("device", &format!("unknown device command: {command}"), &global),
    }
}

pub(super) fn device_retire_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    let context = match parse_tzap_context_args(args, &mut global, "device") {
        Ok(context) => context,
        Err(code) => return code,
    };
    run_local_cert_operation("device_retire", &context, &global, |store, session, options| {
        zmanager_core::local_tzap_service::retire_local_device(store, session, options).map(|report| {
            json!({
                "ok": true,
                "operation": "device_retire",
                "completion": retirement_completion_label(report.completion),
                "attempted_sign_device_ids": report.attempted_sign_device_ids,
            })
        })
    })
}

pub(super) fn device_revoke_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    let mut context = TzapCliContext::default();
    let mut sign_device_id = None;
    let mut service_base_url = None;
    let mut index = 0usize;
    while index < args.len() {
        match parse_global_option(args, &mut index, &mut global) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(error) => return command_usage_error("device", &error, &global),
        }
        match parse_tzap_context_option(args, &mut index, &mut context, "device", &global) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(code) => return code,
        }
        match args[index].as_str() {
            "--device-id" => {
                sign_device_id = Some(match take_value(args, &mut index, "--device-id") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("device", &error, &global),
                });
            }
            "--service-base-url" => {
                service_base_url = Some(match take_value(args, &mut index, "--service-base-url") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("device", &error, &global),
                });
            }
            other => {
                return command_usage_error("device", &format!("unknown device option: {other}"), &global);
            }
        }
    }
    let Some(sign_device_id) = sign_device_id else {
        return command_usage_error("device", "missing --device-id", &global);
    };
    let sign_base_url = service_base_url.unwrap_or_else(|| zmanager_core::auth_client::SIGN_TZAP_BASE_URL.to_owned());
    let session_store = FileTzapSessionStore::new(&context.state_dir);
    let Some(session) = session_store.load_session(&context.account_key) else {
        print_stable_tzap_error("device_revoke", MISSING_TZAP_SESSION, &global);
        return ExitCode::FAILURE;
    };
    let transport = CliHttpJsonTransport;
    let lifecycle = zmanager_core::certificate_lifecycle::TzapCertificateLifecycleClient::new(
        &sign_base_url,
        zmanager_core::auth_client::LOGIN_TZAP_BASE_URL,
        &transport,
    );
    match lifecycle.revoke_personal_device(&session, &sign_device_id) {
        Ok(completion) => {
            if global.json {
                println!(
                    "{}",
                    json!({
                        "ok": true,
                        "operation": "device_revoke",
                        "completion": retirement_completion_label(completion),
                    })
                );
            } else {
                print_success_line(&global, format_args!("device_revoke complete"));
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            print_stable_tzap_error("device_revoke", &error.to_string(), &global);
            ExitCode::FAILURE
        }
    }
}
