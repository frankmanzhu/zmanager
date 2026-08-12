use super::TzapCliContext;
use super::support::{current_unix_seconds, parse_tzap_context_option, print_stable_tzap_error, read_json_argument, service_envelope, service_request, write_json_file};
use crate::cli::options::{GlobalOptions, parse_global_option, take_value};
use crate::cli::usage::{SIGN_HELP, VERIFY_HELP, command_usage_error, json_escape, json_optional_string, print_error_line, print_help_stdout, print_success_line, wants_help};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::ExitCode;
use zmanager_core::tzap_service::tzap_document_verify_json;

pub(crate) fn sign_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    if wants_help(args) {
        print_help_stdout(SIGN_HELP, &global);
        return ExitCode::SUCCESS;
    }
    let mut context = TzapCliContext::default();
    let mut input = None;
    let mut output = None;
    let mut certificate_id = None;
    let mut claimed_signing_time = None;
    let mut index = 0usize;
    while index < args.len() {
        match parse_global_option(args, &mut index, &mut global) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(error) => return command_usage_error("sign", &error, &global),
        }
        match parse_tzap_context_option(args, &mut index, &mut context, "sign", &global) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(code) => return code,
        }
        match args[index].as_str() {
            "--certificate-id" => {
                certificate_id = Some(match take_value(args, &mut index, "--certificate-id") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("sign", &error, &global),
                });
            }
            "--output" => {
                output = Some(PathBuf::from(match take_value(args, &mut index, "--output") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("sign", &error, &global),
                }));
            }
            "--claimed-signing-time" => {
                claimed_signing_time = Some(match take_value(args, &mut index, "--claimed-signing-time") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("sign", &error, &global),
                });
            }
            value if value.starts_with('-') => {
                return command_usage_error("sign", &format!("unknown sign option: {value}"), &global);
            }
            value if input.is_none() => {
                input = Some(value.to_owned());
                index += 1;
            }
            _ => return command_usage_error("sign", "too many arguments", &global),
        }
    }
    let Some(input) = input else {
        return command_usage_error("sign", "missing input", &global);
    };
    let Some(certificate_id) = certificate_id else {
        return command_usage_error("sign", "missing --certificate-id", &global);
    };
    let Some(output) = output else {
        return command_usage_error("sign", "missing --output", &global);
    };
    let payload = match read_json_argument(&input) {
        Ok(payload) => payload,
        Err(error) => {
            print_error_line(&global, format_args!("sign failed: {error}"));
            return ExitCode::FAILURE;
        }
    };
    let request = service_request(
        &context,
        json!({
            "certificate_id": certificate_id,
            "claimed_signing_time": claimed_signing_time,
            "payload": payload,
        }),
    );
    match service_envelope(&zmanager_core::tzap_service::tzap_document_sign_json(&request.to_string())) {
        Ok(response) => {
            let Some(envelope) = response.get("envelope") else {
                print_stable_tzap_error("sign", "service response is missing the envelope", &global);
                return ExitCode::FAILURE;
            };
            if let Err(error) = write_json_file(&output, envelope) {
                print_error_line(&global, format_args!("sign failed: {error}"));
                return ExitCode::FAILURE;
            }
            if global.json {
                println!("{{\"signed\":true,\"output\":\"{}\"}}", json_escape(&output.display().to_string()));
            } else {
                print_success_line(&global, format_args!("signed {}", output.display()));
            }
            ExitCode::SUCCESS
        }
        Err(message) => {
            print_stable_tzap_error("sign", &message, &global);
            ExitCode::FAILURE
        }
    }
}

#[allow(clippy::too_many_lines)]
pub(crate) fn verify_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    if wants_help(args) {
        print_help_stdout(VERIFY_HELP, &global);
        return ExitCode::SUCCESS;
    }
    let mut input = None;
    let mut custom_roots = Vec::new();
    let mut custom_root_cert_paths = Vec::new();
    let mut status_response_path = None;
    let mut verifier_time = current_unix_seconds().cast_signed();
    let mut index = 0usize;
    while index < args.len() {
        match parse_global_option(args, &mut index, &mut global) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(error) => return command_usage_error("verify", &error, &global),
        }
        match args[index].as_str() {
            "--custom-trust-root" => {
                custom_roots.push(match take_value(args, &mut index, "--custom-trust-root") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("verify", &error, &global),
                });
            }
            "--custom-trust-root-cert" => {
                custom_root_cert_paths.push(PathBuf::from(match take_value(args, &mut index, "--custom-trust-root-cert") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("verify", &error, &global),
                }));
            }
            "--status-response" => {
                status_response_path = Some(match take_value(args, &mut index, "--status-response") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("verify", &error, &global),
                });
            }
            "--time" => {
                let value = match take_value(args, &mut index, "--time") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("verify", &error, &global),
                };
                verifier_time = match value.parse::<i64>() {
                    Ok(value) => value,
                    Err(_) => {
                        return command_usage_error("verify", "--time must be a unix timestamp", &global);
                    }
                };
            }
            value if value.starts_with('-') => {
                return command_usage_error("verify", &format!("unknown verify option: {value}"), &global);
            }
            value if input.is_none() => {
                input = Some(value.to_owned());
                index += 1;
            }
            _ => return command_usage_error("verify", "too many arguments", &global),
        }
    }
    let Some(input) = input else {
        return command_usage_error("verify", "missing input", &global);
    };
    let envelope = match read_json_argument(&input) {
        Ok(envelope) => envelope,
        Err(error) => {
            print_error_line(&global, format_args!("verify failed: {error}"));
            return ExitCode::FAILURE;
        }
    };
    let status_response = match status_response_path.as_deref() {
        Some(path) => {
            let value = match read_json_argument(path) {
                Ok(value) => value,
                Err(error) => {
                    print_error_line(&global, format_args!("verify status failed: {error}"));
                    return ExitCode::FAILURE;
                }
            };
            Some(value)
        }
        None => None,
    };
    let custom_root_cert_paths = custom_root_cert_paths.iter().map(|path| path.display().to_string()).collect::<Vec<_>>();
    let mut request = service_request(
        &TzapCliContext::default(),
        json!({
            "verifier_time_unix_seconds": verifier_time,
            "custom_trust_root_sha256": custom_roots,
            "custom_trust_root_cert_paths": custom_root_cert_paths,
            "envelope": envelope,
        }),
    );
    if let Some(status_response) = status_response {
        request["mode"] = json!("valid_now");
        request["status_response"] = status_response;
    }
    // The verify endpoint's `ok` flag is the verification outcome, not the
    // request status: an invalid document is a successful call that reports
    // `state: "invalid"`. Treat responses carrying `state` as results and
    // only the `{ok: false, message}` envelopes as failures.
    let response = tzap_document_verify_json(&request.to_string());
    let response: Value = match serde_json::from_str(&response) {
        Ok(value) => value,
        Err(error) => {
            print_error_line(&global, format_args!("verify failed: invalid service response: {error}"));
            return ExitCode::FAILURE;
        }
    };
    if response.get("state").is_none() {
        let message = response["message"].as_str().unwrap_or("service request failed");
        print_error_line(&global, format_args!("verify failed: {message}"));
        return ExitCode::FAILURE;
    }
    let state = response["state"].as_str().unwrap_or_default();
    let trust_anchor_type = response["trust_anchor_type"].as_str().unwrap_or_default();
    let reason = response["reason"].as_str();
    let root_certificate_sha256 = response["root_certificate_sha256"].as_str();
    if global.json {
        println!(
            "{{\"state\":\"{}\",\"trust_anchor_type\":\"{}\",\"reason\":{},\"root_certificate_sha256\":{}}}",
            json_escape(state),
            json_escape(trust_anchor_type),
            json_optional_string(reason),
            json_optional_string(root_certificate_sha256)
        );
    } else {
        println!("{state} ({trust_anchor_type})");
        if let Some(reason) = reason {
            println!("{reason}");
        }
    }
    if state == "invalid" { ExitCode::FAILURE } else { ExitCode::SUCCESS }
}
