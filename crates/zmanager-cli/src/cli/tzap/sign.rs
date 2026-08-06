use super::support::*;
use super::*;
use crate::cli::options::{GlobalOptions, parse_global_option, take_value};
use crate::cli::usage::{
    SIGN_HELP, VERIFY_HELP, command_usage_error, json_escape, print_error_line, print_help_stdout, print_success_line,
    wants_help,
};
use std::path::PathBuf;
use std::process::ExitCode;

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
    let store = zmanager_core::local_identity_store::FileTzapLocalIdentityStore::new(&context.state_dir);
    let mut request = zmanager_core::document_signing::TzapDocumentSigningRequest::new(
        context.account_key,
        certificate_id,
        current_unix_seconds(),
    );
    request.claimed_signing_time = claimed_signing_time;
    match zmanager_core::document_signing::sign_tzap_document_payload(&store, &request, payload) {
        Ok(envelope) => {
            if let Err(error) = write_json_file(&output, &envelope) {
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
        Err(error) => {
            print_stable_tzap_error("sign", &error.to_string(), &global);
            ExitCode::FAILURE
        }
    }
}

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
                custom_root_cert_paths.push(PathBuf::from(
                    match take_value(args, &mut index, "--custom-trust-root-cert") {
                        Ok(value) => value,
                        Err(error) => return command_usage_error("verify", &error, &global),
                    },
                ));
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
    let bytes = match read_bytes_argument(&input) {
        Ok(bytes) => bytes,
        Err(error) => {
            print_error_line(&global, format_args!("verify failed: {error}"));
            return ExitCode::FAILURE;
        }
    };
    let custom_root_certificates_der = match load_custom_root_certificates(&custom_root_cert_paths, &mut custom_roots) {
        Ok(certificates) => certificates,
        Err(error) => {
            print_error_line(&global, format_args!("verify failed: {error}"));
            return ExitCode::FAILURE;
        }
    };
    let options = zmanager_core::document_verification::TzapOfflineVerificationOptions {
        verifier_time_unix_seconds: verifier_time,
        official_root_pins: &zmanager_core::trust::OFFICIAL_TZAP_ROOT_PINS,
        official_root_certificates_der: Vec::new(),
        custom_trust_root_sha256: custom_roots,
        custom_trust_root_certificates_der: custom_root_certificates_der,
        certificate_profile_options: zmanager_core::trust::TzapCertificateProfileOptions::default(),
    };
    let result = verify_document_bytes_with_optional_status(&bytes, &options, status_response_path.as_deref(), &global);
    print_verification_result(&result, &global);
    if result.state == zmanager_core::trust::TzapVerificationState::Invalid {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

pub(super) fn verify_document_bytes_with_optional_status(
    bytes: &[u8],
    options: &zmanager_core::document_verification::TzapOfflineVerificationOptions<'_>,
    status_response_path: Option<&str>,
    global: &GlobalOptions,
) -> zmanager_core::document_verification::TzapDocumentVerificationResult {
    let offline = zmanager_core::document_verification::verify_tzap_document_envelope_offline_json(bytes, options);
    let Some(status_response_path) = status_response_path else {
        return offline;
    };
    if offline.state == zmanager_core::trust::TzapVerificationState::Invalid {
        return offline;
    }

    let envelope = match zmanager_core::document_envelope::parse_tzap_document_envelope_json(bytes) {
        Ok(envelope) => envelope,
        Err(error) => {
            return zmanager_core::document_verification::TzapDocumentVerificationResult {
                state: zmanager_core::trust::TzapVerificationState::Invalid,
                trust_anchor_type: zmanager_core::trust::TzapTrustAnchorType::Untrusted,
                reason: Some(error.to_string()),
                root_certificate_sha256: None,
                public_metadata: None,
            };
        }
    };
    let status_value = match read_json_argument(status_response_path) {
        Ok(value) => value,
        Err(error) => {
            print_error_line(global, format_args!("verify status failed: {error}"));
            return zmanager_core::document_verification::TzapDocumentVerificationResult {
                state: zmanager_core::trust::TzapVerificationState::Invalid,
                reason: Some("status response JSON is invalid".to_owned()),
                ..offline
            };
        }
    };
    let status = match zmanager_core::status_client::TzapStatusResponse::from_json_value(&status_value) {
        Ok(status) => status,
        Err(error) => {
            print_error_line(global, format_args!("verify status failed: {error}"));
            return zmanager_core::document_verification::TzapDocumentVerificationResult {
                state: zmanager_core::trust::TzapVerificationState::Invalid,
                reason: Some(error.to_string()),
                ..offline
            };
        }
    };
    zmanager_core::status_client::verify_tzap_document_envelope_valid_now(&envelope, options, &status)
}
