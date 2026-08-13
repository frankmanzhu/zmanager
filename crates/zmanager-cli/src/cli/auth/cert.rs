#[cfg(feature = "tzap-online")]
use super::auth::auth_status_command;
use super::hosted::{parse_cert_enroll_args, parse_hosted_cert_renew_args};
#[cfg(feature = "tzap-online")]
use super::hosted::{run_hosted_cert_enroll, run_hosted_cert_renew};
use super::support::{parse_cert_id_operation_args, parse_tzap_context_args, print_stable_tzap_error, service_envelope, service_request};
use crate::cli::options::GlobalOptions;
#[cfg(feature = "tzap-online")]
use crate::cli::usage::ME_HELP;
use crate::cli::usage::{CERT_HELP, command_usage_error, print_error_line, print_help_stdout, print_success_line, wants_help};
use serde_json::{Value, json};
use std::process::ExitCode;
use zmanager_core::tzap_service::{tzap_cert_enroll_json, tzap_cert_renew_json, tzap_cert_revoke_json, tzap_certificate_inventory_json};

#[cfg(feature = "tzap-online")]
pub(crate) fn me_command(args: &[String], global: GlobalOptions) -> ExitCode {
    #[cfg(not(feature = "tzap-online"))]
    {
        return super::unavailable::hosted_command(args, global);
    }
    #[cfg(feature = "tzap-online")]
    {
        if wants_help(args) {
            print_help_stdout(ME_HELP, &global);
            return ExitCode::SUCCESS;
        }
        auth_status_command(args, global)
    }
}
pub(crate) fn cert_command(args: &[String], global: GlobalOptions) -> ExitCode {
    if wants_help(args) || args.is_empty() {
        print_help_stdout(CERT_HELP, &global);
        return if args.is_empty() { ExitCode::from(2) } else { ExitCode::SUCCESS };
    }
    match args[0].as_str() {
        "list" => cert_list_command(&args[1..], global),
        "enroll" => cert_enroll_command(&args[1..], global),
        "renew" => cert_renew_command(&args[1..], global),
        "revoke" => cert_revoke_command(&args[1..], global),
        command => command_usage_error("cert", &format!("unknown cert command: {command}"), &global),
    }
}

pub(super) fn cert_enroll_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    let options = match parse_cert_enroll_args(args, &mut global) {
        Ok(options) => options,
        Err(code) => return code,
    };
    if options.service_base_url.is_some() {
        #[cfg(not(feature = "tzap-online"))]
        return super::unavailable::hosted_command(args, global);
        #[cfg(feature = "tzap-online")]
        return run_hosted_cert_enroll(&options, &global);
    }
    let request = service_request(&options.context, json!({}));
    run_local_tzap_service_command("cert_enroll", &tzap_cert_enroll_json(&request.to_string()), &global)
}

pub(super) fn cert_renew_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    let options = match parse_hosted_cert_renew_args(args, &mut global) {
        Ok(options) => options,
        Err(code) => return code,
    };
    if options.service_base_url.is_some() {
        #[cfg(not(feature = "tzap-online"))]
        return super::unavailable::hosted_command(args, global);
        #[cfg(feature = "tzap-online")]
        return run_hosted_cert_renew(&options, &global);
    }
    let request = service_request(&options.context, json!({"certificate_id": options.certificate_id.unwrap_or_default()}));
    run_local_tzap_service_command("cert_renew", &tzap_cert_renew_json(&request.to_string()), &global)
}

pub(super) fn cert_revoke_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    let (context, certificate_id) = match parse_cert_id_operation_args(args, &mut global, "cert") {
        Ok(parsed) => parsed,
        Err(code) => return code,
    };
    let request = service_request(&context, json!({"certificate_id": certificate_id}));
    run_local_tzap_service_command("cert_revoke", &tzap_cert_revoke_json(&request.to_string()), &global)
}

pub(super) fn cert_list_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    let context = match parse_tzap_context_args(args, &mut global, "cert") {
        Ok(context) => context,
        Err(code) => return code,
    };
    let request = service_request(&context, json!({}));
    let response = match service_envelope(&tzap_certificate_inventory_json(&request.to_string())) {
        Ok(value) => value,
        Err(message) => {
            print_error_line(&global, format_args!("cert list failed: {message}"));
            return ExitCode::FAILURE;
        }
    };
    let certificates: &[Value] = response["inventory"]["certificates"].as_array().map_or(&[], |array| array.as_slice());
    if global.json {
        println!("{{\"certificates\":{}}}", serde_json::to_string(certificates).unwrap_or_else(|_| "[]".to_owned()));
    } else if certificates.is_empty() {
        println!("no local certificates");
    } else {
        for certificate in certificates {
            let certificate_id = certificate["certificate_id"].as_str().unwrap_or_default();
            let state = certificate["state"].as_str().unwrap_or_default();
            let sha256 = certificate["certificate_sha256"].as_str().unwrap_or_default();
            println!("{certificate_id} {state} {sha256}");
        }
    }
    ExitCode::SUCCESS
}

/// Runs a local tzap JSON service operation that requires a session and
/// renders the service envelope unchanged (CR-113: the CLI delegates the
/// local cert operations to `tzap_service`; the envelopes match the CLI's
/// prior output shapes).
fn run_local_tzap_service_command(operation: &str, response: &str, global: &GlobalOptions) -> ExitCode {
    match service_envelope(response) {
        Ok(value) => {
            if global.json {
                println!("{value}");
            } else {
                print_success_line(global, format_args!("{operation} complete"));
            }
            ExitCode::SUCCESS
        }
        Err(message) => {
            print_stable_tzap_error(operation, &message, global);
            ExitCode::FAILURE
        }
    }
}
