use super::support::{parse_tzap_context_args, service_envelope, service_request};
use crate::cli::options::GlobalOptions;
use crate::cli::usage::{CERTS_HELP, print_error_line, print_help_stdout, wants_help};
use serde_json::Value;
use std::process::ExitCode;
use zmanager_tzap_hosted::tzap_service::tzap_certificate_inventory_json;

/// Reads the local TZAP certificate catalogue (`zm tzap certs`) — no
/// network, so it stays available in the default offline build and is the
/// way `--signing-identity` resolvers and scripts discover a certificate id.
pub(crate) fn certs_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    if wants_help(args) {
        print_help_stdout(CERTS_HELP, &global);
        return ExitCode::SUCCESS;
    }
    let context = match parse_tzap_context_args(args, &mut global, "certs") {
        Ok(context) => context,
        Err(code) => return code,
    };
    let request = service_request(&context, serde_json::json!({}));
    let response = match service_envelope(&tzap_certificate_inventory_json(&request.to_string())) {
        Ok(value) => value,
        Err(message) => {
            print_error_line(&global, format_args!("tzap certs failed: {message}"));
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
