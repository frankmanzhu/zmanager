use super::auth::*;
use super::hosted::*;
use super::support::*;
use crate::cli::options::GlobalOptions;
use crate::cli::usage::{CERT_HELP, ME_HELP, command_usage_error, print_error_line, print_help_stdout, wants_help};
use serde_json::json;
use std::process::ExitCode;
use zmanager_core::local_identity_store::TzapLocalIdentityStore as _;

pub(crate) fn me_command(args: &[String], global: GlobalOptions) -> ExitCode {
    if wants_help(args) {
        print_help_stdout(ME_HELP, &global);
        return ExitCode::SUCCESS;
    }
    auth_status_command(args, global)
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
        return run_hosted_cert_enroll(&options, &global);
    }
    run_local_cert_operation("cert_enroll", &options.context, &global, |store, session, options| {
        zmanager_core::local_tzap_service::enroll_local_certificate(store, session, options).map(|certificate| {
            json!({
                "ok": true,
                "operation": "cert_enroll",
                "certificate": certificate_summary_value(&certificate),
            })
        })
    })
}

pub(super) fn cert_renew_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    let options = match parse_hosted_cert_renew_args(args, &mut global) {
        Ok(options) => options,
        Err(code) => return code,
    };
    if options.service_base_url.is_some() {
        return run_hosted_cert_renew(&options, &global);
    }
    let certificate_id = options.certificate_id.as_deref().unwrap_or_default();
    run_local_cert_operation("cert_renew", &options.context, &global, |store, session, local_options| {
        zmanager_core::local_tzap_service::renew_local_certificate(store, session, local_options, certificate_id).map(
            |certificate| {
                json!({
                    "ok": true,
                    "operation": "cert_renew",
                    "certificate": certificate_summary_value(&certificate),
                })
            },
        )
    })
}

pub(super) fn cert_revoke_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    let (context, certificate_id) = match parse_cert_id_operation_args(args, &mut global, "cert") {
        Ok(parsed) => parsed,
        Err(code) => return code,
    };
    run_local_cert_operation("cert_revoke", &context, &global, |store, session, options| {
        zmanager_core::local_tzap_service::revoke_local_certificate(store, session, options, &certificate_id).map(
            |completion| {
                json!({
                    "ok": true,
                    "operation": "cert_revoke",
                    "completion": retirement_completion_label(completion),
                })
            },
        )
    })
}

pub(super) fn cert_list_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    let context = match parse_tzap_context_args(args, &mut global, "cert") {
        Ok(context) => context,
        Err(code) => return code,
    };
    let store = zmanager_core::local_identity_store::FileTzapLocalIdentityStore::new(&context.state_dir);
    match store.load_inventory(&context.account_key) {
        Ok(inventory) => {
            if global.json {
                print!("{{\"certificates\":[");
                for (index, cert) in inventory.enrolled_certificates.iter().enumerate() {
                    if index > 0 {
                        print!(",");
                    }
                    print!("{}", certificate_summary_value(cert));
                }
                println!("]}}");
            } else if inventory.enrolled_certificates.is_empty() {
                println!("no local certificates");
            } else {
                for cert in inventory.enrolled_certificates {
                    println!("{} {} {}", cert.certificate_id, cert.state.as_str(), cert.certificate_sha256);
                }
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            print_error_line(&global, format_args!("cert list failed: {error}"));
            ExitCode::FAILURE
        }
    }
}
