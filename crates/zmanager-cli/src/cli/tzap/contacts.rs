use super::TzapCliContext;
use super::support::{
    current_unix_seconds, parse_tzap_context_args, parse_tzap_context_option, print_stable_tzap_error, read_json_argument, service_envelope, service_request,
    write_json_file,
};
use crate::cli::options::{GlobalOptions, parse_global_option, take_value};
use crate::cli::usage::{CONTACT_HELP, command_usage_error, json_escape, print_error_line, print_help_stdout, print_success_line, wants_help};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::ExitCode;
use zmanager_tzap_hosted::tzap_service::{
    tzap_contact_export_json, tzap_contact_import_json, tzap_contact_list_json, tzap_contact_remove_json, tzap_recipient_key_generate_json,
};

pub(crate) fn contact_command(args: &[String], global: GlobalOptions) -> ExitCode {
    if wants_help(args) || args.is_empty() {
        print_help_stdout(CONTACT_HELP, &global);
        return if args.is_empty() { ExitCode::from(2) } else { ExitCode::SUCCESS };
    }
    match args[0].as_str() {
        "keygen" => contact_keygen_command(&args[1..], global),
        "list" => contact_list_command(&args[1..], global),
        "remove" => contact_remove_command(&args[1..], global),
        "import" => contact_import_command(&args[1..], global),
        "export" => contact_export_command(&args[1..], global),
        command => command_usage_error("contact", &format!("unknown contact command: {command}"), &global),
    }
}

pub(crate) fn contact_keygen_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    let mut context = TzapCliContext::default();
    let mut label = "ZManager recipient key".to_owned();
    let mut index = 0usize;
    while index < args.len() {
        match parse_global_option(args, &mut index, &mut global) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(error) => return command_usage_error("contact", &error, &global),
        }
        match parse_tzap_context_option(args, &mut index, &mut context, "contact", &global) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(code) => return code,
        }
        match args[index].as_str() {
            "--label" => {
                label = match take_value(args, &mut index, "--label") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("contact", &error, &global),
                }
            }
            value => {
                return command_usage_error("contact", &format!("unknown contact keygen option: {value}"), &global);
            }
        }
    }

    let request = service_request(
        &context,
        json!({
            "label": label,
            "created_at_unix_seconds": current_unix_seconds(),
        }),
    );
    match service_envelope(&tzap_recipient_key_generate_json(&request.to_string())) {
        Ok(response) => {
            let key_id = response["recipient_key"]["key_id"].as_str().unwrap_or_default();
            if global.json {
                println!("{{\"generated\":true,\"recipient_key_id\":\"{}\"}}", json_escape(key_id));
            } else {
                print_success_line(&global, format_args!("generated recipient key {key_id}"));
            }
            ExitCode::SUCCESS
        }
        Err(message) => {
            print_stable_tzap_error("contact_keygen", &message, &global);
            ExitCode::FAILURE
        }
    }
}

pub(super) fn contact_list_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    let context = match parse_tzap_context_args(args, &mut global, "contact") {
        Ok(context) => context,
        Err(code) => return code,
    };
    let request = service_request(&context, json!({}));
    match service_envelope(&tzap_contact_list_json(&request.to_string())) {
        Ok(response) => {
            let contacts: &[Value] = response["contacts"].as_array().map_or(&[], |array| array.as_slice());
            if global.json {
                println!("{{\"contacts\":{}}}", serde_json::to_string(contacts).unwrap_or_else(|_| "[]".to_owned()));
            } else if contacts.is_empty() {
                println!("no contacts");
            } else {
                for contact in contacts {
                    let contact_id = contact["contact_id"].as_str().unwrap_or_default();
                    let display_name = contact["display_name"].as_str().unwrap_or_default();
                    println!("{contact_id} {display_name}");
                }
            }
            ExitCode::SUCCESS
        }
        Err(message) => {
            print_error_line(&global, format_args!("contact list failed: {message}"));
            ExitCode::FAILURE
        }
    }
}

pub(super) fn contact_remove_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    let mut context = TzapCliContext::default();
    let mut contact_id = None;
    let mut index = 0usize;
    while index < args.len() {
        match parse_global_option(args, &mut index, &mut global) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(error) => return command_usage_error("contact", &error, &global),
        }
        match parse_tzap_context_option(args, &mut index, &mut context, "contact", &global) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(code) => return code,
        }
        match args[index].as_str() {
            value if value.starts_with('-') => {
                return command_usage_error("contact", &format!("unknown contact option: {value}"), &global);
            }
            value if contact_id.is_none() => {
                contact_id = Some(value.to_owned());
                index += 1;
            }
            _ => return command_usage_error("contact", "too many arguments", &global),
        }
    }
    let Some(contact_id) = contact_id else {
        return command_usage_error("contact", "missing contact id", &global);
    };
    let request = service_request(&context, json!({"contact_id": contact_id.clone()}));
    match service_envelope(&tzap_contact_remove_json(&request.to_string())) {
        Ok(response) => {
            let removed = response["removed"].as_bool().unwrap_or(false);
            if global.json {
                println!("{{\"removed\":{removed}}}");
            } else if removed {
                print_success_line(&global, format_args!("removed contact {contact_id}"));
            } else {
                println!("contact not found: {contact_id}");
            }
            ExitCode::SUCCESS
        }
        Err(message) => {
            print_error_line(&global, format_args!("contact remove failed: {message}"));
            ExitCode::FAILURE
        }
    }
}

pub(super) fn contact_import_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    let mut context = TzapCliContext::default();
    let mut input = None;
    let mut accepted = false;
    let mut custom_roots = Vec::new();
    let mut custom_root_cert_paths = Vec::new();
    let mut index = 0usize;
    while index < args.len() {
        match parse_global_option(args, &mut index, &mut global) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(error) => return command_usage_error("contact", &error, &global),
        }
        match parse_tzap_context_option(args, &mut index, &mut context, "contact", &global) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(code) => return code,
        }
        match args[index].as_str() {
            "--accept" => {
                accepted = true;
                index += 1;
            }
            "--custom-trust-root" => {
                custom_roots.push(match take_value(args, &mut index, "--custom-trust-root") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("contact", &error, &global),
                });
            }
            "--custom-trust-root-cert" => {
                custom_root_cert_paths.push(PathBuf::from(match take_value(args, &mut index, "--custom-trust-root-cert") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("contact", &error, &global),
                }));
            }
            value if value.starts_with('-') => {
                return command_usage_error("contact", &format!("unknown contact option: {value}"), &global);
            }
            value if input.is_none() => {
                input = Some(value.to_owned());
                index += 1;
            }
            _ => return command_usage_error("contact", "too many arguments", &global),
        }
    }
    let Some(input) = input else {
        return command_usage_error("contact", "missing contact card", &global);
    };
    let card = match read_json_argument(&input) {
        Ok(card) => card,
        Err(error) => {
            print_error_line(&global, format_args!("contact import failed: {error}"));
            return ExitCode::FAILURE;
        }
    };
    let custom_root_cert_paths = custom_root_cert_paths.iter().map(|path| path.display().to_string()).collect::<Vec<_>>();
    let request = service_request(
        &context,
        json!({
            "verifier_time_unix_seconds": current_unix_seconds().cast_signed(),
            "custom_trust_root_sha256": custom_roots,
            "custom_trust_root_cert_paths": custom_root_cert_paths,
            "accept": accepted,
            "accepted_at_unix_seconds": accepted.then(current_unix_seconds),
            "contact_card": card,
        }),
    );
    match service_envelope(&tzap_contact_import_json(&request.to_string())) {
        Ok(response) => {
            let display_name = response["contact"]["display_name"].as_str().unwrap_or_default();
            if global.json {
                println!("{{\"contact\":{}}}", response["contact"]);
            } else {
                print_success_line(&global, format_args!("imported contact {display_name}"));
            }
            ExitCode::SUCCESS
        }
        Err(message) => {
            print_stable_tzap_error("contact_import", &message, &global);
            ExitCode::FAILURE
        }
    }
}

#[allow(clippy::too_many_lines)]
pub(super) fn contact_export_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    let mut context = TzapCliContext::default();
    let mut recipient_key_id = None;
    let mut certificate_id = None;
    let mut display_name = None;
    let mut device_label = "ZManager".to_owned();
    let mut output = None;
    let mut index = 0usize;
    while index < args.len() {
        match parse_global_option(args, &mut index, &mut global) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(error) => return command_usage_error("contact", &error, &global),
        }
        match parse_tzap_context_option(args, &mut index, &mut context, "contact", &global) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(code) => return code,
        }
        match args[index].as_str() {
            "--recipient-key-id" => {
                recipient_key_id = Some(match take_value(args, &mut index, "--recipient-key-id") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("contact", &error, &global),
                });
            }
            "--certificate-id" => {
                certificate_id = Some(match take_value(args, &mut index, "--certificate-id") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("contact", &error, &global),
                });
            }
            "--display-name" => {
                display_name = Some(match take_value(args, &mut index, "--display-name") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("contact", &error, &global),
                });
            }
            "--device-label" => {
                device_label = match take_value(args, &mut index, "--device-label") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("contact", &error, &global),
                };
            }
            "--output" => {
                output = Some(PathBuf::from(match take_value(args, &mut index, "--output") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("contact", &error, &global),
                }));
            }
            value => {
                return command_usage_error("contact", &format!("unknown contact option: {value}"), &global);
            }
        }
    }
    let Some(recipient_key_id) = recipient_key_id else {
        return command_usage_error("contact", "missing --recipient-key-id", &global);
    };
    let Some(certificate_id) = certificate_id else {
        return command_usage_error("contact", "missing --certificate-id", &global);
    };
    let Some(display_name) = display_name else {
        return command_usage_error("contact", "missing --display-name", &global);
    };
    let Some(output) = output else {
        return command_usage_error("contact", "missing --output", &global);
    };
    let request = service_request(
        &context,
        json!({
            "recipient_key_id": recipient_key_id,
            "certificate_id": certificate_id,
            "display_name": display_name,
            "device_label": device_label,
            "created_at_unix_seconds": current_unix_seconds(),
        }),
    );
    match service_envelope(&tzap_contact_export_json(&request.to_string())) {
        Ok(response) => {
            let Some(card) = response.get("contact_card") else {
                print_stable_tzap_error("contact_export", "service response is missing the contact card", &global);
                return ExitCode::FAILURE;
            };
            if let Err(error) = write_json_file(&output, card) {
                print_error_line(&global, format_args!("contact export failed: {error}"));
                return ExitCode::FAILURE;
            }
            if global.json {
                println!("{{\"exported\":true,\"output\":\"{}\"}}", json_escape(&output.display().to_string()));
            } else {
                print_success_line(&global, format_args!("exported {}", output.display()));
            }
            ExitCode::SUCCESS
        }
        Err(message) => {
            print_stable_tzap_error("contact_export", &message, &global);
            ExitCode::FAILURE
        }
    }
}
