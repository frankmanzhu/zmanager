use super::support::*;
use super::*;
use crate::cli::options::{GlobalOptions, parse_global_option, take_value};
use crate::cli::usage::{
    CONTACT_HELP, command_usage_error, json_escape, print_error_line, print_help_stdout, print_success_line, wants_help,
};
use std::path::PathBuf;
use std::process::ExitCode;
use zmanager_core::local_identity_store::TzapLocalIdentityStore as _;

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

    let material = match zmanager_core::device_identity::generate_recipient_encryption_key() {
        Ok(material) => material,
        Err(error) => {
            print_stable_tzap_error("contact_keygen", &error.to_string(), &global);
            return ExitCode::FAILURE;
        }
    };
    let key_id = material.public_key_fingerprint.clone();
    let record = zmanager_core::local_identity_store::TzapRecipientEncryptionKeyRecord {
        key_id: key_id.clone(),
        algorithm: material.algorithm.to_owned(),
        public_key_fingerprint: material.public_key_fingerprint,
        public_key_der: material.public_key_spki_der,
        private_key_der: material.private_key_der,
        created_at_unix_seconds: current_unix_seconds(),
        label: Some(label),
    };
    let mut store = zmanager_core::local_identity_store::FileTzapLocalIdentityStore::new(&context.state_dir);
    let mut inventory = match store.load_inventory(&context.account_key) {
        Ok(inventory) => inventory,
        Err(error) => {
            print_stable_tzap_error("contact_keygen", &error.to_string(), &global);
            return ExitCode::FAILURE;
        }
    };
    inventory.recipient_encryption_keys.push(record);
    if let Err(error) = store.save_inventory(&context.account_key, inventory) {
        print_stable_tzap_error("contact_keygen", &error.to_string(), &global);
        return ExitCode::FAILURE;
    }

    if global.json {
        println!("{{\"generated\":true,\"recipient_key_id\":\"{}\"}}", json_escape(&key_id));
    } else {
        print_success_line(&global, format_args!("generated recipient key {key_id}"));
    }
    ExitCode::SUCCESS
}

pub(super) fn contact_list_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    let context = match parse_tzap_context_args(args, &mut global, "contact") {
        Ok(context) => context,
        Err(code) => return code,
    };
    let store = zmanager_core::local_identity_store::FileTzapLocalIdentityStore::new(&context.state_dir);
    match store.load_inventory(&context.account_key) {
        Ok(inventory) => {
            if global.json {
                print!("{{\"contacts\":[");
                for (index, contact) in inventory.contacts.iter().enumerate() {
                    if index > 0 {
                        print!(",");
                    }
                    print_contact_json(contact);
                }
                println!("]}}");
            } else if inventory.contacts.is_empty() {
                println!("no contacts");
            } else {
                for contact in inventory.contacts {
                    println!("{} {}", contact.contact_id, contact.display_name);
                }
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            print_error_line(&global, format_args!("contact list failed: {error}"));
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
    let mut store = zmanager_core::local_identity_store::FileTzapLocalIdentityStore::new(&context.state_dir);
    match store.load_inventory(&context.account_key) {
        Ok(mut inventory) => {
            let before = inventory.contacts.len();
            inventory.contacts.retain(|contact| contact.contact_id != contact_id);
            if let Err(error) = store.save_inventory(&context.account_key, inventory) {
                print_error_line(&global, format_args!("contact remove failed: {error}"));
                return ExitCode::FAILURE;
            }
            let removed =
                before > store.load_inventory(&context.account_key).map_or(0, |inventory| inventory.contacts.len());
            if global.json {
                println!("{{\"removed\":{removed}}}");
            } else if removed {
                print_success_line(&global, format_args!("removed contact {contact_id}"));
            } else {
                println!("contact not found: {contact_id}");
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            print_error_line(&global, format_args!("contact remove failed: {error}"));
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
                custom_root_cert_paths.push(PathBuf::from(
                    match take_value(args, &mut index, "--custom-trust-root-cert") {
                        Ok(value) => value,
                        Err(error) => return command_usage_error("contact", &error, &global),
                    },
                ));
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
    let custom_root_certificates_der = match load_custom_root_certificates(&custom_root_cert_paths, &mut custom_roots) {
        Ok(certificates) => certificates,
        Err(error) => {
            print_error_line(&global, format_args!("contact import failed: {error}"));
            return ExitCode::FAILURE;
        }
    };
    let options = zmanager_core::contact_card::TzapContactCardImportOptions {
        verifier_time_unix_seconds: current_unix_seconds().cast_signed(),
        official_root_pins: &zmanager_core::trust::OFFICIAL_TZAP_ROOT_PINS,
        official_root_certificates_der: Vec::new(),
        custom_trust_root_sha256: custom_roots,
        custom_trust_root_certificates_der: custom_root_certificates_der,
        certificate_profile_options: zmanager_core::trust::TzapCertificateProfileOptions::default(),
    };
    let mut store = zmanager_core::local_identity_store::FileTzapLocalIdentityStore::new(&context.state_dir);
    match zmanager_core::contact_card::import_tzap_contact_card(
        &mut store,
        &context.account_key,
        &card,
        &options,
        accepted.then(current_unix_seconds),
    ) {
        Ok(contact) => {
            if global.json {
                print_contact_json_line(&contact);
            } else {
                print_success_line(&global, format_args!("imported contact {}", contact.display_name));
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            print_stable_tzap_error("contact_import", &error.to_string(), &global);
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
    let store = zmanager_core::local_identity_store::FileTzapLocalIdentityStore::new(&context.state_dir);
    let request = zmanager_core::contact_card::TzapContactCardExportRequest {
        account_key: context.account_key,
        recipient_key_id,
        certificate_id,
        display_name,
        device_label,
        created_at_unix_seconds: current_unix_seconds(),
        expires_at_unix_seconds: None,
    };
    match zmanager_core::contact_card::export_tzap_contact_card(&store, &request) {
        Ok(card) => {
            if let Err(error) = write_json_file(&output, &card) {
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
        Err(error) => {
            print_stable_tzap_error("contact_export", &error.to_string(), &global);
            ExitCode::FAILURE
        }
    }
}
