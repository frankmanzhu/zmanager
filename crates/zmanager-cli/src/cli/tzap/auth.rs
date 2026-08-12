use super::support::{
    callback_url_parameter, exchange_handoff_code, parse_environment_option, parse_tzap_context_args, parse_tzap_context_option, print_session_summary_json, print_stable_tzap_error,
    read_bytes_argument, service_envelope, service_request,
};
use super::{AUTH_PENDING_FILE, AuthEndpointOptions, DEFAULT_TZAP_CLIENT_ID, TzapCliContext};
use crate::cli::options::{GlobalOptions, parse_global_option, take_value};
use crate::cli::usage::{AUTH_HELP, command_usage_error, json_escape, print_error_line, print_help_stdout, print_success_line, wants_help};
use serde_json::{Value, json};
use std::fs;
use std::process::ExitCode;
use zmanager_core::tzap_service::{tzap_auth_account_url_json, tzap_auth_callback_json, tzap_auth_forget_json, tzap_auth_login_json, tzap_auth_status_json};

pub(crate) fn auth_command(args: &[String], global: GlobalOptions) -> ExitCode {
    if wants_help(args) || args.is_empty() {
        print_help_stdout(AUTH_HELP, &global);
        return if args.is_empty() { ExitCode::from(2) } else { ExitCode::SUCCESS };
    }
    match args[0].as_str() {
        "login" => auth_login_command(&args[1..], global),
        "callback" => auth_callback_command(&args[1..], global),
        "status" => auth_status_command(&args[1..], global),
        "forget" => auth_forget_command(&args[1..], global),
        "account" => auth_account_command(&args[1..], global),
        command => command_usage_error("auth", &format!("unknown auth command: {command}"), &global),
    }
}

#[allow(clippy::too_many_lines)]
pub(super) fn auth_login_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    let mut context = TzapCliContext::default();
    let mut endpoints = AuthEndpointOptions::default();
    let mut print_url = false;
    let mut index = 0usize;
    while index < args.len() {
        match parse_global_option(args, &mut index, &mut global) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(error) => return command_usage_error("auth", &error, &global),
        }
        match parse_tzap_context_option(args, &mut index, &mut context, "auth", &global) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(code) => return code,
        }
        match args[index].as_str() {
            "--print-url" => {
                print_url = true;
                index += 1;
            }
            "--environment" => {
                if let Err(code) = parse_environment_option(args, &mut index, &mut endpoints.environment, &global) {
                    return code;
                }
            }
            "--auth-base-url" => {
                endpoints.auth_base_url = Some(match take_value(args, &mut index, "--auth-base-url") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("auth", &error, &global),
                });
            }
            "--account-base-url" => {
                endpoints.account_base_url = Some(match take_value(args, &mut index, "--account-base-url") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("auth", &error, &global),
                });
            }
            "--client-id" => {
                endpoints.client_id = match take_value(args, &mut index, "--client-id") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("auth", &error, &global),
                };
            }
            "--redirect-uri" => {
                endpoints.redirect_uri = match take_value(args, &mut index, "--redirect-uri") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("auth", &error, &global),
                };
            }
            "--provider" => {
                endpoints.provider_id = match take_value(args, &mut index, "--provider") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("auth", &error, &global),
                };
            }
            "--org-id" => {
                endpoints.org_id = Some(match take_value(args, &mut index, "--org-id") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("auth", &error, &global),
                });
            }
            other => {
                return command_usage_error("auth", &format!("unknown auth option: {other}"), &global);
            }
        }
    }

    let request = service_request(
        &context,
        json!({
            "environment": match endpoints.environment {
                zmanager_core::auth_client::TzapHostedAuthEnvironment::Local => "local",
                zmanager_core::auth_client::TzapHostedAuthEnvironment::Staging => "staging",
                zmanager_core::auth_client::TzapHostedAuthEnvironment::Prod => "prod",
            },
            "client_id": endpoints.client_id,
            "redirect_uri": endpoints.redirect_uri,
            "provider_id": endpoints.provider_id,
            "auth_base_url": endpoints.auth_base_url,
            "account_base_url": endpoints.account_base_url,
            "org_id": endpoints.org_id,
        }),
    );
    let response = match service_envelope(&tzap_auth_login_json(&request.to_string())) {
        Ok(value) => value,
        Err(message) => {
            print_error_line(&global, format_args!("auth login failed: {message}"));
            return ExitCode::FAILURE;
        }
    };
    let url = response["launch_url"].as_str().unwrap_or_default().to_owned();
    let state = response["state"].as_str().unwrap_or_default().to_owned();
    let expires_at_unix_seconds = response["expires_at_unix_seconds"].as_u64().unwrap_or(0);
    if global.json {
        println!("{{\"status\":\"pending\",\"launch_url\":\"{}\",\"state\":\"{}\",\"expires_at_unix_seconds\":{}}}", json_escape(&url), json_escape(&state), expires_at_unix_seconds);
    } else if print_url {
        println!("{url}");
    } else {
        match open_browser(&url) {
            Ok(()) => println!("opened the login page in your browser (use --print-url to print the URL instead)"),
            Err(error) => {
                // Never strand the user: fall back to printing the URL.
                println!("{url}");
                eprintln!("note: could not open a browser ({error})");
            }
        }
    }
    ExitCode::SUCCESS
}

/// Hands a URL to the platform's default browser.
pub(super) fn open_browser(url: &str) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open").arg(url).status().map(|_| ())
    }
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd").args(["/c", "start", "", url]).status().map(|_| ())
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        std::process::Command::new("xdg-open").arg(url).status().map(|_| ())
    }
}

#[allow(clippy::too_many_lines)]
pub(super) fn auth_callback_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    let mut context = TzapCliContext::default();
    let mut state = None;
    let mut redirect_uri = None;
    let mut callback_url = None;
    let mut handoff_code = None;
    let mut relay_body_path = None;
    let mut auth_base_url = None;
    let mut client_id = None;
    let mut index = 0usize;
    while index < args.len() {
        match parse_global_option(args, &mut index, &mut global) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(error) => return command_usage_error("auth", &error, &global),
        }
        match parse_tzap_context_option(args, &mut index, &mut context, "auth", &global) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(code) => return code,
        }
        match args[index].as_str() {
            "--state" => {
                state = Some(match take_value(args, &mut index, "--state") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("auth", &error, &global),
                });
            }
            "--redirect-uri" => {
                redirect_uri = Some(match take_value(args, &mut index, "--redirect-uri") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("auth", &error, &global),
                });
            }
            "--auth-base-url" => {
                auth_base_url = Some(match take_value(args, &mut index, "--auth-base-url") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("auth", &error, &global),
                });
            }
            "--client-id" => {
                client_id = Some(match take_value(args, &mut index, "--client-id") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("auth", &error, &global),
                });
            }
            "--callback-url" => {
                callback_url = Some(match take_value(args, &mut index, "--callback-url") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("auth", &error, &global),
                });
            }
            "--handoff-code" => {
                handoff_code = Some(match take_value(args, &mut index, "--handoff-code") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("auth", &error, &global),
                });
            }
            "--relay-body" => {
                relay_body_path = Some(match take_value(args, &mut index, "--relay-body") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("auth", &error, &global),
                });
            }
            other => {
                return command_usage_error("auth", &format!("unknown auth option: {other}"), &global);
            }
        }
    }
    let pending = match zmanager_core::tzap_service_auth::load_pending_auth(&context.state_dir) {
        Ok(pending) => pending,
        Err(error) => {
            print_error_line(&global, format_args!("auth callback failed: {error}"));
            return ExitCode::FAILURE;
        }
    };
    let pending_metadata = zmanager_core::tzap_service_auth::load_pending_auth_metadata(&context.state_dir);
    if state.is_none() {
        state = callback_url.as_deref().and_then(|url| callback_url_parameter(url, "state"));
    }
    if handoff_code.is_none() {
        handoff_code = callback_url.as_deref().and_then(|url| callback_url_parameter(url, "handoff_code"));
    }
    let Some(state) = state else {
        return command_usage_error("auth", "missing --state or callback URL state", &global);
    };
    let redirect_uri = redirect_uri.unwrap_or_else(|| pending.redirect_uri.clone());
    let pkce_verifier = pending.pkce.verifier.clone();
    // The handoff-code exchange is a CLI convenience pre-step that produces
    // the relay body the JSON service's callback consumes (the FFI
    // consumers perform this exchange themselves).
    let relay_body = if let Some(relay_body_path) = relay_body_path {
        match read_bytes_argument(&relay_body_path) {
            Ok(bytes) => bytes,
            Err(error) => {
                print_error_line(&global, format_args!("auth callback failed: {error}"));
                return ExitCode::FAILURE;
            }
        }
    } else if let Some(handoff_code) = handoff_code {
        let exchange_base_url = auth_base_url.or(pending_metadata.auth_base_url).unwrap_or_else(|| zmanager_core::auth_client::LOCAL_HOSTED_AUTH_BASE_URL.to_owned());
        let exchange_client_id = client_id.or(pending_metadata.client_id).unwrap_or_else(|| DEFAULT_TZAP_CLIENT_ID.to_owned());
        match exchange_handoff_code(&exchange_base_url, &exchange_client_id, &redirect_uri, &state, &pkce_verifier, &handoff_code) {
            Ok(bytes) => bytes,
            Err(error) => {
                print_stable_tzap_error("auth_callback", &error, &global);
                return ExitCode::FAILURE;
            }
        }
    } else {
        return command_usage_error("auth", "missing --relay-body or handoff code", &global);
    };
    let request = service_request(
        &context,
        json!({
            "state": state,
            "redirect_uri": redirect_uri,
            "callback_url": callback_url,
            "relay_body": String::from_utf8_lossy(&relay_body),
        }),
    );
    let response = match service_envelope(&tzap_auth_callback_json(&request.to_string())) {
        Ok(value) => value,
        Err(message) => {
            print_stable_tzap_error("auth_callback", &message, &global);
            return ExitCode::FAILURE;
        }
    };
    let _ = fs::remove_file(context.state_dir.join(AUTH_PENDING_FILE));
    if let Some(session) = response.get("session") {
        print_session_summary_json(session, &global);
        ExitCode::SUCCESS
    } else {
        print_stable_tzap_error("auth_callback", "service response is missing the session", &global);
        ExitCode::FAILURE
    }
}

pub(super) fn auth_status_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    let context = match parse_tzap_context_args(args, &mut global, "auth") {
        Ok(context) => context,
        Err(code) => return code,
    };
    let request = service_request(&context, json!({}));
    let response = match service_envelope(&tzap_auth_status_json(&request.to_string())) {
        Ok(value) => value,
        Err(message) => {
            print_error_line(&global, format_args!("auth status failed: {message}"));
            return ExitCode::FAILURE;
        }
    };
    if let Some(session) = response.get("session") {
        print_session_summary_json(session, &global);
        ExitCode::SUCCESS
    } else {
        if global.json {
            println!("{{\"authenticated\":false}}");
        } else {
            println!("not signed in");
        }
        ExitCode::SUCCESS
    }
}

pub(super) fn auth_forget_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    let context = match parse_tzap_context_args(args, &mut global, "auth") {
        Ok(context) => context,
        Err(code) => return code,
    };
    let request = service_request(&context, json!({}));
    let response = match service_envelope(&tzap_auth_forget_json(&request.to_string())) {
        Ok(value) => value,
        Err(message) => {
            print_stable_tzap_error("auth_forget", &message, &global);
            return ExitCode::FAILURE;
        }
    };
    if response.get("forgotten").and_then(Value::as_bool).unwrap_or(false) {
        if global.json {
            println!("{{\"forgotten\":true}}");
        } else {
            print_success_line(&global, format_args!("local auth material forgotten"));
        }
    } else if global.json {
        println!("{{\"forgotten\":false}}");
    } else {
        println!("no local auth material to forget");
    }
    ExitCode::SUCCESS
}

pub(super) fn auth_account_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    let mut endpoints = AuthEndpointOptions::default();
    let mut index = 0usize;
    while index < args.len() {
        match parse_global_option(args, &mut index, &mut global) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(error) => return command_usage_error("auth", &error, &global),
        }
        match args[index].as_str() {
            "--environment" => {
                if let Err(code) = parse_environment_option(args, &mut index, &mut endpoints.environment, &global) {
                    return code;
                }
            }
            "--account-base-url" => {
                endpoints.account_base_url = Some(match take_value(args, &mut index, "--account-base-url") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("auth", &error, &global),
                });
            }
            "--client-id" => {
                endpoints.client_id = match take_value(args, &mut index, "--client-id") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("auth", &error, &global),
                };
            }
            "--redirect-uri" => {
                endpoints.redirect_uri = match take_value(args, &mut index, "--redirect-uri") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("auth", &error, &global),
                };
            }
            other => {
                return command_usage_error("auth", &format!("unknown auth option: {other}"), &global);
            }
        }
    }
    let request = json!({
        "environment": match endpoints.environment {
            zmanager_core::auth_client::TzapHostedAuthEnvironment::Local => "local",
            zmanager_core::auth_client::TzapHostedAuthEnvironment::Staging => "staging",
            zmanager_core::auth_client::TzapHostedAuthEnvironment::Prod => "prod",
        },
        "client_id": endpoints.client_id,
        "redirect_uri": endpoints.redirect_uri,
        "account_base_url": endpoints.account_base_url,
        "org_id": endpoints.org_id,
    });
    let response = match service_envelope(&tzap_auth_account_url_json(&request.to_string())) {
        Ok(value) => value,
        Err(message) => {
            print_error_line(&global, format_args!("auth account failed: {message}"));
            return ExitCode::FAILURE;
        }
    };
    let url = response["account_url"].as_str().unwrap_or_default();
    if global.json {
        println!("{{\"account_url\":\"{}\"}}", json_escape(url));
    } else {
        println!("{url}");
    }
    ExitCode::SUCCESS
}
