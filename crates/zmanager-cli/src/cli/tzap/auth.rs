use super::support::*;
use super::*;
use crate::cli::options::{GlobalOptions, parse_global_option, take_value};
use crate::cli::usage::{
    AUTH_HELP, command_usage_error, json_escape, print_error_line, print_help_stdout, print_success_line, wants_help,
};
use std::fs;
use std::process::ExitCode;

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

    let mut tracker = zmanager_core::auth_client::TzapOAuthStateTracker::new();
    let pending = tracker.begin(endpoints.provider_id.clone(), endpoints.redirect_uri.clone(), current_unix_seconds());
    let mut config = zmanager_core::auth_client::TzapHostedAuthLaunchConfig::for_environment(
        endpoints.environment,
        endpoints.client_id,
        endpoints.redirect_uri,
    );
    if let Some(auth_base_url) = endpoints.auth_base_url {
        config.hosted_auth_base_url = auth_base_url;
    }
    if let Some(account_base_url) = endpoints.account_base_url {
        config.hosted_account_base_url = account_base_url;
    }
    config.selected_org_id = endpoints.org_id;
    if let Err(error) = save_pending_auth(&context.state_dir, &pending, &config) {
        print_error_line(&global, format_args!("auth login failed: {error}"));
        return ExitCode::FAILURE;
    }
    let url = match config.launch_url(&pending) {
        Ok(url) => url,
        Err(error) => {
            print_error_line(&global, format_args!("auth login failed: {error}"));
            return ExitCode::FAILURE;
        }
    };
    if global.json {
        println!(
            "{{\"status\":\"pending\",\"launch_url\":\"{}\",\"state\":\"{}\",\"expires_at_unix_seconds\":{}}}",
            json_escape(&url),
            json_escape(&pending.state),
            pending.created_at_unix_seconds.saturating_add(zmanager_core::auth_client::AUTH_HANDOFF_LIFETIME_SECONDS)
        );
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
    let pending = match load_pending_auth(&context.state_dir) {
        Ok(pending) => pending,
        Err(error) => {
            print_error_line(&global, format_args!("auth callback failed: {error}"));
            return ExitCode::FAILURE;
        }
    };
    let pending_metadata = load_pending_auth_metadata(&context.state_dir);
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
    let relay_body = if let Some(relay_body_path) = relay_body_path {
        match read_bytes_argument(&relay_body_path) {
            Ok(bytes) => bytes,
            Err(error) => {
                print_error_line(&global, format_args!("auth callback failed: {error}"));
                return ExitCode::FAILURE;
            }
        }
    } else if let Some(handoff_code) = handoff_code {
        let exchange_base_url = auth_base_url
            .or(pending_metadata.auth_base_url)
            .unwrap_or_else(|| zmanager_core::auth_client::LOCAL_HOSTED_AUTH_BASE_URL.to_owned());
        let exchange_client_id =
            client_id.or(pending_metadata.client_id).unwrap_or_else(|| DEFAULT_TZAP_CLIENT_ID.to_owned());
        match exchange_handoff_code(
            &exchange_base_url,
            &exchange_client_id,
            &redirect_uri,
            &state,
            &pkce_verifier,
            &handoff_code,
        ) {
            Ok(bytes) => bytes,
            Err(error) => {
                print_stable_tzap_error("auth_callback", &error, &global);
                return ExitCode::FAILURE;
            }
        }
    } else {
        return command_usage_error("auth", "missing --relay-body or handoff code", &global);
    };
    let mut tracker = zmanager_core::auth_client::TzapOAuthStateTracker::new();
    if let Err(error) = tracker.insert_pending(pending) {
        print_error_line(&global, format_args!("auth callback failed: {error}"));
        return ExitCode::FAILURE;
    }
    let callback = zmanager_core::auth_client::TzapHostedAuthCallback {
        state,
        redirect_uri,
        pkce_verifier,
        callback_url,
        relay_body,
    };
    let mut session_store = FileTzapSessionStore::new(&context.state_dir);
    match zmanager_core::auth_client::complete_hosted_auth_handoff(
        &mut tracker,
        &mut session_store,
        &context.account_key,
        &callback,
        current_unix_seconds(),
    ) {
        Ok(session) => {
            let _ = fs::remove_file(context.state_dir.join(AUTH_PENDING_FILE));
            print_session_summary(&session, &global);
            ExitCode::SUCCESS
        }
        Err(error) => {
            print_stable_tzap_error("auth_callback", &error.to_string(), &global);
            ExitCode::FAILURE
        }
    }
}

pub(super) fn auth_status_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    let context = match parse_tzap_context_args(args, &mut global, "auth") {
        Ok(context) => context,
        Err(code) => return code,
    };
    let store = FileTzapSessionStore::new(&context.state_dir);
    if let Some(session) = store.load_session(&context.account_key) {
        print_session_summary(&session, &global);
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
    let mut store = FileTzapSessionStore::new(&context.state_dir);
    if let Err(error) = store.clear_session(&context.account_key) {
        print_stable_tzap_error("auth_forget", &error.to_string(), &global);
        return ExitCode::FAILURE;
    }
    let _ = fs::remove_file(context.state_dir.join(AUTH_PENDING_FILE));
    if global.json {
        println!("{{\"forgotten\":true}}");
    } else {
        print_success_line(&global, format_args!("local auth material forgotten"));
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
    let mut config = zmanager_core::auth_client::TzapHostedAuthLaunchConfig::for_environment(
        endpoints.environment,
        endpoints.client_id,
        endpoints.redirect_uri,
    );
    if let Some(account_base_url) = endpoints.account_base_url {
        config.hosted_account_base_url = account_base_url;
    }
    let url = config.account_url();
    if global.json {
        println!("{{\"account_url\":\"{}\"}}", json_escape(&url));
    } else {
        println!("{url}");
    }
    ExitCode::SUCCESS
}
