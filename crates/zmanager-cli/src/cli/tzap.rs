use crate::cli::app::ProgressReporter;
use crate::cli::format::{TZAP_DEFAULT_RECOVERY_PERCENTAGE, TZAP_SINGLE_VOLUME_LOSS_TOLERANCE};
use crate::cli::options::{GlobalOptions, parse_global_option, take_value};
use crate::cli::planning::plan_sources;
use crate::cli::usage::{
    AUTH_HELP, CERT_HELP, CONTACT_HELP, DEVICE_HELP, ME_HELP, SHARE_HELP, SIGN_HELP, VERIFY_HELP, command_usage_error,
    json_escape, json_optional_string, print_error_line, print_help_stdout, print_success_line, wants_help,
};
use serde_json::{Value, json};
use std::env;
use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zmanager_core::auth_client::TzapSessionStore as _;
use zmanager_core::jobs::{CancellationToken, JobContext};
use zmanager_core::local_identity_store::TzapLocalIdentityStore as _;
const DEFAULT_TZAP_STATE_DIR_ENV: &str = "ZM_TZAP_STATE_DIR";
const DEFAULT_TZAP_STATE_HOME_CHILD: &str = ".zmanager/tzap";
const DEFAULT_TZAP_CLIENT_ID: &str = "zmanager-cli";
pub(crate) const DEFAULT_TZAP_REDIRECT_URI: &str = "tzap://auth/callback";
const DEFAULT_TZAP_PROVIDER_ID: &str = "hosted";
const AUTH_PENDING_FILE: &str = "auth-pending.json";
const AUTH_SESSION_FILE: &str = "auth-session.json";
const AUTH_SESSION_EXCHANGE_PATH: &str = "/auth/session/exchange";
const MISSING_TZAP_SESSION: &str = "no local TZAP session";
const DEFAULT_TZAP_CERT_VALIDITY_SECONDS: u64 = 90 * 24 * 60 * 60;
const STAGING_ENROLLMENT_KEY_LABEL: &str = "Hosted TZAP enrollment signing key";

#[derive(Debug, Clone)]
struct TzapCliContext {
    state_dir: PathBuf,
    account_key: String,
}

impl Default for TzapCliContext {
    fn default() -> Self {
        Self {
            state_dir: default_tzap_state_dir(),
            account_key: zmanager_core::local_identity_store::DEFAULT_IDENTITY_INVENTORY_ACCOUNT.to_owned(),
        }
    }
}

#[derive(Debug, Clone)]
struct AuthEndpointOptions {
    environment: zmanager_core::auth_client::TzapHostedAuthEnvironment,
    auth_base_url: Option<String>,
    account_base_url: Option<String>,
    client_id: String,
    redirect_uri: String,
    provider_id: String,
    org_id: Option<String>,
}

impl Default for AuthEndpointOptions {
    fn default() -> Self {
        Self {
            environment: zmanager_core::auth_client::TzapHostedAuthEnvironment::Prod,
            auth_base_url: None,
            account_base_url: None,
            client_id: DEFAULT_TZAP_CLIENT_ID.to_owned(),
            redirect_uri: DEFAULT_TZAP_REDIRECT_URI.to_owned(),
            provider_id: DEFAULT_TZAP_PROVIDER_ID.to_owned(),
            org_id: None,
        }
    }
}

#[derive(Debug, Clone)]
struct FileTzapSessionStore {
    path: PathBuf,
}

impl FileTzapSessionStore {
    fn new(state_dir: &Path) -> Self {
        Self { path: state_dir.join(AUTH_SESSION_FILE) }
    }
}

impl zmanager_core::auth_client::TzapSessionStore for FileTzapSessionStore {
    fn save_session(
        &mut self,
        account_key: &str,
        session: zmanager_core::auth_client::TzapSessionRecord,
    ) -> Result<(), zmanager_core::auth_client::TzapAuthError> {
        let mut root = read_json_file(&self.path).unwrap_or_else(|| json!({ "sessions": {} }));
        if !root.is_object() {
            root = json!({ "sessions": {} });
        }
        root["sessions"][account_key] = session_to_json(&session, true);
        write_secret_json_file(&self.path, &root).map_err(|error| zmanager_core::auth_client::TzapAuthError::Storage {
            message: format!("could not write {}: {error}", self.path.display()),
        })
    }

    fn load_session(&self, account_key: &str) -> Option<zmanager_core::auth_client::TzapSessionRecord> {
        let root = read_json_file(&self.path)?;
        session_from_json(root.get("sessions")?.get(account_key)?).ok()
    }

    fn clear_session(&mut self, account_key: &str) -> Result<(), zmanager_core::auth_client::TzapAuthError> {
        let Some(mut root) = read_json_file(&self.path) else {
            return Ok(());
        };
        if let Some(sessions) = root.get_mut("sessions").and_then(Value::as_object_mut) {
            sessions.remove(account_key);
        }
        write_secret_json_file(&self.path, &root).map_err(|error| zmanager_core::auth_client::TzapAuthError::Storage {
            message: format!("could not write {}: {error}", self.path.display()),
        })
    }
}
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
fn auth_login_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
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
fn open_browser(url: &str) -> std::io::Result<()> {
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
fn auth_callback_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
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

fn auth_status_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
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

fn auth_forget_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
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

fn auth_account_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
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

fn cert_enroll_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
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

fn cert_renew_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
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

fn cert_revoke_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
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

fn cert_list_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
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

fn device_retire_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
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

fn device_revoke_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
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

fn verify_document_bytes_with_optional_status(
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

fn contact_list_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
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

fn contact_remove_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
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

fn contact_import_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
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
fn contact_export_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
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
#[allow(clippy::too_many_lines)]
pub(crate) fn share_command(args: &[String], mut global: GlobalOptions) -> ExitCode {
    if wants_help(args) {
        print_help_stdout(SHARE_HELP, &global);
        return ExitCode::SUCCESS;
    }
    let mut context = TzapCliContext::default();
    let mut archive = None;
    let mut sources = Vec::new();
    let mut contact_ids = Vec::new();
    let mut certificate_id = None;
    let mut force = false;
    let mut index = 0usize;
    while index < args.len() {
        match parse_global_option(args, &mut index, &mut global) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(error) => return command_usage_error("share", &error, &global),
        }
        match parse_tzap_context_option(args, &mut index, &mut context, "share", &global) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(code) => return code,
        }
        match args[index].as_str() {
            "--contact" => contact_ids.push(match take_value(args, &mut index, "--contact") {
                Ok(value) => value,
                Err(error) => return command_usage_error("share", &error, &global),
            }),
            "--certificate-id" => {
                certificate_id = Some(match take_value(args, &mut index, "--certificate-id") {
                    Ok(value) => value,
                    Err(error) => return command_usage_error("share", &error, &global),
                });
            }
            "--force" => {
                force = true;
                index += 1;
            }
            value if value.starts_with('-') => {
                return command_usage_error("share", &format!("unknown share option: {value}"), &global);
            }
            value if archive.is_none() => {
                archive = Some(PathBuf::from(value));
                index += 1;
            }
            value => {
                sources.push(PathBuf::from(value));
                index += 1;
            }
        }
    }
    let Some(archive) = archive else {
        return command_usage_error("share", "missing archive", &global);
    };
    if sources.is_empty() {
        return command_usage_error("share", "missing source path", &global);
    }
    let Some(certificate_id) = certificate_id else {
        return command_usage_error("share", "missing --certificate-id", &global);
    };
    let store = zmanager_core::local_identity_store::FileTzapLocalIdentityStore::new(&context.state_dir);
    let x509_signing =
        match local_tzap_x509_signing_options(&store, &context.account_key, &certificate_id, current_unix_seconds()) {
            Ok(signing) => signing,
            Err(error) => {
                print_stable_tzap_error("share", &error, &global);
                return ExitCode::FAILURE;
            }
        };
    let recipients = match zmanager_core::contact_card::accepted_contact_recipients(
        &store,
        &context.account_key,
        &contact_ids,
        current_unix_seconds(),
    ) {
        Ok(recipients) => recipients,
        Err(error) => {
            print_stable_tzap_error("share", &error.to_string(), &global);
            return ExitCode::FAILURE;
        }
    };
    let recipient_warning_count = recipients.iter().filter(|recipient| recipient.missing_status_caveat).count();
    let recipient_public_keys = recipients.into_iter().map(|recipient| recipient.recipient_public_key_der).collect();
    let manifest = match plan_sources(&sources, false, false, false) {
        Ok(manifest) => manifest,
        Err(error) => {
            print_error_line(&global, format_args!("share failed: {error}"));
            return ExitCode::FAILURE;
        }
    };
    if archive.exists() && !force {
        print_error_line(&global, format_args!("share failed: destination exists: {}", archive.display()));
        return ExitCode::FAILURE;
    }
    let token = CancellationToken::new();
    let mut progress = ProgressReporter::from_global(Some(&global));
    let options = zmanager_core::tzap_backend::TzapCreateOptions {
        key_source: zmanager_core::tzap_backend::TzapKeySource::RecipientPublicKeys(recipient_public_keys),
        level: 3,
        preserve_metadata: true,
        replace_existing: force,
        volume_size: None,
        recovery_percentage: TZAP_DEFAULT_RECOVERY_PERCENTAGE,
        volume_loss_tolerance: TZAP_SINGLE_VOLUME_LOSS_TOLERANCE,
        x509_signing: Some(x509_signing),
    };
    let result = {
        let mut sink = |event| progress.emit(event);
        let mut job_context = JobContext::new_with_progress_total(&token, &mut sink, Some(manifest.total_bytes));
        let result = zmanager_core::tzap_backend::create_tzap_from_manifest_with_context(
            &manifest,
            &archive,
            &options,
            &mut job_context,
        );
        job_context.flush_progress();
        result
    };
    match result {
        Ok(report) => {
            if global.json {
                println!(
                    "{{\"archive\":\"{}\",\"format\":\"tzap\",\"entries\":{},\"bytes\":{},\"recipients\":{},\"recipient_status_caveats\":{},\"signed\":true,\"certificate_id\":\"{}\"}}",
                    json_escape(&archive.display().to_string()),
                    report.written_entries,
                    report.written_bytes,
                    contact_ids.len(),
                    recipient_warning_count,
                    json_escape(&certificate_id)
                );
            } else {
                if recipient_warning_count > 0 {
                    print_error_line(
                        &global,
                        format_args!("{recipient_warning_count} recipient contact(s) have offline-only status caveats"),
                    );
                }
                print_success_line(&global, format_args!("created shared tzap {}", archive.display()));
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            print_error_line(&global, format_args!("share failed: {error}"));
            ExitCode::FAILURE
        }
    }
}

fn local_tzap_x509_signing_options(
    store: &impl zmanager_core::local_identity_store::TzapLocalIdentityStore,
    account_key: &str,
    certificate_id: &str,
    now_unix_seconds: u64,
) -> Result<zmanager_core::tzap_backend::TzapX509SigningOptions, String> {
    let inventory = store.load_inventory(account_key).map_err(|error| error.to_string())?;
    let certificate = inventory
        .enrolled_certificates
        .iter()
        .find(|record| record.certificate_id == certificate_id)
        .ok_or_else(|| format!("certificate not found: {certificate_id}"))?;
    if certificate.state != zmanager_core::local_identity_store::TzapLocalCertificateState::Active {
        return Err(format!("certificate is not active: {}", certificate.state.as_str()));
    }
    if now_unix_seconds < certificate.not_before_unix_seconds {
        return Err("certificate is not yet valid".to_owned());
    }
    if now_unix_seconds >= certificate.not_after_unix_seconds {
        return Err("certificate is expired".to_owned());
    }
    if inventory.emergency_blocklist.blocked_issuer_sha256.contains(&certificate.issuer_certificate_sha256) {
        return Err("certificate issuer is locally blocked".to_owned());
    }
    if inventory.certificate_status_cache.iter().any(|status| {
        status.certificate_sha256 == certificate.certificate_sha256
            && status.status != zmanager_core::trust::TzapCertificateStatus::Valid
    }) {
        return Err("certificate status blocks signing".to_owned());
    }
    let signing_key = inventory
        .device_signing_keys
        .iter()
        .find(|key| key.key_id == certificate.signing_key_id)
        .ok_or_else(|| "certificate signing key is missing".to_owned())?;
    Ok(zmanager_core::tzap_backend::TzapX509SigningOptions::InMemory {
        signing_certificate: certificate.leaf_certificate_der.clone(),
        signing_private_key: signing_key.private_key_der.clone(),
        signing_chain: certificate.intermediate_chain_der.clone(),
    })
}
fn parse_tzap_context_args(
    args: &[String],
    global: &mut GlobalOptions,
    command: &str,
) -> Result<TzapCliContext, ExitCode> {
    let mut context = TzapCliContext::default();
    let mut index = 0usize;
    while index < args.len() {
        match parse_global_option(args, &mut index, global) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(error) => return Err(command_usage_error(command, &error, global)),
        }
        match parse_tzap_context_option(args, &mut index, &mut context, command, global) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(code) => return Err(code),
        }
        return Err(command_usage_error(command, &format!("unknown {command} option: {}", args[index]), global));
    }
    Ok(context)
}

fn parse_cert_id_operation_args(
    args: &[String],
    global: &mut GlobalOptions,
    command: &str,
) -> Result<(TzapCliContext, String), ExitCode> {
    let mut context = TzapCliContext::default();
    let mut certificate_id = None;
    let mut index = 0usize;
    while index < args.len() {
        match parse_global_option(args, &mut index, global) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(error) => return Err(command_usage_error(command, &error, global)),
        }
        match parse_tzap_context_option(args, &mut index, &mut context, command, global) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(code) => return Err(code),
        }
        match args[index].as_str() {
            "--certificate-id" => {
                certificate_id = Some(
                    take_value(args, &mut index, "--certificate-id")
                        .map_err(|error| command_usage_error(command, &error, global))?,
                );
            }
            other => {
                return Err(command_usage_error(command, &format!("unknown {command} option: {other}"), global));
            }
        }
    }
    let Some(certificate_id) = certificate_id else {
        return Err(command_usage_error(command, "missing --certificate-id", global));
    };
    Ok((context, certificate_id))
}

fn parse_tzap_context_option(
    args: &[String],
    index: &mut usize,
    context: &mut TzapCliContext,
    command: &str,
    global: &GlobalOptions,
) -> Result<bool, ExitCode> {
    match args[*index].as_str() {
        "--state-dir" => {
            context.state_dir = PathBuf::from(
                take_value(args, index, "--state-dir").map_err(|error| command_usage_error(command, &error, global))?,
            );
        }
        "--account-key" => {
            context.account_key = take_value(args, index, "--account-key")
                .map_err(|error| command_usage_error(command, &error, global))?;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

fn parse_environment_option(
    args: &[String],
    index: &mut usize,
    environment: &mut zmanager_core::auth_client::TzapHostedAuthEnvironment,
    global: &GlobalOptions,
) -> Result<(), ExitCode> {
    let value =
        take_value(args, index, "--environment").map_err(|error| command_usage_error("auth", &error, global))?;
    *environment = match value.as_str() {
        "local" => zmanager_core::auth_client::TzapHostedAuthEnvironment::Local,
        "staging" => zmanager_core::auth_client::TzapHostedAuthEnvironment::Staging,
        "prod" => zmanager_core::auth_client::TzapHostedAuthEnvironment::Prod,
        _ => return Err(command_usage_error("auth", "environment must be local, staging, or prod", global)),
    };
    Ok(())
}

#[derive(Debug)]
struct HostedCertOptions {
    context: TzapCliContext,
    certificate_id: Option<String>,
    service_base_url: Option<String>,
    trusted_root_cert_paths: Vec<PathBuf>,
    org_id: Option<String>,
    requested_validity_seconds: u64,
}

fn parse_hosted_cert_renew_args(args: &[String], global: &mut GlobalOptions) -> Result<HostedCertOptions, ExitCode> {
    parse_hosted_cert_args(args, global, true)
}

fn parse_cert_enroll_args(args: &[String], global: &mut GlobalOptions) -> Result<HostedCertOptions, ExitCode> {
    parse_hosted_cert_args(args, global, false)
}

fn parse_hosted_cert_args(
    args: &[String],
    global: &mut GlobalOptions,
    require_certificate_id: bool,
) -> Result<HostedCertOptions, ExitCode> {
    let mut options = HostedCertOptions {
        context: TzapCliContext::default(),
        certificate_id: None,
        service_base_url: None,
        trusted_root_cert_paths: Vec::new(),
        org_id: None,
        requested_validity_seconds: DEFAULT_TZAP_CERT_VALIDITY_SECONDS,
    };
    let mut index = 0usize;
    while index < args.len() {
        match parse_global_option(args, &mut index, global) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(error) => return Err(command_usage_error("cert", &error, global)),
        }
        match parse_tzap_context_option(args, &mut index, &mut options.context, "cert", global) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(code) => return Err(code),
        }
        match args[index].as_str() {
            "--certificate-id" if require_certificate_id => {
                options.certificate_id = Some(
                    take_value(args, &mut index, "--certificate-id")
                        .map_err(|error| command_usage_error("cert", &error, global))?,
                );
            }
            "--certificate-id" => {
                return Err(command_usage_error("cert", "unknown cert option: --certificate-id", global));
            }
            "--service-base-url" => {
                options.service_base_url = Some(
                    take_value(args, &mut index, "--service-base-url")
                        .map_err(|error| command_usage_error("cert", &error, global))?,
                );
            }
            "--trusted-root-cert" => {
                options.trusted_root_cert_paths.push(PathBuf::from(
                    take_value(args, &mut index, "--trusted-root-cert")
                        .map_err(|error| command_usage_error("cert", &error, global))?,
                ));
            }
            "--org-id" => {
                options.org_id = Some(
                    take_value(args, &mut index, "--org-id")
                        .map_err(|error| command_usage_error("cert", &error, global))?,
                );
            }
            "--requested-validity-seconds" => {
                let value = take_value(args, &mut index, "--requested-validity-seconds")
                    .map_err(|error| command_usage_error("cert", &error, global))?;
                options.requested_validity_seconds = value.parse::<u64>().map_err(|_| {
                    command_usage_error("cert", "--requested-validity-seconds must be an integer", global)
                })?;
            }
            other => {
                return Err(command_usage_error("cert", &format!("unknown cert option: {other}"), global));
            }
        }
    }
    if require_certificate_id && options.certificate_id.as_deref().unwrap_or("").is_empty() {
        return Err(command_usage_error("cert", "missing --certificate-id", global));
    }
    if options.service_base_url.is_none() && !options.trusted_root_cert_paths.is_empty() {
        return Err(command_usage_error("cert", "--trusted-root-cert requires --service-base-url", global));
    }
    if options.service_base_url.is_none() && options.org_id.is_some() {
        return Err(command_usage_error("cert", "--org-id requires --service-base-url", global));
    }
    Ok(options)
}

#[derive(Debug)]
enum HostedCertOperationError {
    Operation(String),
    Message(String),
}

#[allow(clippy::too_many_arguments)]
fn run_hosted_cert_operation<F>(
    operation: &'static str,
    hosted_kind_label: &'static str,
    error_prefix: &'static str,
    options: &HostedCertOptions,
    global: &GlobalOptions,
    run: F,
) -> ExitCode
where
    F: FnOnce(
        &str,
        &zmanager_core::auth_client::TzapSessionRecord,
        &mut zmanager_core::local_identity_store::FileTzapLocalIdentityStore,
        Vec<String>,
        Vec<Vec<u8>>,
    )
        -> Result<zmanager_core::local_identity_store::TzapEnrolledCertificateRecord, HostedCertOperationError>,
{
    let Some(service_base_url) = options.service_base_url.as_deref() else {
        unreachable!("hosted operation checked by caller")
    };
    if options.trusted_root_cert_paths.is_empty() {
        return command_usage_error(
            "cert",
            &format!("hosted {hosted_kind_label} requires at least one --trusted-root-cert"),
            global,
        );
    }
    let session_store = FileTzapSessionStore::new(&options.context.state_dir);
    let Some(session) = session_store.load_session(&options.context.account_key) else {
        print_stable_tzap_error(operation, MISSING_TZAP_SESSION, global);
        return ExitCode::FAILURE;
    };
    let mut trusted_root_sha256 = Vec::new();
    let trusted_root_der =
        match load_custom_root_certificates(&options.trusted_root_cert_paths, &mut trusted_root_sha256) {
            Ok(roots) => roots,
            Err(error) => {
                print_error_line(global, format_args!("{error_prefix}{error}"));
                return ExitCode::FAILURE;
            }
        };
    let mut identity_store =
        zmanager_core::local_identity_store::FileTzapLocalIdentityStore::new(&options.context.state_dir);
    match run(service_base_url, &session, &mut identity_store, trusted_root_sha256, trusted_root_der) {
        Ok(certificate) => {
            if global.json {
                println!(
                    "{}",
                    json!({
                        "ok": true,
                        "operation": operation,
                        "service_base_url": service_base_url,
                        "certificate": certificate_summary_value(&certificate),
                    })
                );
            } else {
                print_success_line(global, format_args!("{operation} complete"));
            }
            ExitCode::SUCCESS
        }
        Err(HostedCertOperationError::Operation(message)) => {
            print_stable_tzap_error(operation, &message, global);
            ExitCode::FAILURE
        }
        Err(HostedCertOperationError::Message(message)) => {
            print_error_line(global, format_args!("{error_prefix}{message}"));
            ExitCode::FAILURE
        }
    }
}

fn run_hosted_cert_enroll(options: &HostedCertOptions, global: &GlobalOptions) -> ExitCode {
    run_hosted_cert_operation(
        "cert_enroll",
        "enrollment",
        "cert enroll failed: ",
        options,
        global,
        |service_base_url, session, identity_store, trusted_root_sha256, trusted_root_der| {
            let now_unix_seconds = current_unix_seconds();
            let request = zmanager_core::enrollment_client::TzapEnrollmentRequest {
                account_key: options.context.account_key.clone(),
                org_id: options.org_id.clone().or_else(|| session.selected_org_id.clone()),
                requested_validity_seconds: options.requested_validity_seconds,
                now_unix_seconds,
            };
            let (signing_key, csr_der) =
                match create_and_store_staging_enrollment_key(identity_store, &request, now_unix_seconds) {
                    Ok(material) => material,
                    Err(error) => return Err(HostedCertOperationError::Message(error)),
                };
            let transport = CliHttpJsonTransport;
            let client = zmanager_core::enrollment_client::TzapEnrollmentClient::local_staging_server(
                service_base_url,
                &transport,
            );
            let validator = CliTrustedEnrollmentCertificateValidator {
                trusted_root_sha256,
                trusted_root_der,
                options: zmanager_core::trust::TzapCertificateProfileOptions::default(),
            };
            zmanager_core::enrollment_client::enroll_device_certificate(
                &client,
                &validator,
                identity_store,
                session,
                &request,
                &signing_key,
                &csr_der,
            )
            .map_err(|error| HostedCertOperationError::Operation(error.to_string()))
        },
    )
}

fn run_hosted_cert_renew(options: &HostedCertOptions, global: &GlobalOptions) -> ExitCode {
    let certificate_id = options.certificate_id.as_deref().unwrap_or_default();
    run_hosted_cert_operation(
        "cert_renew",
        "renewal",
        "cert renew failed: ",
        options,
        global,
        |service_base_url, session, identity_store, trusted_root_sha256, trusted_root_der| {
            let inventory = match identity_store.load_inventory(&options.context.account_key) {
                Ok(inventory) => inventory,
                Err(error) => {
                    return Err(HostedCertOperationError::Message(format!("cannot load identity store: {error}")));
                }
            };
            let previous_certificate = if let Some(certificate) =
                inventory.enrolled_certificates.iter().find(|record| record.certificate_id == certificate_id)
            {
                certificate.clone()
            } else {
                return Err(HostedCertOperationError::Message(format!(
                    "certificate {certificate_id} not found locally"
                )));
            };
            let signing_key = if let Some(record) =
                inventory.device_signing_keys.iter().find(|record| record.key_id == previous_certificate.signing_key_id)
            {
                record.clone()
            } else {
                return Err(HostedCertOperationError::Message(format!(
                    "signing key {} not found",
                    previous_certificate.signing_key_id
                )));
            };
            let csr_der = match zmanager_core::device_identity::generate_device_csr_from_private_key(
                &signing_key.private_key_der,
                &zmanager_core::device_identity::TzapDeviceCsrOptions::default(),
            ) {
                Ok(csr) => csr,
                Err(error) => return Err(HostedCertOperationError::Message(format!("cannot generate CSR: {error}"))),
            };
            let now_unix_seconds = current_unix_seconds();
            let login_base_url = zmanager_core::auth_client::LOGIN_TZAP_BASE_URL;
            let transport = CliHttpJsonTransport;
            let lifecycle = zmanager_core::certificate_lifecycle::TzapCertificateLifecycleClient::local_staging_server(
                service_base_url,
                login_base_url,
                &transport,
            );
            let validator = CliTrustedEnrollmentCertificateValidator {
                trusted_root_sha256,
                trusted_root_der,
                options: zmanager_core::trust::TzapCertificateProfileOptions::default(),
            };
            let org_id = options.org_id.clone().or_else(|| session.selected_org_id.clone());
            let renewal_request = zmanager_core::certificate_lifecycle::TzapRenewalRequest {
                account_key: options.context.account_key.clone(),
                previous_certificate_id: previous_certificate.certificate_id,
                previous_certificate_sha256: previous_certificate.certificate_sha256,
                org_id,
                requested_validity_seconds: options.requested_validity_seconds,
                renewal_policy: zmanager_core::certificate_lifecycle::TzapRenewalPolicy::SameKeyRequired,
                now_unix_seconds,
                server_grace_seconds: zmanager_core::certificate_lifecycle::RENEWAL_GRACE_MAX_SECONDS,
            };
            lifecycle
                .renew_certificate(
                    &validator,
                    identity_store,
                    session,
                    &renewal_request,
                    &signing_key,
                    &signing_key,
                    &csr_der,
                )
                .map_err(|error| HostedCertOperationError::Operation(error.to_string()))
        },
    )
}

pub(crate) fn create_and_store_staging_enrollment_key(
    store: &mut zmanager_core::local_identity_store::FileTzapLocalIdentityStore,
    request: &zmanager_core::enrollment_client::TzapEnrollmentRequest,
    now_unix_seconds: u64,
) -> Result<(zmanager_core::local_identity_store::TzapDeviceSigningKeyRecord, Vec<u8>), String> {
    let mut inventory = store.load_inventory(&request.account_key).map_err(|error| error.to_string())?;
    let label = staging_enrollment_key_label(request.org_id.as_deref());
    if let Some(record) = inventory.device_signing_keys.iter().find(|record| {
        record.label.as_deref() == Some(label.as_str())
            && !inventory.enrolled_certificates.iter().any(|certificate| certificate.signing_key_id == record.key_id)
    }) {
        let csr_der = zmanager_core::device_identity::generate_device_csr_from_private_key(
            &record.private_key_der,
            &zmanager_core::device_identity::TzapDeviceCsrOptions::default(),
        )
        .map_err(|error| error.to_string())?;
        return Ok((record.clone(), csr_der));
    }

    let material = zmanager_core::device_identity::generate_device_signing_key_and_csr(
        &zmanager_core::device_identity::TzapDeviceCsrOptions::default(),
    )
    .map_err(|error| error.to_string())?;
    let record = zmanager_core::local_identity_store::TzapDeviceSigningKeyRecord {
        key_id: material.public_key_fingerprint.clone(),
        public_key_fingerprint: material.public_key_fingerprint,
        private_key_der: material.private_key_der,
        created_at_unix_seconds: now_unix_seconds,
        label: Some(label),
    };
    inventory.device_signing_keys.push(record.clone());
    store.save_inventory(&request.account_key, inventory).map_err(|error| error.to_string())?;
    Ok((record, material.csr_der))
}

fn staging_enrollment_key_label(org_id: Option<&str>) -> String {
    match org_id {
        Some(org_id) => format!("{STAGING_ENROLLMENT_KEY_LABEL} (org:{org_id})"),
        None => format!("{STAGING_ENROLLMENT_KEY_LABEL} (personal)"),
    }
}

struct CliTrustedEnrollmentCertificateValidator {
    trusted_root_sha256: Vec<String>,
    trusted_root_der: Vec<Vec<u8>>,
    options: zmanager_core::trust::TzapCertificateProfileOptions,
}

impl zmanager_core::enrollment_client::TzapEnrollmentCertificateValidator for CliTrustedEnrollmentCertificateValidator {
    fn validate_certificate_chain(
        &self,
        chain_der: &[Vec<u8>],
    ) -> Result<
        zmanager_core::trust::TzapCertificatePublicMetadata,
        zmanager_core::enrollment_client::TzapEnrollmentError,
    > {
        self.validate_custom_chain_with_root_pin(chain_der).map(|validation| validation.public_metadata)
    }

    fn validate_and_complete_certificate_chain(
        &self,
        chain_der: &[Vec<u8>],
    ) -> Result<
        (Vec<Vec<u8>>, zmanager_core::trust::TzapCertificatePublicMetadata),
        zmanager_core::enrollment_client::TzapEnrollmentError,
    > {
        let mut last_error = match self.validate_completed_chain(chain_der) {
            Ok(result) => return Ok(result),
            Err(error) => error,
        };
        for root_der in &self.trusted_root_der {
            let mut completed_chain = chain_der.to_vec();
            completed_chain.push(root_der.clone());
            match self.validate_completed_chain(&completed_chain) {
                Ok(result) => return Ok(result),
                Err(error) => {
                    last_error = error;
                }
            }
        }
        Err(last_error)
    }
}

impl CliTrustedEnrollmentCertificateValidator {
    fn validate_completed_chain(
        &self,
        chain_der: &[Vec<u8>],
    ) -> Result<
        (Vec<Vec<u8>>, zmanager_core::trust::TzapCertificatePublicMetadata),
        zmanager_core::enrollment_client::TzapEnrollmentError,
    > {
        self.validate_custom_chain_with_root_pin(chain_der)
            .map(|validation| (chain_der.to_vec(), validation.public_metadata))
    }

    fn validate_custom_chain_with_root_pin(
        &self,
        chain_der: &[Vec<u8>],
    ) -> Result<
        zmanager_core::trust::TzapCertificateProfileValidation,
        zmanager_core::enrollment_client::TzapEnrollmentError,
    > {
        let validation = zmanager_core::trust::validate_custom_tzap_certificate_chain_der(chain_der, &self.options)
            .map_err(|error| {
                zmanager_core::enrollment_client::TzapEnrollmentError::CertificateChain(error.to_string())
            })?;
        if !self.trusted_root_sha256.iter().any(|trusted| trusted == &validation.root_certificate_sha256) {
            return Err(zmanager_core::enrollment_client::TzapEnrollmentError::CertificateChain(format!(
                "root certificate is not in the temporary trust store: {}",
                validation.root_certificate_sha256
            )));
        }
        Ok(validation)
    }
}

fn run_local_cert_operation<F>(operation: &str, context: &TzapCliContext, global: &GlobalOptions, action: F) -> ExitCode
where
    F: FnOnce(
        &mut zmanager_core::local_identity_store::FileTzapLocalIdentityStore,
        &zmanager_core::auth_client::TzapSessionRecord,
        &zmanager_core::local_tzap_service::TzapLocalServiceOptions,
    ) -> Result<serde_json::Value, zmanager_core::local_tzap_service::TzapLocalServiceError>,
{
    let session_store = FileTzapSessionStore::new(&context.state_dir);
    let Some(session) = session_store.load_session(&context.account_key) else {
        print_stable_tzap_error(operation, MISSING_TZAP_SESSION, global);
        return ExitCode::FAILURE;
    };
    let mut identity_store = zmanager_core::local_identity_store::FileTzapLocalIdentityStore::new(&context.state_dir);
    let options = zmanager_core::local_tzap_service::TzapLocalServiceOptions {
        account_key: context.account_key.clone(),
        now_unix_seconds: current_unix_seconds(),
    };
    match action(&mut identity_store, &session, &options) {
        Ok(value) => {
            if global.json {
                println!("{value}");
            } else {
                print_success_line(global, format_args!("{operation} complete"));
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            print_stable_tzap_error(operation, &error.to_string(), global);
            ExitCode::FAILURE
        }
    }
}

fn print_stable_tzap_error(operation: &str, message: &str, global: &GlobalOptions) {
    if global.json {
        println!(
            "{{\"ok\":false,\"operation\":\"{}\",\"error\":\"{}\"}}",
            json_escape(operation),
            json_escape(message)
        );
    } else {
        print_error_line(global, format_args!("{operation} failed: {message}"));
    }
}
fn certificate_summary_value(
    cert: &zmanager_core::local_identity_store::TzapEnrolledCertificateRecord,
) -> serde_json::Value {
    json!({
        "certificate_id": cert.certificate_id,
        "certificate_sha256": cert.certificate_sha256,
        "state": cert.state.as_str(),
        "not_before_unix_seconds": cert.not_before_unix_seconds,
        "not_after_unix_seconds": cert.not_after_unix_seconds,
        "public_signer_id": cert.public_metadata.public_signer_id,
        "public_org_id": cert.public_metadata.public_org_id,
        "public_device_id": cert.public_metadata.public_device_id,
        "assurance_level": cert.public_metadata.assurance_level.as_str(),
    })
}

#[allow(clippy::needless_pass_by_value)]
fn retirement_completion_label(
    completion: zmanager_core::certificate_lifecycle::TzapRetirementCompletion,
) -> &'static str {
    match completion {
        zmanager_core::certificate_lifecycle::TzapRetirementCompletion::Complete => "complete",
        zmanager_core::certificate_lifecycle::TzapRetirementCompletion::Incomplete => "incomplete",
    }
}

fn default_tzap_state_dir() -> PathBuf {
    if let Some(path) = env::var_os(DEFAULT_TZAP_STATE_DIR_ENV)
        && !path.is_empty()
    {
        return PathBuf::from(path);
    }
    env::var_os("HOME").map_or_else(
        || PathBuf::from(".").join(DEFAULT_TZAP_STATE_HOME_CHILD),
        |home| PathBuf::from(home).join(DEFAULT_TZAP_STATE_HOME_CHILD),
    )
}

fn current_unix_seconds() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_secs())
}

fn read_bytes_argument(path: &str) -> io::Result<Vec<u8>> {
    if path == "-" {
        let mut bytes = Vec::new();
        io::Read::read_to_end(&mut io::stdin(), &mut bytes)?;
        Ok(bytes)
    } else {
        fs::read(path)
    }
}

fn read_json_argument(path: &str) -> Result<Value, String> {
    let bytes = read_bytes_argument(path).map_err(|error| error.to_string())?;
    serde_json::from_slice(&bytes).map_err(|error| error.to_string())
}

fn load_custom_root_certificates(paths: &[PathBuf], custom_roots: &mut Vec<String>) -> Result<Vec<Vec<u8>>, String> {
    paths
        .iter()
        .map(|path| {
            let bytes = fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
            let der = zmanager_core::trust::certificate_pem_or_der_to_der(&bytes)
                .map_err(|error| format!("{}: {error}", path.display()))?;
            let fingerprint = zmanager_core::trust::certificate_sha256_identifier_for_der(&der);
            if !custom_roots.iter().any(|root| root == &fingerprint) {
                custom_roots.push(fingerprint);
            }
            Ok(der)
        })
        .collect()
}

fn read_json_file(path: &Path) -> Option<Value> {
    let bytes = fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn write_json_file(path: &Path, value: &Value) -> io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(value).map_err(io::Error::other)?;
    fs::write(path, bytes)
}

fn write_secret_json_file(path: &Path, value: &Value) -> io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(value).map_err(io::Error::other)?;
    write_secret_file(path, &bytes)
}

#[cfg(unix)]
fn write_secret_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    let mut file = fs::OpenOptions::new().create(true).truncate(true).write(true).mode(0o600).open(path)?;
    file.write_all(bytes)?;
    let mut permissions = file.metadata()?.permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_secret_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    fs::write(path, bytes)
}

fn save_pending_auth(
    state_dir: &Path,
    pending: &zmanager_core::auth_client::TzapPendingAuthState,
    config: &zmanager_core::auth_client::TzapHostedAuthLaunchConfig,
) -> io::Result<()> {
    write_secret_json_file(
        &state_dir.join(AUTH_PENDING_FILE),
        &json!({
            "state": pending.state,
            "provider_id": pending.provider_id,
            "redirect_uri": pending.redirect_uri,
            "pkce_verifier": pending.pkce.verifier,
            "created_at_unix_seconds": pending.created_at_unix_seconds,
            "client_id": config.client_id,
            "auth_base_url": config.hosted_auth_base_url,
        }),
    )
}

#[derive(Debug, Default)]
struct PendingAuthMetadata {
    client_id: Option<String>,
    auth_base_url: Option<String>,
}

fn load_pending_auth_metadata(state_dir: &Path) -> PendingAuthMetadata {
    let Some(value) = read_json_file(&state_dir.join(AUTH_PENDING_FILE)) else {
        return PendingAuthMetadata::default();
    };
    PendingAuthMetadata {
        client_id: json_optional_string_field(&value, "client_id").ok().flatten(),
        auth_base_url: json_optional_string_field(&value, "auth_base_url").ok().flatten(),
    }
}

fn load_pending_auth(state_dir: &Path) -> Result<zmanager_core::auth_client::TzapPendingAuthState, String> {
    let value = read_json_file(&state_dir.join(AUTH_PENDING_FILE))
        .ok_or_else(|| "no pending hosted-auth handoff".to_owned())?;
    let verifier = json_string_field(&value, "pkce_verifier")?;
    let pkce = zmanager_core::auth_client::TzapPkcePair::from_verifier(&verifier).map_err(|error| error.to_string())?;
    Ok(zmanager_core::auth_client::TzapPendingAuthState {
        state: json_string_field(&value, "state")?,
        provider_id: json_string_field(&value, "provider_id")?,
        redirect_uri: json_string_field(&value, "redirect_uri")?,
        pkce,
        created_at_unix_seconds: json_u64_field(&value, "created_at_unix_seconds")?,
    })
}

fn callback_url_parameter(callback_url: &str, key: &str) -> Option<String> {
    let (_, query) = callback_url.split_once('?')?;
    let query = query.split_once('#').map_or(query, |(query, _)| query);
    for parameter in query.split('&') {
        let (parameter_key, value) = parameter.split_once('=').unwrap_or((parameter, ""));
        if percent_decode_url_component(parameter_key).ok().as_deref() == Some(key) {
            return percent_decode_url_component(value).ok();
        }
    }
    None
}

fn exchange_handoff_code(
    auth_base_url: &str,
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    pkce_verifier: &str,
    handoff_code: &str,
) -> Result<Vec<u8>, String> {
    let url = format!("{}{}", auth_base_url.trim_end_matches('/'), AUTH_SESSION_EXCHANGE_PATH);
    let exchange = http_post_json(
        &url,
        &json!({
            "handoff_code": handoff_code,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "code_verifier": pkce_verifier,
            "required_audience": zmanager_core::auth_client::SESSION_AUDIENCE_SIGN_TZAP,
        }),
    )?;
    let session_token = json_string_field(&exchange, "session_token")?;
    let session_id = json_string_field(&exchange, "session_id")?;
    let audience = json_string_field(&exchange, "audience")
        .unwrap_or_else(|_| zmanager_core::auth_client::SESSION_AUDIENCE_SIGN_TZAP.to_owned());
    let expires_at_unix_seconds = exchange.get("expires_at_unix_seconds").and_then(Value::as_u64).map_or_else(
        || json_string_field(&exchange, "expires_at").and_then(|expires_at| rfc3339_utc_to_unix_seconds(&expires_at)),
        Ok,
    )?;
    let identity_assurance = json_string_field(&exchange, "identity_assurance")
        .or_else(|_| json_string_field(&exchange, "identity_assurance_level"))
        .unwrap_or_else(|_| zmanager_core::trust::TzapIdentityAssurance::OauthVerifiedEmail.as_str().to_owned());
    serde_json::to_vec(&json!({
        "status": "ok",
        "session": {
            "audience": audience,
            "access_token": session_token,
            "expires_at_unix_seconds": expires_at_unix_seconds,
            "identity_assurance": identity_assurance,
            "selected_org_id": exchange.get("selected_org_id").cloned().unwrap_or(Value::Null),
            "login_session_id": session_id,
        }
    }))
    .map_err(|error| error.to_string())
}

fn http_post_json(url: &str, body: &Value) -> Result<Value, String> {
    let response = http_json_request("POST", url, None, Some(body))?;
    if !(200..=299).contains(&response.status_code) {
        return Err(format!("hosted auth exchange failed with HTTP {}", response.status_code));
    }
    serde_json::from_slice(&response.body).map_err(|error| error.to_string())
}

#[derive(Debug, Clone, Copy)]
struct CliHttpJsonTransport;

impl zmanager_core::auth_client::TzapAuthHttpTransport for CliHttpJsonTransport {
    fn send(
        &self,
        request: &zmanager_core::auth_client::TzapAuthHttpRequest,
    ) -> Result<zmanager_core::auth_client::TzapAuthHttpResponse, zmanager_core::auth_client::TzapAuthError> {
        let method = match request.method {
            zmanager_core::auth_client::TzapAuthHttpMethod::Get => "GET",
            zmanager_core::auth_client::TzapAuthHttpMethod::Post => "POST",
        };
        http_json_request(
            method,
            &request.url,
            request.bearer_token.as_ref().map(zmanager_core::auth_client::TzapBearerToken::expose),
            request.body.as_ref(),
        )
        .map_err(|message| zmanager_core::auth_client::TzapAuthError::Transport { message })
    }
}

fn http_json_request(
    method: &str,
    url: &str,
    bearer_token: Option<&str>,
    body: Option<&Value>,
) -> Result<zmanager_core::auth_client::TzapAuthHttpResponse, String> {
    let client = reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| format!("could not initialize hosted HTTPS client: {error}"))?;
    let request = build_hosted_http_request(&client, method, url, bearer_token, body)?;
    let response = client.execute(request).map_err(|error| format!("hosted HTTPS request failed: {error}"))?;
    let status_code = response.status().as_u16();
    let response_body =
        response.bytes().map_err(|error| format!("could not read hosted HTTPS response: {error}"))?.to_vec();
    Ok(zmanager_core::auth_client::TzapAuthHttpResponse { status_code, body: response_body })
}

pub(crate) fn build_hosted_http_request(
    client: &reqwest::blocking::Client,
    method: &str,
    url: &str,
    bearer_token: Option<&str>,
    body: Option<&Value>,
) -> Result<reqwest::blocking::Request, String> {
    let method = reqwest::Method::from_bytes(method.as_bytes())
        .map_err(|error| format!("invalid hosted HTTP method: {error}"))?;
    let mut request = client.request(method, url).header(reqwest::header::ACCEPT, "application/json");
    if let Some(token) = bearer_token {
        request = request.bearer_auth(token);
    }
    if let Some(body) = body {
        request = request.json(body);
    }
    request.build().map_err(|error| format!("invalid hosted HTTPS request: {error}"))
}

fn percent_decode_url_component(value: &str) -> Result<String, String> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).map_err(|error| error.to_string())?;
                output.push(u8::from_str_radix(hex, 16).map_err(|error| error.to_string())?);
                index += 3;
            }
            b'+' => {
                output.push(b' ');
                index += 1;
            }
            byte => {
                output.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(output).map_err(|error| error.to_string())
}

fn rfc3339_utc_to_unix_seconds(value: &str) -> Result<u64, String> {
    let without_z = value.strip_suffix('Z').ok_or_else(|| "expires_at must be a UTC RFC3339 timestamp".to_owned())?;
    let (date, time) = without_z.split_once('T').ok_or_else(|| "expires_at must include a date and time".to_owned())?;
    let mut date_parts = date.split('-');
    let year = parse_i64_part(date_parts.next(), "year")?;
    let month = parse_i64_part(date_parts.next(), "month")?;
    let day = parse_i64_part(date_parts.next(), "day")?;
    if date_parts.next().is_some() {
        return Err("expires_at has too many date components".to_owned());
    }
    if !(1..=12).contains(&month) {
        return Err(format!("expires_at month {month} is out of range"));
    }
    let month_length = days_in_month(year, month);
    if !(1..=month_length).contains(&day) {
        return Err(format!("expires_at day {day} is out of range"));
    }
    let time = time.split_once('.').map_or(time, |(whole, _)| whole);
    let mut time_parts = time.split(':');
    let hour = parse_i64_part(time_parts.next(), "hour")?;
    let minute = parse_i64_part(time_parts.next(), "minute")?;
    let second = parse_i64_part(time_parts.next(), "second")?;
    if time_parts.next().is_some() {
        return Err("expires_at has too many time components".to_owned());
    }
    if !(0..=23).contains(&hour) {
        return Err(format!("expires_at hour {hour} is out of range"));
    }
    if !(0..=59).contains(&minute) {
        return Err(format!("expires_at minute {minute} is out of range"));
    }
    if !(0..=59).contains(&second) {
        return Err(format!("expires_at second {second} is out of range"));
    }
    let days = days_from_civil(year, month, day);
    let seconds = days
        .checked_mul(86_400)
        .and_then(|value| value.checked_add(hour * 3_600 + minute * 60 + second))
        .ok_or_else(|| "expires_at is out of range".to_owned())?;
    u64::try_from(seconds).map_err(|_| "expires_at is before the Unix epoch".to_owned())
}

fn days_in_month(year: i64, month: i64) -> i64 {
    let leap_february = i64::from(month == 2 && ((year % 4 == 0 && year % 100 != 0) || year % 400 == 0));
    [31, 28 + leap_february, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month as usize - 1]
}

fn parse_i64_part(value: Option<&str>, field: &str) -> Result<i64, String> {
    value.ok_or_else(|| format!("expires_at is missing {field}"))?.parse::<i64>().map_err(|error| error.to_string())
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_prime = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn session_to_json(session: &zmanager_core::auth_client::TzapSessionRecord, include_token: bool) -> Value {
    let mut value = json!({
        "audience": session.audience,
        "expires_at_unix_seconds": session.expires_at_unix_seconds,
        "identity_assurance": session.identity_assurance.as_str(),
        "selected_org_id": session.selected_org_id,
        "login_session_id": session.login_session_id,
    });
    if include_token {
        value["access_token"] = json!(session.access_token.expose());
    }
    value
}

fn session_from_json(value: &Value) -> Result<zmanager_core::auth_client::TzapSessionRecord, String> {
    let assurance = json_string_field(value, "identity_assurance")?;
    let identity_assurance = zmanager_core::trust::TzapIdentityAssurance::parse(&assurance)
        .ok_or_else(|| "invalid identity assurance".to_owned())?;
    Ok(zmanager_core::auth_client::TzapSessionRecord {
        audience: json_string_field(value, "audience")?,
        access_token: zmanager_core::auth_client::TzapBearerToken::new(json_string_field(value, "access_token")?)
            .map_err(|error| error.to_string())?,
        expires_at_unix_seconds: json_u64_field(value, "expires_at_unix_seconds")?,
        identity_assurance,
        selected_org_id: json_optional_string_field(value, "selected_org_id")?,
        login_session_id: json_optional_string_field(value, "login_session_id")?,
    })
}

fn json_string_field(value: &Value, field: &'static str) -> Result<String, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("missing or invalid field: {field}"))
}

fn json_optional_string_field(value: &Value, field: &'static str) -> Result<Option<String>, String> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        _ => Err(format!("missing or invalid field: {field}")),
    }
}

fn json_u64_field(value: &Value, field: &'static str) -> Result<u64, String> {
    value.get(field).and_then(Value::as_u64).ok_or_else(|| format!("missing or invalid field: {field}"))
}

fn print_session_summary(session: &zmanager_core::auth_client::TzapSessionRecord, global: &GlobalOptions) {
    let expired = session.is_expired_at(current_unix_seconds());
    if global.json {
        println!(
            "{{\"authenticated\":true,\"audience\":\"{}\",\"expires_at_unix_seconds\":{},\"expired\":{},\"identity_assurance\":\"{}\",\"selected_org_id\":{},\"login_session_id\":{}}}",
            json_escape(&session.audience),
            session.expires_at_unix_seconds,
            expired,
            json_escape(session.identity_assurance.as_str()),
            json_optional_string(session.selected_org_id.as_deref()),
            json_optional_string(session.login_session_id.as_deref())
        );
    } else {
        let status = if expired { "expired" } else { "active" };
        println!("{status} session for {} ({})", session.audience, session.identity_assurance.as_str());
    }
}

fn print_verification_result(
    result: &zmanager_core::document_verification::TzapDocumentVerificationResult,
    global: &GlobalOptions,
) {
    if global.json {
        println!(
            "{{\"state\":\"{}\",\"trust_anchor_type\":\"{}\",\"reason\":{},\"root_certificate_sha256\":{}}}",
            json_escape(result.state.as_str()),
            json_escape(result.trust_anchor_type.as_str()),
            json_optional_string(result.reason.as_deref()),
            json_optional_string(result.root_certificate_sha256.as_deref())
        );
    } else {
        println!("{} ({})", result.state.as_str(), result.trust_anchor_type.as_str());
        if let Some(reason) = &result.reason {
            println!("{reason}");
        }
    }
}

fn print_contact_json(contact: &zmanager_core::local_identity_store::TzapContactRecord) {
    print!(
        "{{\"contact_id\":\"{}\",\"display_name\":\"{}\",\"signing_certificate_sha256\":\"{}\",\"recipient_public_key_fingerprint\":\"{}\",\"trust_anchor_type\":\"{}\",\"verification_state\":\"{}\",\"missing_status_caveat\":{},\"accepted_at_unix_seconds\":{}}}",
        json_escape(&contact.contact_id),
        json_escape(&contact.display_name),
        json_escape(&contact.signing_certificate_sha256),
        json_escape(&contact.recipient_public_key_fingerprint),
        contact.trust_anchor_type.as_str(),
        contact.verification_state.as_str(),
        contact.missing_status_caveat,
        contact.accepted_at_unix_seconds
    );
}

fn print_contact_json_line(contact: &zmanager_core::local_identity_store::TzapContactRecord) {
    print!("{{\"contact\":");
    print_contact_json(contact);
    println!("}}");
}

#[cfg(test)]
mod tests {
    use super::rfc3339_utc_to_unix_seconds;

    #[test]
    fn rfc3339_parses_valid_utc_timestamps() {
        assert_eq!(rfc3339_utc_to_unix_seconds("1970-01-01T00:00:00Z").unwrap(), 0);
        assert_eq!(rfc3339_utc_to_unix_seconds("1970-01-01T00:00:00.123Z").unwrap(), 0);
        assert_eq!(rfc3339_utc_to_unix_seconds("2024-02-29T12:34:56Z").unwrap(), 1_709_210_096);
    }

    #[test]
    fn rfc3339_rejects_invalid_calendar_values() {
        for value in [
            "2026-13-01T00:00:00Z",
            "2026-00-01T00:00:00Z",
            "2026-02-30T00:00:00Z",
            "2025-02-29T00:00:00Z",
            "2026-04-31T00:00:00Z",
            "2026-06-01T24:00:00Z",
            "2026-06-01T00:60:00Z",
            "2026-06-01T00:00:60Z",
        ] {
            assert!(rfc3339_utc_to_unix_seconds(value).is_err(), "expected rejection for {value}");
        }
    }

    #[test]
    fn rfc3339_rejects_malformed_timestamps() {
        for value in ["2026-06-01T00:00:00", "2026-06-01", "not-a-timestamp", "2026-06-01T00:00:00+02:00"] {
            assert!(rfc3339_utc_to_unix_seconds(value).is_err(), "expected rejection for {value}");
        }
    }
}
