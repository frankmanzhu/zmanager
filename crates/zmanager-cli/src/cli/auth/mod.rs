#![cfg_attr(not(feature = "tzap-online"), allow(dead_code))]

//! Hosted-TZAP command surface (CR-113, medium option).
//!
//! Split by domain from the former `cli/tzap.rs` dump ground: [`auth`],
//! [`cert`], [`device`], [`sign`], [`contacts`], [`share`], the hosted-cert
//! operations in [`hosted`], and the shared helpers in [`support`]. The
//! command entry points are re-exported here so the app dispatcher is
//! unchanged.

#[cfg(feature = "tzap-online")]
#[allow(clippy::module_inception)]
mod auth;
#[cfg(feature = "tzap-online")]
mod cert;
#[cfg(feature = "tzap-online")]
mod contacts;
#[cfg(feature = "tzap-online")]
mod device;
#[cfg(feature = "tzap-online")]
mod hosted;
#[cfg(feature = "tzap-online")]
mod share;
#[cfg(feature = "tzap-online")]
mod sign;
#[cfg(feature = "tzap-online")]
mod support;
#[cfg(all(test, feature = "tzap-online"))]
mod tests;

#[cfg(feature = "tzap-online")]
pub(crate) use auth::auth_command as hosted_auth_command;
#[cfg(feature = "tzap-online")]
pub(crate) use cert::cert_command;
#[cfg(feature = "tzap-online")]
pub(crate) use cert::me_command;
#[cfg(feature = "tzap-online")]
pub(crate) use contacts::contact_command;
#[cfg(feature = "tzap-online")]
pub(crate) use device::device_command;
#[cfg(feature = "tzap-online")]
pub(crate) use share::share_command;
#[cfg(feature = "tzap-online")]
pub(crate) use sign::{sign_command, verify_command};
#[cfg(all(test, feature = "tzap-online"))]
pub(crate) use {contacts::contact_keygen_command, hosted::create_and_store_staging_enrollment_key, support::build_hosted_http_request};

use std::path::PathBuf;

#[cfg(feature = "tzap-online")]
pub(super) const DEFAULT_TZAP_CLIENT_ID: &str = "zmanager-cli";
#[cfg(feature = "tzap-online")]
pub(crate) const DEFAULT_TZAP_REDIRECT_URI: &str = "tzap://auth/callback";
#[cfg(feature = "tzap-online")]
pub(super) const DEFAULT_TZAP_PROVIDER_ID: &str = "hosted";
#[cfg(feature = "tzap-online")]
pub(super) const AUTH_PENDING_FILE: &str = "auth-pending.json";
#[cfg(feature = "tzap-online")]
pub(super) const AUTH_SESSION_EXCHANGE_PATH: &str = "/auth/session/exchange";
pub(super) const MISSING_TZAP_SESSION: &str = "no local TZAP session";
pub(super) const DEFAULT_TZAP_CERT_VALIDITY_SECONDS: u64 = 90 * 24 * 60 * 60;
pub(super) const STAGING_ENROLLMENT_KEY_LABEL: &str = "Hosted TZAP enrollment signing key";

#[derive(Debug, Clone)]
pub(super) struct TzapCliContext {
    pub(super) state_dir: PathBuf,
    pub(super) account_key: String,
}

impl Default for TzapCliContext {
    fn default() -> Self {
        Self { state_dir: default_offline_tzap_state_dir(), account_key: zmanager_core::local_identity_store::DEFAULT_IDENTITY_INVENTORY_ACCOUNT.to_owned() }
    }
}

fn default_offline_tzap_state_dir() -> PathBuf {
    for variable in ["ZM_TZAP_STATE_DIR", "ZMANAGER_TZAP_STATE_DIR"] {
        if let Some(path) = std::env::var_os(variable)
            && !path.is_empty()
        {
            return PathBuf::from(path);
        }
    }
    std::env::var_os("HOME").map_or_else(|| PathBuf::from(".").join(".zmanager").join("tzap"), |home| PathBuf::from(home).join(".zmanager").join("tzap"))
}

#[cfg(feature = "tzap-online")]
#[derive(Debug, Clone)]
pub(super) struct AuthEndpointOptions {
    pub(super) environment: zmanager_tzap_hosted::auth_client::TzapHostedAuthEnvironment,
    pub(super) auth_base_url: Option<String>,
    pub(super) account_base_url: Option<String>,
    pub(super) client_id: String,
    pub(super) redirect_uri: String,
    pub(super) provider_id: String,
    pub(super) org_id: Option<String>,
}

#[cfg(feature = "tzap-online")]
impl Default for AuthEndpointOptions {
    fn default() -> Self {
        Self {
            environment: zmanager_tzap_hosted::auth_client::TzapHostedAuthEnvironment::Prod,
            auth_base_url: None,
            account_base_url: None,
            client_id: DEFAULT_TZAP_CLIENT_ID.to_owned(),
            redirect_uri: DEFAULT_TZAP_REDIRECT_URI.to_owned(),
            provider_id: DEFAULT_TZAP_PROVIDER_ID.to_owned(),
            org_id: None,
        }
    }
}

#[cfg(feature = "tzap-online")]
pub(crate) fn auth_command(args: &[String], global: crate::cli::options::GlobalOptions) -> std::process::ExitCode {
    hosted_auth_command(args, global)
}
