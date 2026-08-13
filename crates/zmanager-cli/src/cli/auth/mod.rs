//! Hosted-TZAP command surface (CR-113, medium option).
//!
//! Split by domain from the former `cli/tzap.rs` dump ground: [`auth`],
//! [`cert`], [`device`], [`sign`], [`contacts`], [`share`], the hosted-cert
//! operations in [`hosted`], and the shared helpers in [`support`]. The
//! command entry points are re-exported here so the app dispatcher is
//! unchanged.

// The real command surface is compiled only with the `auth` feature; the
// offline build registers the `auth` command as a stub that points users at
// the full build (see [`unavailable`]).
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
#[cfg(not(feature = "tzap-online"))]
mod unavailable;

#[cfg(feature = "tzap-online")]
pub(crate) use auth::auth_command;
#[cfg(feature = "tzap-online")]
pub(crate) use cert::{cert_command, me_command};
#[cfg(feature = "tzap-online")]
pub(crate) use contacts::contact_command;
#[cfg(feature = "tzap-online")]
pub(crate) use device::device_command;
#[cfg(feature = "tzap-online")]
pub(crate) use share::share_command;
#[cfg(feature = "tzap-online")]
pub(crate) use sign::{sign_command, verify_command};
#[cfg(not(feature = "tzap-online"))]
pub(crate) use unavailable::auth_command;
#[cfg(all(test, feature = "tzap-online"))]
pub(crate) use {contacts::contact_keygen_command, hosted::create_and_store_staging_enrollment_key, support::build_hosted_http_request};

// Everything below is the real command surface's shared context; the
// offline build compiles none of it.
#[cfg(feature = "tzap-online")]
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
#[cfg(feature = "tzap-online")]
pub(super) const MISSING_TZAP_SESSION: &str = "no local TZAP session";
#[cfg(feature = "tzap-online")]
pub(super) const DEFAULT_TZAP_CERT_VALIDITY_SECONDS: u64 = 90 * 24 * 60 * 60;
#[cfg(feature = "tzap-online")]
pub(super) const STAGING_ENROLLMENT_KEY_LABEL: &str = "Hosted TZAP enrollment signing key";

#[cfg(feature = "tzap-online")]
#[derive(Debug, Clone)]
pub(super) struct TzapCliContext {
    pub(super) state_dir: PathBuf,
    pub(super) account_key: String,
}

#[cfg(feature = "tzap-online")]
impl Default for TzapCliContext {
    fn default() -> Self {
        Self { state_dir: support::default_tzap_state_dir(), account_key: zmanager_core::local_identity_store::DEFAULT_IDENTITY_INVENTORY_ACCOUNT.to_owned() }
    }
}

#[cfg(feature = "tzap-online")]
#[derive(Debug, Clone)]
pub(super) struct AuthEndpointOptions {
    pub(super) environment: zmanager_core::auth_client::TzapHostedAuthEnvironment,
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
