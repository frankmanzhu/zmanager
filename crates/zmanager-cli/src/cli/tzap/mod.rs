//! Hosted-TZAP command surface (CR-113, medium option).
//!
//! Split by domain from the former `cli/tzap.rs` dump ground: [`auth`],
//! [`cert`], [`device`], [`sign`], [`contacts`], [`share`], the hosted-cert
//! operations in [`hosted`], and the shared helpers in [`support`]. The
//! command entry points are re-exported here so the app dispatcher is
//! unchanged.

mod auth;
mod cert;
mod contacts;
mod device;
mod hosted;
mod share;
mod sign;
mod support;
#[cfg(test)]
mod tests;

pub(crate) use auth::auth_command;
pub(crate) use cert::{cert_command, me_command};
pub(crate) use contacts::contact_command;
pub(crate) use device::device_command;
pub(crate) use share::share_command;
pub(crate) use sign::{sign_command, verify_command};
#[cfg(test)]
pub(crate) use {
    contacts::contact_keygen_command, hosted::create_and_store_staging_enrollment_key,
    support::build_hosted_http_request,
};

use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use zmanager_core::auth_client::TzapSessionStore as _;

use support::{read_json_file, session_from_json, session_to_json, write_secret_json_file};

pub(super) const DEFAULT_TZAP_STATE_DIR_ENV: &str = "ZM_TZAP_STATE_DIR";
pub(super) const DEFAULT_TZAP_STATE_HOME_CHILD: &str = ".zmanager/tzap";
pub(super) const DEFAULT_TZAP_CLIENT_ID: &str = "zmanager-cli";
pub(crate) const DEFAULT_TZAP_REDIRECT_URI: &str = "tzap://auth/callback";
pub(super) const DEFAULT_TZAP_PROVIDER_ID: &str = "hosted";
pub(super) const AUTH_PENDING_FILE: &str = "auth-pending.json";
pub(super) const AUTH_SESSION_FILE: &str = "auth-session.json";
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
        Self {
            state_dir: support::default_tzap_state_dir(),
            account_key: zmanager_core::local_identity_store::DEFAULT_IDENTITY_INVENTORY_ACCOUNT.to_owned(),
        }
    }
}

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
pub(super) struct FileTzapSessionStore {
    path: PathBuf,
}

impl FileTzapSessionStore {
    pub(super) fn new(state_dir: &Path) -> Self {
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
