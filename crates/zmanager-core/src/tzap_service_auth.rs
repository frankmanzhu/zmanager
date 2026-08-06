//! Hosted-auth session storage and pending-handoff persistence (CR-136).
//!
//! Extracted from the tzap JSON service; the service imports these
//! `pub(crate)` items for its `tzap_auth_*_json` endpoints.

use crate::atomic_file::write_atomic_secret_file;
use crate::auth_client::TzapSessionStore;
use crate::trust;
use crate::tzap_service::{request_string, request_u64, required_request_string};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) const AUTH_PENDING_FILE: &str = "auth-pending.json";
const AUTH_SESSION_FILE: &str = "auth-session.json";

pub(crate) struct TzapFfiSessionStore {
    path: PathBuf,
}

impl TzapFfiSessionStore {
    pub(crate) fn new(state_dir: &Path) -> Self {
        Self { path: state_dir.join(AUTH_SESSION_FILE) }
    }
}

impl TzapSessionStore for TzapFfiSessionStore {
    fn save_session(
        &mut self,
        account_key: &str,
        session: crate::auth_client::TzapSessionRecord,
    ) -> Result<(), crate::auth_client::TzapAuthError> {
        let mut root = read_json_file(&self.path).unwrap_or_else(|| json!({ "sessions": {} }));
        if !root.is_object() {
            root = json!({ "sessions": {} });
        }
        root["sessions"][account_key] = session_json(&session, true);
        write_secret_json_file(&self.path, &root).map_err(|error| crate::auth_client::TzapAuthError::Storage {
            message: format!("could not write {}: {error}", self.path.display()),
        })
    }

    fn load_session(&self, account_key: &str) -> Option<crate::auth_client::TzapSessionRecord> {
        let root = read_json_file(&self.path)?;
        session_from_json(root.get("sessions")?.get(account_key)?).ok()
    }

    fn clear_session(&mut self, account_key: &str) -> Result<(), crate::auth_client::TzapAuthError> {
        let Some(mut root) = read_json_file(&self.path) else {
            return Ok(());
        };
        if let Some(sessions) = root.get_mut("sessions").and_then(Value::as_object_mut) {
            sessions.remove(account_key);
        }
        write_secret_json_file(&self.path, &root).map_err(|error| crate::auth_client::TzapAuthError::Storage {
            message: format!("could not write {}: {error}", self.path.display()),
        })
    }
}

pub(crate) fn parse_auth_environment(value: &str) -> Result<crate::auth_client::TzapHostedAuthEnvironment, String> {
    match value {
        "local" => Ok(crate::auth_client::TzapHostedAuthEnvironment::Local),
        "staging" => Ok(crate::auth_client::TzapHostedAuthEnvironment::Staging),
        "prod" => Ok(crate::auth_client::TzapHostedAuthEnvironment::Prod),
        _ => Err("environment must be local, staging, or prod".to_owned()),
    }
}

pub(crate) fn default_tzap_state_dir() -> PathBuf {
    std::env::var_os("ZMANAGER_TZAP_STATE_DIR").map_or_else(
        || {
            std::env::var_os("HOME").map_or_else(
                || PathBuf::from(".").join(".zmanager").join("tzap"),
                |home| PathBuf::from(home).join(".zmanager").join("tzap"),
            )
        },
        PathBuf::from,
    )
}

pub(crate) fn current_unix_seconds() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_secs())
}

fn read_json_file(path: &Path) -> Option<Value> {
    let bytes = fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn write_secret_json_file(path: &Path, value: &Value) -> std::io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(value).map_err(std::io::Error::other)?;
    write_atomic_secret_file(path, &bytes)
}

pub(crate) fn save_pending_auth(
    state_dir: &Path,
    pending: &crate::auth_client::TzapPendingAuthState,
) -> std::io::Result<()> {
    write_secret_json_file(
        &state_dir.join(AUTH_PENDING_FILE),
        &json!({
            "state": pending.state,
            "provider_id": pending.provider_id,
            "redirect_uri": pending.redirect_uri,
            "pkce_verifier": pending.pkce.verifier,
            "created_at_unix_seconds": pending.created_at_unix_seconds,
        }),
    )
}

pub(crate) fn load_pending_auth(state_dir: &Path) -> Result<crate::auth_client::TzapPendingAuthState, String> {
    let value = read_json_file(&state_dir.join(AUTH_PENDING_FILE))
        .ok_or_else(|| "no pending hosted-auth handoff".to_owned())?;
    let verifier = required_request_string(&value, "pkce_verifier")?;
    let pkce = crate::auth_client::TzapPkcePair::from_verifier(&verifier).map_err(|error| error.to_string())?;
    Ok(crate::auth_client::TzapPendingAuthState {
        state: required_request_string(&value, "state")?,
        provider_id: required_request_string(&value, "provider_id")?,
        redirect_uri: required_request_string(&value, "redirect_uri")?,
        pkce,
        created_at_unix_seconds: request_u64(&value, "created_at_unix_seconds")?
            .ok_or_else(|| "missing or invalid field: created_at_unix_seconds".to_owned())?,
    })
}

fn session_json(session: &crate::auth_client::TzapSessionRecord, include_token: bool) -> Value {
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

pub(crate) fn session_summary_json(session: &crate::auth_client::TzapSessionRecord) -> Value {
    session_summary_json_at(session, current_unix_seconds())
}

pub(crate) fn session_summary_json_at(session: &crate::auth_client::TzapSessionRecord, now_unix_seconds: u64) -> Value {
    json!({
        "audience": session.audience,
        "expires_at_unix_seconds": session.expires_at_unix_seconds,
        "expired": session.is_expired_at(now_unix_seconds),
        "identity_assurance": session.identity_assurance.as_str(),
        "selected_org_id": session.selected_org_id,
        "login_session_id": session.login_session_id,
    })
}

fn session_from_json(value: &Value) -> Result<crate::auth_client::TzapSessionRecord, String> {
    let assurance = required_request_string(value, "identity_assurance")?;
    let identity_assurance =
        trust::TzapIdentityAssurance::parse(&assurance).ok_or_else(|| "invalid identity assurance".to_owned())?;
    Ok(crate::auth_client::TzapSessionRecord {
        audience: required_request_string(value, "audience")?,
        access_token: crate::auth_client::TzapBearerToken::new(required_request_string(value, "access_token")?)
            .map_err(|error| error.to_string())?,
        expires_at_unix_seconds: request_u64(value, "expires_at_unix_seconds")?
            .ok_or_else(|| "missing or invalid field: expires_at_unix_seconds".to_owned())?,
        identity_assurance,
        selected_org_id: request_string(value, "selected_org_id")?,
        login_session_id: request_string(value, "login_session_id")?,
    })
}
