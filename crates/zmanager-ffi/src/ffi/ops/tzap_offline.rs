//! Offline TZAP document verification retained by the reduced FFI profile.

use serde_json::{Value, json};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn current_unix_seconds() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).ok().and_then(|duration| i64::try_from(duration.as_secs()).ok()).unwrap_or(i64::MAX)
}

fn string_array(request: &Value, field: &str) -> Result<Vec<String>, String> {
    match request.get(field) {
        None => Ok(Vec::new()),
        Some(Value::Array(values)) => {
            values.iter().map(|value| value.as_str().map(str::to_owned).ok_or_else(|| format!("{field} must contain only strings"))).collect()
        }
        Some(_) => Err(format!("{field} must be an array of strings")),
    }
}

fn document_verification_result_json(result: &zmanager_core::document_verification::TzapDocumentVerificationResult) -> Value {
    json!({
        "ok": result.state != zmanager_core::trust::TzapVerificationState::Invalid,
        "state": result.state.as_str(),
        "trust_anchor_type": result.trust_anchor_type.as_str(),
        "reason": result.reason,
        "root_certificate_sha256": result.root_certificate_sha256,
        "public_metadata": result.public_metadata.as_ref().map(|metadata| {
            json!({
                "version": metadata.version,
                "public_signer_id": metadata.public_signer_id,
                "public_org_id": metadata.public_org_id,
                "public_device_id": metadata.public_device_id,
                "assurance_level": metadata.assurance_level.as_str(),
                "policy_oid": metadata.policy_oid,
            })
        }),
    })
}

/// Verifies a document envelope without requiring hosted transport or account state.
pub fn tzap_document_verify_json(request_json: String) -> String {
    let response = (|| {
        let request: Value = serde_json::from_str(&request_json).map_err(|error| error.to_string())?;
        let envelope = request.get("envelope").ok_or_else(|| "missing or invalid field: envelope".to_owned())?;
        let bytes = serde_json::to_vec(envelope).map_err(|error| error.to_string())?;
        let mut custom_trust_root_sha256 = string_array(&request, "custom_trust_root_sha256")?;
        let custom_root_paths = string_array(&request, "custom_trust_root_cert_paths")?.into_iter().map(PathBuf::from).collect::<Vec<_>>();
        let custom_trust_root_certificates_der = zmanager_core::trust::load_custom_root_certificate_files(&custom_root_paths, &mut custom_trust_root_sha256)?;
        let verifier_time_unix_seconds = request.get("verifier_time_unix_seconds").and_then(Value::as_i64).unwrap_or_else(current_unix_seconds);
        let options = zmanager_core::document_verification::TzapOfflineVerificationOptions {
            verifier_time_unix_seconds,
            official_root_pins: &zmanager_core::trust::OFFICIAL_TZAP_ROOT_PINS,
            official_root_certificates_der: Vec::new(),
            custom_trust_root_sha256,
            custom_trust_root_certificates_der,
            certificate_profile_options: zmanager_core::trust::TzapCertificateProfileOptions::default(),
        };
        Ok::<_, String>(document_verification_result_json(&zmanager_core::document_verification::verify_tzap_document_envelope_offline_json(&bytes, &options)))
    })();

    match response {
        Ok(value) => serde_json::to_string(&value).unwrap_or_else(|error| format!(r#"{{"ok":false,"error":"{error}"}}"#)),
        Err(error) => serde_json::to_string(&json!({ "ok": false, "error": error })).unwrap_or_else(|_| r#"{"ok":false,"error":"invalid request"}"#.to_owned()),
    }
}
