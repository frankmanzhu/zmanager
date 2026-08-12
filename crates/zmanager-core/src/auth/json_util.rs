//! Shared JSON field extraction helpers for TZAP client modules.
//!
//! Only flat, field-shaped errors belong here. The auth and document-envelope
//! clients keep their path-shaped error helpers per-file (see round-1 CR-036:
//! their `MissingField { path, field }` diagnostics are semantically richer
//! than the flat `invalid_field(field)` form).

use crate::certificate_lifecycle::TzapCertificateLifecycleError;
use crate::contact_card::TzapContactCardError;
use crate::enrollment_client::TzapEnrollmentError;
use crate::local_identity_store::TzapLocalIdentityStoreError;
use crate::status_client::TzapStatusClientError;
use serde_json::{Map, Value};

/// Error types that can report a named JSON field on parse failures.
pub(crate) trait JsonFieldError: Sized {
    fn invalid_field(field: &'static str) -> Self;
}

impl JsonFieldError for TzapEnrollmentError {
    fn invalid_field(field: &'static str) -> Self {
        Self::InvalidField { field }
    }
}

impl JsonFieldError for TzapStatusClientError {
    fn invalid_field(field: &'static str) -> Self {
        Self::InvalidField { field }
    }
}

impl JsonFieldError for TzapCertificateLifecycleError {
    fn invalid_field(field: &'static str) -> Self {
        Self::InvalidField { field }
    }
}

impl JsonFieldError for TzapLocalIdentityStoreError {
    fn invalid_field(field: &'static str) -> Self {
        Self::InvalidField { field }
    }
}

impl JsonFieldError for TzapContactCardError {
    fn invalid_field(field: &'static str) -> Self {
        Self::InvalidField { field }
    }
}

pub(crate) fn json_object<'a, E: JsonFieldError>(value: &'a Value, field: &'static str) -> Result<&'a Map<String, Value>, E> {
    value.as_object().ok_or_else(|| E::invalid_field(field))
}

pub(crate) fn required_field<'a, E: JsonFieldError>(object: &'a Map<String, Value>, field: &'static str) -> Result<&'a Value, E> {
    object.get(field).ok_or_else(|| E::invalid_field(field))
}

pub(crate) fn required_string<E: JsonFieldError>(object: &Map<String, Value>, field: &'static str) -> Result<String, E> {
    required_string_value(required_field(object, field)?, field)
}

pub(crate) fn required_string_value<E: JsonFieldError>(value: &Value, field: &'static str) -> Result<String, E> {
    value.as_str().filter(|value| !value.is_empty()).map(ToOwned::to_owned).ok_or_else(|| E::invalid_field(field))
}

pub(crate) fn required_array<'a, E: JsonFieldError>(object: &'a Map<String, Value>, field: &'static str) -> Result<&'a Vec<Value>, E> {
    required_field(object, field)?.as_array().ok_or_else(|| E::invalid_field(field))
}

pub(crate) fn required_bool<E: JsonFieldError>(object: &Map<String, Value>, field: &'static str) -> Result<bool, E> {
    required_field(object, field)?.as_bool().ok_or_else(|| E::invalid_field(field))
}

pub(crate) fn optional_string<E: JsonFieldError>(object: &Map<String, Value>, field: &'static str) -> Result<Option<String>, E> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value.as_str().filter(|value| !value.is_empty()).map(|value| Some(value.to_owned())).ok_or_else(|| E::invalid_field(field)),
    }
}

pub(crate) fn required_u64<E: JsonFieldError>(object: &Map<String, Value>, field: &'static str) -> Result<u64, E> {
    required_field(object, field)?.as_u64().ok_or_else(|| E::invalid_field(field))
}

pub(crate) fn optional_u64<E: JsonFieldError>(object: &Map<String, Value>, field: &'static str) -> Result<Option<u64>, E> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value.as_u64().map(Some).ok_or_else(|| E::invalid_field(field)),
    }
}
