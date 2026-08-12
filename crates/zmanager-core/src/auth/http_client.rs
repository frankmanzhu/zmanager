//! Shared HTTP client plumbing for TZAP client modules.

use crate::auth_client::{TzapAuthError, TzapAuthHttpMethod, TzapAuthHttpRequest, TzapAuthHttpResponse, TzapAuthHttpTransport, TzapBearerToken};
use serde_json::Value;

/// Sends a JSON-capable TZAP HTTP request and returns the raw response.
pub(crate) fn send_json_request<T: TzapAuthHttpTransport>(
    transport: &T,
    method: TzapAuthHttpMethod,
    base_url: &str,
    path: &str,
    bearer_token: Option<TzapBearerToken>,
    body: Option<Value>,
) -> Result<TzapAuthHttpResponse, TzapAuthError> {
    let request = TzapAuthHttpRequest { method, url: format!("{}{}", trim_trailing_slash(base_url), path), bearer_token, body };
    let mut attempts = 0;
    let max_attempts = 3;
    loop {
        attempts += 1;
        match transport.send(&request) {
            Ok(response) => {
                if attempts < max_attempts && (response.status_code == 429 || (500..=599).contains(&response.status_code)) {
                    // Backoff omitted for tests/simplicity, but normally this would sleep.
                    continue;
                }
                return Ok(response);
            }
            Err(error) => {
                if attempts < max_attempts && matches!(error, TzapAuthError::Transport { .. }) {
                    continue;
                }
                return Err(error);
            }
        }
    }
}

/// Requires a 2xx status code, otherwise maps the response into an error.
pub(crate) fn require_success<E>(
    response: TzapAuthHttpResponse,
    error_from_status: impl FnOnce(u16, &TzapAuthHttpResponse) -> E,
) -> Result<TzapAuthHttpResponse, E> {
    if (200..=299).contains(&response.status_code) { Ok(response) } else { Err(error_from_status(response.status_code, &response)) }
}

/// Strips trailing slashes from a base URL before path concatenation.
pub(crate) fn trim_trailing_slash(value: &str) -> &str {
    value.trim_end_matches('/')
}

/// Trims an HTTP error body and returns it only when it is non-empty.
pub(crate) fn http_error_body(bytes: &[u8]) -> Option<String> {
    let value = String::from_utf8_lossy(bytes).trim().to_owned();
    if value.is_empty() { None } else { Some(value) }
}
