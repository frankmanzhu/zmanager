//! LocalSend JSON passthrough endpoints. Thin wrappers over
//! `zmanager-localsend`'s registry — no LAN/protocol logic lives here.

fn ok_or_error<T: serde::Serialize>(result: Result<T, zmanager_localsend::LocalSendBridgeError>) -> String {
    match result {
        Ok(value) => serde_json::to_string(&value).unwrap_or_else(|error| bridge_error_envelope(&error.to_string())),
        Err(error) => bridge_error_envelope(&error.to_string()),
    }
}

fn bridge_error_envelope(message: &str) -> String {
    serde_json::json!({ "ok": false, "error": message }).to_string()
}

fn parse_or_error<T: serde::de::DeserializeOwned>(request_json: &str) -> Result<T, String> {
    serde_json::from_str(request_json).map_err(|error| bridge_error_envelope(&format!("invalid request: {error}")))
}

pub fn localsend_discover_json(request_json: String) -> String {
    let request = match parse_or_error(&request_json) {
        Ok(request) => request,
        Err(envelope) => return envelope,
    };
    let devices = zmanager_localsend::registry().discover(request);
    ok_or_error(devices)
}

pub fn localsend_start_receiver_json(request_json: String) -> String {
    let request = match parse_or_error(&request_json) {
        Ok(request) => request,
        Err(envelope) => return envelope,
    };
    ok_or_error(zmanager_localsend::registry().start_receiver(request).map(|()| serde_json::json!({ "ok": true })))
}

pub fn localsend_stop_receiver_json(_request_json: String) -> String {
    ok_or_error(zmanager_localsend::registry().stop_receiver().map(|()| serde_json::json!({ "ok": true })))
}

pub fn localsend_poll_events_json(_request_json: String) -> String {
    serde_json::to_string(&zmanager_localsend::registry().poll_events()).unwrap_or_else(|error| bridge_error_envelope(&error.to_string()))
}

pub fn localsend_respond_to_transfer_json(request_json: String) -> String {
    let request = match parse_or_error(&request_json) {
        Ok(request) => request,
        Err(envelope) => return envelope,
    };
    ok_or_error(zmanager_localsend::registry().respond_to_transfer(request).map(|()| serde_json::json!({ "ok": true })))
}

pub fn localsend_send_file_json(request_json: String) -> String {
    let request = match parse_or_error(&request_json) {
        Ok(request) => request,
        Err(envelope) => return envelope,
    };
    ok_or_error(zmanager_localsend::registry().send_file(request))
}

pub fn localsend_cancel_send_json(request_json: String) -> String {
    let request = match parse_or_error(&request_json) {
        Ok(request) => request,
        Err(envelope) => return envelope,
    };
    ok_or_error(zmanager_localsend::registry().cancel_send(&request).map(|()| serde_json::json!({ "ok": true })))
}
