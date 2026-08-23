//! Stable FFI stubs for builds without the `localsend` feature.

fn unavailable(operation: &str) -> String {
    format!(r#"{{"ok":false,"error":"localsend feature not enabled in this build","operation":"{operation}"}}"#)
}

macro_rules! unavailable_json_endpoint {
    ($name:ident, $operation:literal) => {
        pub fn $name(_request_json: String) -> String {
            unavailable($operation)
        }
    };
}

unavailable_json_endpoint!(localsend_discover_json, "localsend_discover_json");
unavailable_json_endpoint!(localsend_start_receiver_json, "localsend_start_receiver_json");
unavailable_json_endpoint!(localsend_stop_receiver_json, "localsend_stop_receiver_json");
unavailable_json_endpoint!(localsend_poll_events_json, "localsend_poll_events_json");
unavailable_json_endpoint!(localsend_respond_to_transfer_json, "localsend_respond_to_transfer_json");
unavailable_json_endpoint!(localsend_send_file_json, "localsend_send_file_json");
unavailable_json_endpoint!(localsend_cancel_send_json, "localsend_cancel_send_json");
