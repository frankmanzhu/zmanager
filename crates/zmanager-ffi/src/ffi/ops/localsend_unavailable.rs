//! Stable FFI stubs for builds without the `localsend` feature.

use crate::ffi::error::{ERROR_UNSUPPORTED_FORMAT, bridge_error};
use crate::ffi::types::{
    CancelSendRequest, DeviceInfoDto, DiscoverRequest, PollEventsResult, RespondToTransferRequest, SendFileRequest, SendFileResult, StartReceiverRequest,
    ZmanagerGuiError,
};

fn unavailable(operation: &str) -> ZmanagerGuiError {
    bridge_error(ERROR_UNSUPPORTED_FORMAT, format!("The {operation} feature is not enabled in this build."), None, crate::ffi::types::BridgeSeverity::Warning, false)
}

#[allow(non_snake_case)]
pub fn localsendDiscover(_request: DiscoverRequest) -> Result<Vec<DeviceInfoDto>, ZmanagerGuiError> {
    Err(unavailable("localsendDiscover"))
}

#[allow(non_snake_case)]
pub fn localsendStartReceiver(_request: StartReceiverRequest) -> Result<(), ZmanagerGuiError> {
    Err(unavailable("localsendStartReceiver"))
}

#[allow(non_snake_case)]
pub fn localsendStopReceiver() -> Result<(), ZmanagerGuiError> {
    Err(unavailable("localsendStopReceiver"))
}

#[allow(non_snake_case)]
pub fn localsendPollEvents() -> PollEventsResult {
    PollEventsResult { events: Vec::new() }
}

#[allow(non_snake_case)]
pub fn localsendRespondToTransfer(_request: RespondToTransferRequest) -> Result<(), ZmanagerGuiError> {
    Err(unavailable("localsendRespondToTransfer"))
}

#[allow(non_snake_case)]
pub fn localsendSendFile(_request: SendFileRequest) -> Result<SendFileResult, ZmanagerGuiError> {
    Err(unavailable("localsendSendFile"))
}

#[allow(non_snake_case)]
pub fn localsendCancelSend(_request: CancelSendRequest) -> Result<(), ZmanagerGuiError> {
    Err(unavailable("localsendCancelSend"))
}
