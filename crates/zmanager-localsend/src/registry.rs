//! Persistent LocalSend receiver + one-shot discovery/send, bridged to a
//! synchronous, JSON-shaped surface for FFI callers (`zmanager-ffi`) and for
//! `zmanager-desktop`'s direct-Rust callers alike.
//!
//! `localsend-rs` is async-native (tokio, axum) throughout, unlike the rest
//! of this workspace's HTTP-backed logic (`zmanager-tzap-hosted` stays
//! synchronous behind an injected transport trait). This crate owns the one
//! tokio runtime that bridges the two worlds; nothing above this module
//! needs to know LocalSend is async at all.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

use localsend_rs::DeviceInfoBuilder;
use localsend_rs::client::client::ProgressCallback;
use localsend_rs::protocol::{DeviceInfo, FileId, Protocol};
use localsend_rs::server::{LocalSendServer, PendingRequest, ServerEvent};
use serde::{Deserialize, Serialize};
use tokio::task::AbortHandle;

const MAX_QUEUED_EVENTS: usize = 512;

static REGISTRY: OnceLock<Arc<LocalSendRegistry>> = OnceLock::new();

/// The process-wide registry. Callers should go through [`registry`] rather
/// than constructing this directly.
pub struct LocalSendRegistry {
    runtime: tokio::runtime::Runtime,
    state: Mutex<RegistryState>,
}

#[derive(Default)]
struct RegistryState {
    server: Option<LocalSendServer>,
    pending_requests: HashMap<String, PendingRequest>,
    next_request_id: u64,
    events: VecDeque<QueuedEvent>,
    /// Abort handles for in-flight `send_file` tasks, keyed by the
    /// caller-supplied `SendFileRequest::send_id`. `send_file` blocks the
    /// calling thread on the spawned task's `JoinHandle`, so aborting via
    /// this handle from a *different* thread (e.g. a "Cancel" button) is the
    /// only way to unblock it early — cooperative checks inside the upload
    /// loop aren't reachable from here the way they were in the native
    /// per-platform implementations this crate replaces.
    active_sends: HashMap<String, AbortHandle>,
}

/// Returns the shared registry, creating it (and its runtime) on first use.
pub fn registry() -> Arc<LocalSendRegistry> {
    REGISTRY
        .get_or_init(|| {
            Arc::new(LocalSendRegistry {
                runtime: tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .expect("zmanager-localsend runtime failed to start"),
                state: Mutex::new(RegistryState::default()),
            })
        })
        .clone()
}

#[derive(Debug, thiserror::Error)]
pub enum LocalSendBridgeError {
    #[error("localsend error: {0}")]
    LocalSend(#[from] localsend_rs::error::LocalSendError),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("no receiver is running")]
    NoReceiverRunning,
    #[error("receiver is already running")]
    ReceiverAlreadyRunning,
    #[error("unknown transfer request id: {0}")]
    UnknownRequestId(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("send was cancelled")]
    SendCancelled,
    #[error("unknown send id: {0}")]
    UnknownSendId(String),
}

pub type BridgeResult<T> = Result<T, LocalSendBridgeError>;

// ---------------------------------------------------------------------
// Receiver lifecycle
// ---------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct StartReceiverRequest {
    pub alias: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub https: bool,
    pub save_dir: PathBuf,
    #[serde(default)]
    pub auto_accept: bool,
    #[serde(default)]
    pub pin: Option<String>,
}

fn default_port() -> u16 {
    localsend_rs::protocol::DEFAULT_HTTP_PORT
}

impl LocalSendRegistry {
    pub fn start_receiver(&self, request: StartReceiverRequest) -> BridgeResult<()> {
        {
            let state = self.state.lock().expect("registry lock poisoned");
            if state.server.is_some() {
                return Err(LocalSendBridgeError::ReceiverAlreadyRunning);
            }
        }

        let protocol = if request.https { Protocol::Https } else { Protocol::Http };
        let mut builder =
            LocalSendServer::builder().alias(request.alias).port(request.port).save_dir(&request.save_dir).protocol(protocol).auto_accept(request.auto_accept);
        if let Some(pin) = request.pin.as_ref() {
            builder = builder.pin(pin.clone());
        }
        if request.https {
            let cert = localsend_rs::generate_tls_certificate()?;
            builder = builder.tls_certificate(cert);
        }

        // `LocalSendServerBuilder::build()` already starts the server
        // internally (binds the real socket and spawns the serve task,
        // `localsend-rs/src/server/server.rs:587`) before handing back the
        // events receiver via `take_events()` — it is not a "configure only"
        // step the way the name suggests. Calling `.start()` again here
        // would try to rebind the port it just bound.
        let (server, mut events_rx) = self.runtime.block_on(builder.build())?;

        let registry_for_pump = registry();
        self.runtime.spawn(async move {
            while let Some(event) = events_rx.recv().await {
                registry_for_pump.absorb_event(event);
            }
        });

        let mut state = self.state.lock().expect("registry lock poisoned");
        state.server = Some(server);
        Ok(())
    }

    pub fn stop_receiver(&self) -> BridgeResult<()> {
        let server = {
            let mut state = self.state.lock().expect("registry lock poisoned");
            state.pending_requests.clear();
            state.server.take()
        };
        let Some(mut server) = server else {
            return Err(LocalSendBridgeError::NoReceiverRunning);
        };
        self.runtime.block_on(server.stop());
        Ok(())
    }

    /// The receiver's actual bound port, useful when [`StartReceiverRequest::port`]
    /// was `0` (OS-assigned) — the server resolves the real port during its
    /// own bind, before any caller could otherwise learn it. `None` if no
    /// receiver is running.
    pub fn receiver_port(&self) -> Option<u16> {
        let state = self.state.lock().expect("registry lock poisoned");
        state.server.as_ref().map(LocalSendServer::port)
    }

    /// The receiver's own fingerprint — under `https: true` this is the SHA-256
    /// of the TLS certificate `start_receiver` generated, resolved only once
    /// the server has actually bound (same reasoning as [`receiver_port`](Self::receiver_port)).
    /// `None` if no receiver is running.
    pub fn receiver_fingerprint(&self) -> Option<String> {
        let state = self.state.lock().expect("registry lock poisoned");
        state.server.as_ref().map(|server| server.device().fingerprint.clone())
    }

    /// Converts one `ServerEvent` into a queued, JSON-serializable event.
    /// `TransferRequest`/`WebShareRequest` carry a non-serializable
    /// one-shot responder, so those are stashed by request id and only
    /// their descriptive fields are queued; the app responds later via
    /// [`LocalSendRegistry::respond_to_transfer`].
    fn absorb_event(&self, event: ServerEvent) {
        let queued = {
            let mut state = self.state.lock().expect("registry lock poisoned");
            match event {
                ServerEvent::PeerRegistered(device) => QueuedEvent::PeerRegistered { device: device.into() },
                ServerEvent::TransferRequest(pending) => {
                    state.next_request_id = state.next_request_id.saturating_add(1);
                    let request_id = format!("transfer-{}-{}", std::process::id(), state.next_request_id);
                    let sender = pending.sender().clone().into();
                    let files: Vec<TransferFile> = pending
                        .files()
                        .values()
                        .map(|metadata| TransferFile {
                            id: metadata.id.as_str().to_owned(),
                            file_name: metadata.file_name.clone(),
                            size: metadata.size,
                            file_type: metadata.file_type.clone(),
                        })
                        .collect();
                    state.pending_requests.insert(request_id.clone(), pending);
                    QueuedEvent::TransferRequest { request_id, sender, files }
                }
                ServerEvent::TextReceived { session_id, text, sender_alias } => {
                    QueuedEvent::TextReceived { session_id: session_id.as_str().to_owned(), text, sender_alias }
                }
                ServerEvent::FileReceiveProgress { session_id, file_id, file_name, sender_alias, bytes_received, total_bytes, file_count } => {
                    QueuedEvent::FileReceiveProgress {
                        session_id: session_id.as_str().to_owned(),
                        file_id: file_id.as_str().to_owned(),
                        file_name,
                        sender_alias,
                        bytes_received,
                        total_bytes,
                        file_count,
                    }
                }
                ServerEvent::FileReceived { session_id, file_id, file_name, path, .. } => {
                    QueuedEvent::FileReceived { session_id: session_id.as_str().to_owned(), file_id: file_id.as_str().to_owned(), file_name, path }
                }
                ServerEvent::SessionDone { session_id } => QueuedEvent::SessionDone { session_id: session_id.as_str().to_owned() },
                // Web Share (browser-facing) events are out of scope for the
                // device-to-device workflows this crate wraps; drop them.
                ServerEvent::WebShareRequest(_) | ServerEvent::WebShareDownloadProgress { .. } | ServerEvent::WebShareSessionDone { .. } => return,
            }
        };
        self.push_event(queued);
    }

    /// Appends one event to the shared, bounded queue `poll_events` drains.
    /// Shared by the receive-event pump (`absorb_event`) and the send-side
    /// progress callback in [`LocalSendRegistry::send_file`] — both push
    /// into the same queue, so the eviction policy only needs to live once.
    fn push_event(&self, event: QueuedEvent) {
        let mut state = self.state.lock().expect("registry lock poisoned");
        if state.events.len() >= MAX_QUEUED_EVENTS {
            state.events.pop_front();
        }
        state.events.push_back(event);
    }

    pub fn poll_events(&self) -> PollEventsResult {
        let mut state = self.state.lock().expect("registry lock poisoned");
        PollEventsResult { events: state.events.drain(..).collect() }
    }

    pub fn respond_to_transfer(&self, request: RespondToTransferRequest) -> BridgeResult<()> {
        let pending = {
            let mut state = self.state.lock().expect("registry lock poisoned");
            state.pending_requests.remove(&request.request_id).ok_or_else(|| LocalSendBridgeError::UnknownRequestId(request.request_id.clone()))?
        };
        match request.decision {
            TransferDecisionKind::Accept => pending.accept(),
            TransferDecisionKind::AcceptFiles => {
                let ids = request.file_ids.into_iter().map(FileId).collect();
                pending.accept_files(ids);
            }
            TransferDecisionKind::Decline => pending.decline(),
            TransferDecisionKind::Refuse => pending.refuse(request.reason.unwrap_or_else(|| "rejected".to_owned())),
        }
        Ok(())
    }

    // ---------------------------------------------------------------------
    // Discovery — a bounded sweep, not a persistent background listener.
    // ---------------------------------------------------------------------

    pub fn discover(&self, request: DiscoverRequest) -> BridgeResult<Vec<DiscoveredDevice>> {
        self.runtime.block_on(async move {
            use localsend_rs::{Discovery, MulticastDiscovery};

            let found: Arc<Mutex<Vec<DeviceInfo>>> = Arc::new(Mutex::new(Vec::new()));
            let sink = found.clone();

            let protocol = if request.https { Protocol::Https } else { Protocol::Http };
            let device = DeviceInfoBuilder::new(request.alias, request.port).protocol(protocol).build();
            let mut discovery = MulticastDiscovery::new_with_device(device);
            discovery.on_discovered(move |found_device| {
                let mut guard = sink.lock().expect("discovery result lock poisoned");
                if !guard.iter().any(|existing| existing.fingerprint == found_device.fingerprint) {
                    guard.push(found_device);
                }
            });
            discovery.start().await?;
            discovery.announce_presence().await?;
            tokio::time::sleep(std::time::Duration::from_millis(request.timeout_ms)).await;
            discovery.stop();

            let devices = found.lock().expect("discovery result lock poisoned").clone();
            Ok(devices.into_iter().map(DiscoveredDevice::from).collect())
        })
    }

    // ---------------------------------------------------------------------
    // Send — one file, one push, blocking on completion.
    // ---------------------------------------------------------------------

    pub fn send_file(&self, request: SendFileRequest) -> BridgeResult<SendFileResult> {
        if !request.file_path.is_file() {
            return Err(LocalSendBridgeError::InvalidRequest(format!("not a file: {}", request.file_path.display())));
        }

        let send_id = request.send_id.clone();
        let alias = request.alias;
        let self_port = request.self_port;
        let https = request.https;
        let target: DeviceInfo = request.target.into();
        let file_path = request.file_path;
        let pin = request.pin;

        let progress_registry = registry();
        let progress_send_id = send_id.clone();

        let task = self.runtime.spawn(async move {
            use localsend_rs::{LocalSendClient, TlsTrustPolicy};

            let protocol = if https { Protocol::Https } else { Protocol::Http };
            let self_device = DeviceInfoBuilder::new(alias, self_port).protocol(protocol).build();
            // `LocalSendClient::new` builds a plain reqwest client that does
            // ordinary TLS validation — it will always reject a LocalSend
            // peer's self-signed cert. HTTPS targets need the pinned trust
            // policy instead, keyed off the fingerprint `discover()` already
            // returned for this device (LocalSend's actual security model:
            // trust is established by the fingerprint shown to the user at
            // send time, not by a CA chain).
            let client = if matches!(target.protocol, Protocol::Https) {
                LocalSendClient::with_trust_policy(self_device, TlsTrustPolicy::PinnedFingerprint(target.fingerprint.clone()))?
            } else {
                LocalSendClient::new(self_device)
            };

            let metadata = localsend_rs::build_file_metadata(&file_path).await?;
            let file_id = metadata.id.clone();
            let file_name = metadata.file_name.clone();
            let mut files = HashMap::new();
            files.insert(file_id.clone(), metadata);

            let prepared = client.prepare_upload(&target, files, pin.as_deref()).await?;
            let token = prepared
                .files
                .get(&file_id)
                .ok_or_else(|| LocalSendBridgeError::InvalidRequest("receiver did not return an upload token for the offered file".to_owned()))?
                .clone();

            let session_id = prepared.session_id.clone();
            let progress: ProgressCallback = {
                let registry = progress_registry.clone();
                let send_id = progress_send_id.clone();
                let session_id = session_id.as_str().to_owned();
                let file_id = file_id.as_str().to_owned();
                let file_name = file_name.clone();
                Box::new(move |bytes_sent, total_bytes, rate_bytes_per_second| {
                    registry.push_event(QueuedEvent::FileSendProgress {
                        send_id: send_id.clone(),
                        session_id: session_id.clone(),
                        file_id: file_id.clone(),
                        file_name: file_name.clone(),
                        bytes_sent,
                        total_bytes,
                        rate_bytes_per_second,
                    });
                })
            };

            client.upload_file_with_rate_limit(&target, &session_id, &file_id, &token, &file_path, Some(progress), None).await?;

            Ok::<SendFileResult, LocalSendBridgeError>(SendFileResult { session_id: session_id.as_str().to_owned(), file_id: file_id.as_str().to_owned() })
        });

        {
            let mut state = self.state.lock().expect("registry lock poisoned");
            state.active_sends.insert(send_id.clone(), task.abort_handle());
        }

        let result = self.runtime.block_on(task);

        {
            let mut state = self.state.lock().expect("registry lock poisoned");
            state.active_sends.remove(&send_id);
        }

        match result {
            Ok(inner) => inner,
            Err(join_error) if join_error.is_cancelled() => Err(LocalSendBridgeError::SendCancelled),
            Err(join_error) => Err(LocalSendBridgeError::InvalidRequest(format!("send task failed unexpectedly: {join_error}"))),
        }
    }

    /// Aborts the in-flight `send_file` task registered under
    /// `request.send_id`, unblocking its `block_on` on this or another
    /// thread with [`LocalSendBridgeError::SendCancelled`]. This is a hard
    /// abort (the underlying connection is simply dropped), not a
    /// protocol-level cancel notice to the peer — `localsend-rs`'s
    /// `LocalSendClient::cancel` exists for that and is a separate concern.
    pub fn cancel_send(&self, request: CancelSendRequest) -> BridgeResult<()> {
        let state = self.state.lock().expect("registry lock poisoned");
        let handle = state.active_sends.get(&request.send_id).ok_or_else(|| LocalSendBridgeError::UnknownSendId(request.send_id.clone()))?;
        handle.abort();
        Ok(())
    }
}

// ---------------------------------------------------------------------
// JSON-facing DTOs
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfoDto {
    pub alias: String,
    pub fingerprint: String,
    pub port: u16,
    pub protocol: String,
    pub ip: Option<String>,
    pub device_model: Option<String>,
}

impl From<DeviceInfo> for DeviceInfoDto {
    fn from(device: DeviceInfo) -> Self {
        Self {
            alias: device.alias,
            fingerprint: device.fingerprint,
            port: device.port,
            protocol: device.protocol.as_str().to_owned(),
            ip: device.ip,
            device_model: device.device_model,
        }
    }
}

impl From<DeviceInfoDto> for DeviceInfo {
    fn from(dto: DeviceInfoDto) -> Self {
        let mut device = DeviceInfo::new(dto.alias, dto.port, Protocol::from(dto.protocol.as_str()));
        device.fingerprint = dto.fingerprint;
        device.ip = dto.ip;
        device.device_model = dto.device_model;
        device
    }
}

pub type DiscoveredDevice = DeviceInfoDto;

#[derive(Debug, Deserialize)]
pub struct DiscoverRequest {
    pub alias: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub https: bool,
    #[serde(default = "default_discover_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_discover_timeout_ms() -> u64 {
    3_000
}

#[derive(Debug, Serialize)]
pub struct TransferFile {
    pub id: String,
    pub file_name: String,
    pub size: u64,
    pub file_type: String,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type")]
pub enum QueuedEvent {
    PeerRegistered {
        device: DeviceInfoDto,
    },
    TransferRequest {
        request_id: String,
        sender: DeviceInfoDto,
        files: Vec<TransferFile>,
    },
    TextReceived {
        session_id: String,
        text: String,
        sender_alias: String,
    },
    FileReceiveProgress {
        session_id: String,
        file_id: String,
        file_name: String,
        sender_alias: String,
        bytes_received: u64,
        total_bytes: u64,
        file_count: usize,
    },
    FileReceived {
        session_id: String,
        file_id: String,
        file_name: String,
        path: PathBuf,
    },
    SessionDone {
        session_id: String,
    },
    FileSendProgress {
        send_id: String,
        session_id: String,
        file_id: String,
        file_name: String,
        bytes_sent: u64,
        total_bytes: u64,
        rate_bytes_per_second: f64,
    },
}

#[derive(Debug, Serialize)]
pub struct PollEventsResult {
    pub events: Vec<QueuedEvent>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferDecisionKind {
    Accept,
    AcceptFiles,
    Decline,
    Refuse,
}

#[derive(Debug, Deserialize)]
pub struct RespondToTransferRequest {
    pub request_id: String,
    pub decision: TransferDecisionKind,
    #[serde(default)]
    pub file_ids: Vec<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SendFileRequest {
    /// Caller-generated identifier for this send, used to key
    /// [`LocalSendRegistry::cancel_send`] and to tag [`QueuedEvent::FileSendProgress`]
    /// events — the registry has no way to name an in-flight send otherwise,
    /// since `send_file` may be called for several files/targets concurrently.
    pub send_id: String,
    pub alias: String,
    #[serde(default = "default_port")]
    pub self_port: u16,
    #[serde(default)]
    pub https: bool,
    pub target: DeviceInfoDto,
    pub file_path: PathBuf,
    #[serde(default)]
    pub pin: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SendFileResult {
    pub session_id: String,
    pub file_id: String,
}

#[derive(Debug, Deserialize)]
pub struct CancelSendRequest {
    pub send_id: String,
}
