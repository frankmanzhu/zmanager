//! Same-process loopback verification: a receiver started by this crate
//! actually accepts a push sent by this crate's own send path, over a real
//! TCP socket. This is the one thing that can be verified without a second
//! physical device or simulator — it confirms the registry wiring (runtime,
//! server lifecycle, client send) is actually connected correctly, not just
//! that each piece compiles in isolation. It does **not** substitute for
//! real interop testing against the existing mobile app, which needs a
//! real second device — see the crate's implementation plan.

use std::io::Write as _;
use std::time::Duration;

use zmanager_localsend::{DeviceInfoDto, SendFileRequest, StartReceiverRequest};

#[test]
fn a_pushed_file_arrives_intact_on_the_receiver_this_crate_started() {
    let registry = zmanager_localsend::registry();
    let receive_dir = tempfile::tempdir().expect("tempdir");
    let source_dir = tempfile::tempdir().expect("tempdir");

    let source_path = source_dir.path().join("hello.txt");
    let contents = b"loopback verification payload";
    std::fs::File::create(&source_path).expect("create source file").write_all(contents).expect("write source file");

    // Request port 0 (OS-assigned) rather than probing a free port and
    // rebinding it a moment later — the latter is a real, reproducible race
    // on some machines (confirmed directly against the vendored fork,
    // independent of this crate: a `std` probe-then-drop followed by a
    // `tokio::net::TcpListener::bind` on that exact port a moment later can
    // return `AddrInUse` even though nothing else was observably holding
    // it). Port 0 avoids the race entirely: the OS assigns an available
    // port atomically as part of the one real bind, and
    // `LocalSendRegistry::receiver_port` reads back what it picked.
    registry
        .start_receiver(StartReceiverRequest {
            alias: "loopback-receiver".to_owned(),
            port: 0,
            https: false,
            save_dir: receive_dir.path().to_path_buf(),
            auto_accept: true,
            pin: None,
        })
        .expect("receiver must start on an OS-assigned port");
    let port = registry.receiver_port().expect("receiver_port must report the just-bound port");

    let target = DeviceInfoDto {
        alias: "loopback-receiver".to_owned(),
        fingerprint: String::new(),
        port,
        protocol: "http".to_owned(),
        ip: Some("127.0.0.1".to_owned()),
        device_model: None,
    };

    let result = registry.send_file(SendFileRequest {
        alias: "loopback-sender".to_owned(),
        // The client never binds `self_port` — it's only a label carried in
        // outbound requests (see `LocalSendClient::new`) — so 0 is fine here.
        self_port: 0,
        https: false,
        target,
        file_path: source_path.clone(),
        pin: None,
    });

    // Give the receiver's async write-and-publish a moment to land before
    // asserting on disk state; poll rather than sleep-and-hope.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let received_path = receive_dir.path().join("hello.txt");
    while std::time::Instant::now() < deadline && !received_path.exists() {
        std::thread::sleep(Duration::from_millis(50));
    }

    registry.stop_receiver().expect("receiver was running and must stop cleanly");

    let send_result = result.expect("send_file must succeed against a receiver that just auto-accepted");
    assert!(!send_result.session_id.is_empty());

    let received = std::fs::read(&received_path).expect("receiver must have written the file to its save_dir");
    assert_eq!(received, contents, "received bytes must match exactly what was sent");
}
