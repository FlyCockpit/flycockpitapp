//! Linux coturn conformance for the real TURN allocation driver.
//!
//! Compiled only under the `turn-coturn-conformance` feature (so the default
//! workspace suite never needs Docker) and `#[ignore]`d so it runs only when
//! explicitly requested. The Linux CI leg starts a pinned coturn image, exports
//! the fixture credentials, and runs:
//!
//! ```sh
//! COTURN_CONFORMANCE=1 \
//!   TURN_HOST=127.0.0.1 TURN_UDP_PORT=3478 TURN_TCP_PORT=3478 TURN_TLS_PORT=5349 \
//!   TURN_USER=... TURN_PASS=... TURN_TLS_SNI=localhost \
//!   cargo nextest run --locked -p cockpit-core \
//!     --features turn-coturn-conformance \
//!     remote_turn_socket_provider_coturn_conformance --run-ignored all
//! ```
//!
//! It proves UDP/TCP/TLS allocate against real coturn, rejects a bad
//! credential, and honors the cancellation (deadline) bound. It never contacts
//! a public TURN host: all endpoints come from the CI-local coturn.
#![cfg(feature = "turn-coturn-conformance")]

use std::net::SocketAddr;
use std::time::Duration;

use cockpit_core::daemon::turn_socket_provider::io::drive_allocation;
use cockpit_core::daemon::turn_socket_provider::{ConnectError, ConnectionPlan, TurnTransport};

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("coturn conformance requires env var {key}"))
}

fn addr(host: &str, port_key: &str) -> SocketAddr {
    format!("{host}:{}", env(port_key))
        .parse()
        .expect("valid coturn socket addr")
}

#[tokio::test]
#[ignore = "requires a live coturn instance (Linux CI leg, COTURN_CONFORMANCE=1)"]
async fn remote_turn_socket_provider_coturn_conformance() {
    assert_eq!(
        env("COTURN_CONFORMANCE"),
        "1",
        "coturn conformance must be explicitly enabled"
    );
    let host = env("TURN_HOST");
    let user = env("TURN_USER");
    let pass = env("TURN_PASS");
    let deadline = Duration::from_secs(10);

    // UDP allocate must succeed against real coturn with good credentials.
    let udp = ConnectionPlan {
        transport: TurnTransport::Udp,
        server_name: None,
        addresses: vec![addr(&host, "TURN_UDP_PORT")],
        is_ip_literal: true,
        require_ip_san_for_literals: false,
        allow_enterprise_roots: false,
        enterprise_root_ders: Vec::new(),
    };
    drive_allocation(&udp, &user, &pass, deadline)
        .await
        .expect("UDP allocate against coturn");

    // TCP allocate must succeed.
    let tcp = ConnectionPlan {
        transport: TurnTransport::Tcp,
        server_name: None,
        addresses: vec![addr(&host, "TURN_TCP_PORT")],
        is_ip_literal: true,
        require_ip_san_for_literals: false,
        allow_enterprise_roots: false,
        enterprise_root_ders: Vec::new(),
    };
    drive_allocation(&tcp, &user, &pass, deadline)
        .await
        .expect("TCP allocate against coturn");

    // TLS allocate must succeed with the fixture SNI + trusted root.
    let tls = ConnectionPlan {
        transport: TurnTransport::Tls,
        server_name: Some(env("TURN_TLS_SNI")),
        addresses: vec![addr(&host, "TURN_TLS_PORT")],
        is_ip_literal: false,
        require_ip_san_for_literals: true,
        allow_enterprise_roots: false,
        enterprise_root_ders: Vec::new(),
    };
    drive_allocation(&tls, &user, &pass, deadline)
        .await
        .expect("TLS allocate against coturn");

    // A bad credential must fail closed (never a fabricated success).
    let err = drive_allocation(&udp, "nobody", "wrong-password", deadline)
        .await
        .expect_err("bad credential must be rejected");
    assert!(matches!(
        err,
        ConnectError::Unauthorized | ConnectError::AllocationFailed | ConnectError::ConnectTimeout
    ));

    // Cancellation bound: a sub-round-trip deadline yields a timeout, not a hang.
    let err = drive_allocation(&udp, &user, &pass, Duration::from_millis(1))
        .await
        .expect_err("tiny deadline must time out");
    assert_eq!(err, ConnectError::ConnectTimeout);
}
