//! Phase B.1 — Live integration test for [`info::get_server_info`] against
//! the Samba container in `tests/samba/`.
//!
//! Validates the full pipeline introduced by Phase B.1:
//!
//! ```text
//! Smb2Session::connect_with_password
//!   → tree_connect IPC$
//!   → SmbPipeTransport::open(srvsvc)
//!   → RpcChannel::bind_authenticated (NTLMSSP PKT_PRIVACY)
//!   → call(opnum=21, NetrServerGetInfo level=101)
//!   → decode_netr_server_get_info_response
//! ```
//!
//! Marked `#[ignore]` because it needs the containerised Samba on
//! `127.0.0.1:1445` (override with `NETRAZE_SAMBA_ADDR`):
//!
//! ```shell
//! docker compose -f tests/samba/docker-compose.yml up -d --wait
//! cargo test -p netraze-protocols --test info_rpc_samba -- \
//!     --ignored --test-threads=1
//! ```

use std::net::TcpStream;
use std::time::Duration;

use netraze_protocols::smb::ServerInfo;
use netraze_protocols::smb::connection::SmbCredential;

const DEFAULT_SAMBA_ADDR: &str = "127.0.0.1:1445";
const TEST_USER: &str = "alice";
const TEST_PASSWORD: &str = "wonderland";
const TEST_DOMAIN: &str = "NETRAZE";

fn samba_addr() -> String {
    std::env::var("NETRAZE_SAMBA_ADDR").unwrap_or_else(|_| DEFAULT_SAMBA_ADDR.to_owned())
}

fn samba_reachable() -> bool {
    let addr = samba_addr();
    let sock = addr.parse::<std::net::SocketAddr>().ok().or_else(|| {
        use std::net::ToSocketAddrs;
        addr.to_socket_addrs().ok().and_then(|mut i| i.next())
    });
    match sock {
        Some(sa) => TcpStream::connect_timeout(&sa, Duration::from_millis(500)).is_ok(),
        None => false,
    }
}

/// Re-export of the public path so the test reads naturally.
async fn fetch_info(target: &str, cred: &SmbCredential) -> Result<ServerInfo, String> {
    // We deliberately go through the public `smb::info` path — same
    // entry point `SmbClient::server_info` uses — so any regression in
    // the wiring (mod.rs, info_rpc.rs, rpc.rs helpers) fails here too.
    netraze_protocols::smb::info::get_server_info(target, cred).await
}

#[tokio::test]
#[ignore = "requires Samba container on NETRAZE_SAMBA_ADDR (default 127.0.0.1:1445)"]
async fn info_rpc_returns_samba_server_info() {
    if !samba_reachable() {
        panic!(
            "Samba container not running at {}. Start it with:\n  \
             docker compose -f tests/samba/docker-compose.yml up -d --wait\n\
             See tests/samba/README.md.",
            samba_addr()
        );
    }

    let cred = SmbCredential::new(TEST_USER, TEST_DOMAIN, TEST_PASSWORD);
    let info = fetch_info(&samba_addr(), &cred)
        .await
        .expect("get_server_info against live Samba");

    // Samba sets `name` to the server's NetBIOS name (uppercase). The
    // smb.conf in tests/samba pins `netbios name = NETRAZE-SAMBA` (image
    // default if not overridden — accept any non-empty NetBIOS name to
    // avoid coupling this test to that exact string).
    assert!(
        !info.name.is_empty(),
        "server name must be non-empty, got {:?}",
        info.name
    );

    // Samba 4.x advertises platform_id = 500 (PLATFORM_ID_NT) — matches
    // every Windows host we'd target, so this is a useful invariant.
    assert_eq!(
        info.platform_id, 500,
        "Samba advertises PLATFORM_ID_NT (500), got {}",
        info.platform_id
    );

    // Version string is built as "Windows {major & 0x0F}.{minor}". Samba
    // reports its emulated NT version (typically 6.1 or 10.0 depending on
    // build); we just assert the string follows that shape.
    assert!(
        info.os_version.starts_with("Windows "),
        "os_version must start with 'Windows ', got {:?}",
        info.os_version
    );
    let after = &info.os_version["Windows ".len()..];
    let parts: Vec<&str> = after.split('.').collect();
    assert_eq!(
        parts.len(),
        2,
        "os_version must be 'Windows MAJOR.MINOR', got {:?}",
        info.os_version
    );
    assert!(
        parts[0].chars().all(|c| c.is_ascii_digit()),
        "version major must be numeric in {:?}",
        info.os_version
    );
    assert!(
        parts[1].chars().all(|c| c.is_ascii_digit()),
        "version minor must be numeric in {:?}",
        info.os_version
    );

    // server_type bitfield: SV_TYPE_SERVER (0x2) is always set by anyone
    // running an SMB server. Use that as a low-risk presence check.
    assert!(
        info.server_type & 0x0000_0002 != 0,
        "server_type must include SV_TYPE_SERVER (0x2), got 0x{:08x}",
        info.server_type
    );
}

#[tokio::test]
#[ignore = "requires Samba container on NETRAZE_SAMBA_ADDR (default 127.0.0.1:1445)"]
async fn info_rpc_rejects_bad_password() {
    if !samba_reachable() {
        panic!(
            "Samba container not running at {}. See tests/samba/README.md",
            samba_addr()
        );
    }

    let bad_cred = SmbCredential::new(TEST_USER, TEST_DOMAIN, "definitely-not-the-password");
    let res = fetch_info(&samba_addr(), &bad_cred).await;
    assert!(
        res.is_err(),
        "Samba accepted a bogus password — auth path is broken: {:?}",
        res
    );
}
