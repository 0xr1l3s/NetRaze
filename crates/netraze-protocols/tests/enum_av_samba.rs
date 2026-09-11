//! Phase F — Live integration test for the portable AV/EDR enumeration
//! backend against the Samba container in `tests/samba/`.
//!
//! Samba has no Windows SCM and no AV products, so both detection phases
//! have nothing to find. What this test pins:
//!
//! 1. The whole `enum_av` run completes without panicking. With the minimal
//!    `SC_MANAGER_CONNECT` right (same mask as the Windows impl), Samba
//!    grants the manager open to any authenticated user, so the SCM phase
//!    runs clean and every probe answers 1060 (absent). A hardened server
//!    policy refusing the open must surface as a readable error — never a
//!    hang, never an empty-result-with-no-explanation.
//! 2. The D8 wire question: SMB2 `query_directory` on `\\host\IPC$` (what
//!    the Windows impl's `FindFirstFileW` did under the hood). Samba refuses
//!    directory enumeration on IPC$ at CREATE with `0xC0000236` (Impacket's
//!    listPath is refused equally), so the pipe phase must skip silently —
//!    documented here so the behaviour is pinned.
//!
//! Marked `#[ignore]` because it needs the containerised Samba on
//! `127.0.0.1:1445` (override with `NETRAZE_SAMBA_ADDR`):
//!
//! ```shell
//! docker compose -f tests/samba/docker-compose.yml up -d --wait
//! cargo test -p netraze-protocols --test enum_av_samba -- --ignored
//! ```

use std::net::TcpStream;
use std::time::Duration;

use netraze_protocols::smb::browser;
use netraze_protocols::smb::connection::SmbCredential;
use netraze_protocols::smb::enum_av;

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

fn cred() -> SmbCredential {
    SmbCredential::new(TEST_USER, TEST_DOMAIN, TEST_PASSWORD)
}

/// The full enum_av chain against Samba. With the minimal
/// SC_MANAGER_CONNECT mask (the same right the Windows impl used), Samba
/// grants the manager open to any authenticated user — the SCM phase runs
/// cleanly, every service probe answers 1060 (absent), and no products are
/// reported. If a hardened server policy refuses the open instead, that
/// must surface as a readable error. Either way: no panic, no hang.
#[tokio::test]
#[ignore = "requires Samba container on NETRAZE_SAMBA_ADDR (default 127.0.0.1:1445)"]
async fn enum_av_samba_scm_phase_is_graceful() {
    assert!(
        samba_reachable(),
        "Samba container not running — see tests/samba/README.md"
    );
    let addr = samba_addr();

    let result = tokio::time::timeout(
        Duration::from_secs(30),
        enum_av::enum_av(&addr, Some(&cred())),
    )
    .await
    .expect("enum_av must complete within 30s (no hangs)");

    // Two acceptable outcomes depending on server policy:
    // - the manager open succeeds and the phase runs clean (errors empty —
    //   the pinned Samba behaviour with SC_MANAGER_CONNECT), or
    // - the open is refused and the failure surfaces readably.
    for e in &result.errors {
        assert!(
            !e.is_empty(),
            "error entries must carry a message, got: {:?}",
            result.errors
        );
    }
    // No false positives — the harness runs no AV.
    assert!(
        result.products.is_empty(),
        "no products expected on Samba, got: {:?}",
        result
            .products
            .iter()
            .map(|p| p.to_line())
            .collect::<Vec<_>>()
    );
}

/// A missing credential is an error, not a silent empty result.
#[tokio::test]
#[ignore = "requires Samba container on NETRAZE_SAMBA_ADDR (default 127.0.0.1:1445)"]
async fn enum_av_requires_credential() {
    assert!(
        samba_reachable(),
        "Samba container not running — see tests/samba/README.md"
    );
    let addr = samba_addr();
    let result = enum_av::enum_av(&addr, None).await;
    assert!(
        result
            .errors
            .iter()
            .any(|e| e.contains("requires a credential")),
        "missing credential must surface as an error, got: {:?}",
        result.errors
    );
    assert!(result.products.is_empty());
}

/// D8: SMB2 query_directory on IPC$ against Samba. Samba refuses directory
/// enumeration on IPC$ (Impacket's listPath gets the same refusal), so the
/// expected outcome here is a readable error — which the enum_av pipe phase
/// must swallow silently. If Samba one day serves pipe listings, a
/// non-empty result is equally fine; what must never happen is a panic.
#[tokio::test]
#[ignore = "requires Samba container on NETRAZE_SAMBA_ADDR (default 127.0.0.1:1445)"]
async fn enum_av_ipc_pipe_listing_is_graceful() {
    assert!(
        samba_reachable(),
        "Samba container not running — see tests/samba/README.md"
    );
    let addr = samba_addr();

    match browser::list_directory(&addr, &cred(), "IPC$", "").await {
        Ok(entries) => {
            // Samba grew IPC$ enumeration support — fine, just assert the
            // entries look like pipe names.
            for e in &entries {
                assert!(!e.name.is_empty());
                assert_ne!(e.name, ".");
                assert_ne!(e.name, "..");
            }
        }
        Err(e) => {
            // The pinned Samba behaviour: refusal at CREATE with
            // 0xC0000236 (Impacket's listPath gets a refusal too), surfaced
            // readably.
            assert!(!e.is_empty(), "error must carry a message");
        }
    }
}
