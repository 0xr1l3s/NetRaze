//! Phase B.2 — Live integration test for [`shares::enum_shares`] +
//! [`shares::enum_shares_with_access`] against the Samba container in
//! `tests/samba/`.
//!
//! Validates the full pipeline:
//!
//! ```text
//! Smb2Session::connect_with_password
//!   → tree_connect IPC$
//!   → SmbPipeTransport::open(srvsvc)
//!   → RpcChannel::bind_authenticated (NTLMSSP PKT_PRIVACY)
//!   → call(opnum=15, NetrShareEnum level=1)
//!   → decode_netr_share_enum_response
//!   → per-share: tree_connect + probe_write
//! ```
//!
//! Pinned shares come from `tests/samba/smb.conf`:
//! - `IPC$` (auto-emitted by Samba — STYPE_IPC)
//! - `private` (alice-only, STYPE_DISKTREE, comment "Alice's private share")
//! - `public` (guest-readable, STYPE_DISKTREE, comment "Public read-only")
//! - `ADMIN$` (alice + admin, STYPE_DISKTREE)
//!
//! Marked `#[ignore]` because it needs the containerised Samba on
//! `127.0.0.1:1445` (override with `NETRAZE_SAMBA_ADDR`):
//!
//! ```shell
//! docker compose -f tests/samba/docker-compose.yml up -d --wait
//! cargo test -p netraze-protocols --test shares_rpc_samba -- \
//!     --ignored --test-threads=1
//! ```

use std::net::TcpStream;
use std::time::Duration;

use netraze_protocols::smb::connection::SmbCredential;
use netraze_protocols::smb::shares::{ShareAccess, ShareInfo, ShareType};

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

fn find<'a>(shares: &'a [ShareInfo], name: &str) -> Option<&'a ShareInfo> {
    shares.iter().find(|s| s.name.eq_ignore_ascii_case(name))
}

#[tokio::test]
#[ignore = "requires Samba container on NETRAZE_SAMBA_ADDR (default 127.0.0.1:1445)"]
async fn shares_rpc_lists_pinned_samba_shares() {
    if !samba_reachable() {
        panic!(
            "Samba container not running at {}. Start it with:\n  \
             docker compose -f tests/samba/docker-compose.yml up -d --wait\n\
             See tests/samba/README.md.",
            samba_addr()
        );
    }

    let cred = SmbCredential::new(TEST_USER, TEST_DOMAIN, TEST_PASSWORD);
    let shares = netraze_protocols::smb::shares::enum_shares(&samba_addr(), &cred)
        .await
        .expect("enum_shares against live Samba");

    // Pinned inventory from tests/samba/smb.conf — every name MUST appear.
    // We tolerate extra entries (Samba auto-injects `IPC$`, future shares
    // could be added by infra without breaking this test).
    for must_have in &["IPC$", "private", "public"] {
        assert!(
            find(&shares, must_have).is_some(),
            "expected share {must_have:?} in Samba enumeration, got {:?}",
            shares.iter().map(|s| &s.name).collect::<Vec<_>>()
        );
    }

    // Type classification — `private` and `public` are disk shares,
    // `IPC$` is the IPC pipe carrier.
    let ipc = find(&shares, "IPC$").unwrap();
    assert_eq!(
        ipc.share_type,
        ShareType::Ipc,
        "IPC$ must classify as Ipc, got {:?}",
        ipc.share_type
    );
    let private = find(&shares, "private").unwrap();
    assert_eq!(
        private.share_type,
        ShareType::Disk,
        "private must classify as Disk, got {:?}",
        private.share_type
    );
    assert_eq!(
        private.remark, "Alice's private share",
        "private comment drift from smb.conf"
    );
    let public = find(&shares, "public").unwrap();
    assert_eq!(
        public.share_type,
        ShareType::Disk,
        "public must classify as Disk, got {:?}",
        public.share_type
    );
    assert_eq!(
        public.remark, "Public read-only",
        "public comment drift from smb.conf"
    );

    // Bare enum_shares leaves `access` at NoAccess for everyone — the
    // probing step is opt-in via `enum_shares_with_access`.
    for s in &shares {
        assert_eq!(
            s.access,
            ShareAccess::NoAccess,
            "enum_shares must NOT probe access; {} reported {:?}",
            s.name,
            s.access
        );
    }
}

#[tokio::test]
#[ignore = "requires Samba container on NETRAZE_SAMBA_ADDR (default 127.0.0.1:1445)"]
async fn shares_rpc_classifies_per_share_access() {
    if !samba_reachable() {
        panic!(
            "Samba container not running at {}. See tests/samba/README.md",
            samba_addr()
        );
    }

    let cred = SmbCredential::new(TEST_USER, TEST_DOMAIN, TEST_PASSWORD);
    let shares = netraze_protocols::smb::shares::enum_shares_with_access(&samba_addr(), &cred)
        .await
        .expect("enum_shares_with_access against live Samba");

    // alice owns `private` with `read only = no` → must be ReadWrite.
    let private = find(&shares, "private").expect("private share missing");
    assert_eq!(
        private.access,
        ShareAccess::ReadWrite,
        "alice should have RW on `private`, got {:?}",
        private.access
    );

    // `public` is `read only = yes` for everyone (including alice) → Read.
    let public = find(&shares, "public").expect("public share missing");
    assert_eq!(
        public.access,
        ShareAccess::Read,
        "`public` is read-only per smb.conf, got {:?}",
        public.access
    );

    // IPC$ is left at NoAccess — we deliberately skip probing pipe/print
    // shares because writing to them isn't a meaningful operation and
    // would just confuse the access classification.
    let ipc = find(&shares, "IPC$").expect("IPC$ missing");
    assert_eq!(
        ipc.access,
        ShareAccess::NoAccess,
        "IPC$ must be skipped from probing, got {:?}",
        ipc.access
    );
}

#[tokio::test]
#[ignore = "requires Samba container on NETRAZE_SAMBA_ADDR (default 127.0.0.1:1445)"]
async fn shares_rpc_admin_share_check() {
    if !samba_reachable() {
        panic!(
            "Samba container not running at {}. See tests/samba/README.md",
            samba_addr()
        );
    }

    // alice is in `admin users` for ADMIN$ in smb.conf — must succeed.
    let cred = SmbCredential::new(TEST_USER, TEST_DOMAIN, TEST_PASSWORD);
    let granted =
        netraze_protocols::smb::shares::can_access_admin_share(&samba_addr(), &cred).await;
    assert!(
        granted,
        "alice should have ADMIN$ access per smb.conf `admin users = alice`"
    );

    // A bogus password path must NOT grant admin — gates a regression where
    // we'd silently treat any session-setup failure as `false`.
    let bad = SmbCredential::new(TEST_USER, TEST_DOMAIN, "definitely-not-the-password");
    let denied = netraze_protocols::smb::shares::can_access_admin_share(&samba_addr(), &bad).await;
    assert!(
        !denied,
        "bogus password must not yield ADMIN$ access — auth path is broken"
    );
}
