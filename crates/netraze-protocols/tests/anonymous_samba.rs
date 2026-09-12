//! Anonymous (null session) and guest access against the Samba container
//! in `tests/samba/`.
//!
//! The harness maps bad passwords to guest (`map to guest = Bad Password`)
//! and the `public` share is `guest ok` — together these exercise the two
//! downgrade-accepting auth paths in `smb2`:
//!
//! ```text
//! Smb2Session::connect_anonymous  → IS_NULL-flagged session → public
//! Smb2Session::connect_guest      → IS_GUEST-flagged session → public
//! ```
//!
//! while `private` / `ADMIN$` (alice-only) must stay refused — guest-grade
//! access is browse-only, never a real login.
//!
//! Marked `#[ignore]` because it needs the containerised Samba on
//! `127.0.0.1:1445` (override with `NETRAZE_SAMBA_ADDR`):
//!
//! ```shell
//! docker compose -f tests/samba/docker-compose.yml up -d --wait
//! cargo test -p netraze-protocols --test anonymous_samba -- \
//!     --ignored --test-threads=1
//! ```

use std::net::TcpStream;
use std::time::Duration;

use netraze_protocols::smb::browser;
use netraze_protocols::smb::connection::SmbCredential;
use netraze_protocols::smb::shares;
use netraze_protocols::smb::smb2::Smb2Session;
use netraze_protocols::smb::users;

const DEFAULT_SAMBA_ADDR: &str = "127.0.0.1:1445";
const TEST_USER: &str = "alice";
/// Alice-only share pinned in the harness user database.
const TEST_DOMAIN: &str = "NETRAZE";
/// Guest-ok share pinned in `tests/samba/smb.conf` (`guest ok = yes`).
const GUEST_SHARE: &str = "public";
/// Alice-only share — must refuse every guest-grade session.
const PRIVATE_SHARE: &str = "private";

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

fn require_samba() {
    if !samba_reachable() {
        panic!(
            "Samba container not running at {}. Start it with:\n  \
             docker compose -f tests/samba/docker-compose.yml up -d --wait\n\
             See tests/samba/README.md.",
            samba_addr()
        );
    }
}

fn host_only() -> String {
    samba_addr()
        .split(':')
        .next()
        .unwrap_or_default()
        .to_owned()
}

fn anon_cred() -> SmbCredential {
    SmbCredential::new("", "", "")
}

fn guest_cred() -> SmbCredential {
    SmbCredential::new("someguest", TEST_DOMAIN, "")
}

/// Null session completes against Samba and reaches the guest-ok share —
/// but not the alice-only one.
#[test]
#[ignore = "requires Samba container on NETRAZE_SAMBA_ADDR (default 127.0.0.1:1445)"]
fn anonymous_session_browses_guest_share_only() {
    require_samba();
    let addr = samba_addr();
    let host = host_only();

    let mut session = Smb2Session::connect_anonymous(&addr)
        .expect("null session setup must complete against Samba");

    let tid = session
        .tree_connect(&host, GUEST_SHARE)
        .expect("null session must tree_connect the guest-ok share");
    assert_ne!(tid, 0);
    let _ = session.tree_disconnect(tid);

    let denied = session
        .tree_connect(&host, PRIVATE_SHARE)
        .expect_err("null session must NOT reach the alice-only share");
    assert!(
        denied.contains("ACCESS_DENIED") || denied.contains("0x{"),
        "expected an access-denied style error, got: {denied}"
    );
    session.logoff();
}

/// The full desktop flow for "no user provided": anonymous credential →
/// `connect_session` dispatch → share browse via `browser`.
#[tokio::test]
#[ignore = "requires Samba container on NETRAZE_SAMBA_ADDR (default 127.0.0.1:1445)"]
async fn anonymous_browse_via_browser_rpc() {
    require_samba();
    let listing = browser::list_directory(&samba_addr(), &anon_cred(), GUEST_SHARE, "")
        .await
        .expect("anonymous list_directory on the guest-ok share");
    // The tmpfs share starts empty — a successful (possibly empty) listing
    // is the contract; ordering/contents are covered by browser_ops_samba.
    let _ = listing;
}

/// Username without a secret: the harness maps the (blank) password to
/// guest, `connect_guest` accepts the IS_GUEST downgrade, and the
/// guest-ok share is reachable while the alice-only one is not.
#[test]
#[ignore = "requires Samba container on NETRAZE_SAMBA_ADDR (default 127.0.0.1:1445)"]
fn guest_session_browses_guest_share_only() {
    require_samba();
    let addr = samba_addr();
    let host = host_only();

    let mut session = Smb2Session::connect_guest(&addr, "someguest", TEST_DOMAIN)
        .expect("guest session setup must complete (map to guest = Bad Password)");

    let tid = session
        .tree_connect(&host, GUEST_SHARE)
        .expect("guest session must tree_connect the guest-ok share");
    assert_ne!(tid, 0);
    let _ = session.tree_disconnect(tid);

    let denied = session
        .tree_connect(&host, PRIVATE_SHARE)
        .expect_err("guest session must NOT reach the alice-only share");
    assert!(
        denied.contains("ACCESS_DENIED") || denied.contains("0x{"),
        "expected an access-denied style error, got: {denied}"
    );
    session.logoff();
}

/// The desktop "user without secret" flow end-to-end: `connect_session`
/// dispatches a secret-less credential onto the guest path.
#[tokio::test]
#[ignore = "requires Samba container on NETRAZE_SAMBA_ADDR (default 127.0.0.1:1445)"]
async fn guest_browse_via_browser_rpc() {
    require_samba();
    let listing = browser::list_directory(&samba_addr(), &guest_cred(), GUEST_SHARE, "")
        .await
        .expect("guest list_directory on the guest-ok share");
    let _ = listing;
}

/// Anonymous share enumeration. Samba (like Windows with
/// `RestrictAnonymous = 0`) serves the share-*name* list to null
/// sessions — including alice-only names — because access is enforced at
/// tree_connect, not at listing. That's exactly the pen-test value of a
/// null session: it leaks the inventory. Parity with Impacket's
/// null-session `listShares` is verified in the Impacket cross-check.
#[tokio::test]
#[ignore = "requires Samba container on NETRAZE_SAMBA_ADDR (default 127.0.0.1:1445)"]
async fn anonymous_share_enumeration_lists_names() {
    require_samba();
    let list = shares::enum_shares(&samba_addr(), &anon_cred())
        .await
        .expect("Samba serves the share-name list to null sessions");
    let names: Vec<&str> = list.iter().map(|s| s.name.as_str()).collect();
    // Impacket-verified parity: a null session sees every share *name*
    // (ADMIN$, public, private, IPC$) — identical to Impacket's
    // `listShares` after `login('', '')`.
    println!("anonymous enum_shares: {names:?}");
    assert!(
        names.contains(&GUEST_SHARE),
        "guest-ok share must be listed, got: {names:?}"
    );
    // Name visibility only — `anonymous_session_browses_guest_share_only`
    // pins that the alice-only share stays unreachable at tree_connect.
}

/// Guest share enumeration — the regression for the RPC fault 0x5 bug:
/// a guest credential used to take the authenticated NTLMSSP bind, whose
/// pipe-level AUTH3 (non-existent user, blank hash) Samba faults with
/// `status=0x00000005` on `NetrShareEnum`. Guest sessions now ride the
/// unauthenticated bind like Impacket's `listShares` does, and enumerate
/// the same share names a null session sees.
#[tokio::test]
#[ignore = "requires Samba container on NETRAZE_SAMBA_ADDR (default 127.0.0.1:1445)"]
async fn guest_share_enumeration_lists_names() {
    require_samba();
    let list = shares::enum_shares(&samba_addr(), &guest_cred())
        .await
        .expect("guest session must enumerate share names (unauthenticated bind)");
    let names: Vec<&str> = list.iter().map(|s| s.name.as_str()).collect();
    println!("guest enum_shares: {names:?}");
    assert!(
        names.contains(&GUEST_SHARE),
        "guest-ok share must be listed, got: {names:?}"
    );
}

/// Guest user enumeration — same unauthenticated-bind fix for SAMR
/// (`SamrConnect2` → domain enum → `SamrOpenDomain` → user enum). The
/// harness answers a guest session with the same account list an
/// authenticated session gets (Impacket parity verified: its guest
/// `hSamrEnumerateUsersInDomain` returns the same single account).
#[tokio::test]
#[ignore = "requires Samba container on NETRAZE_SAMBA_ADDR (default 127.0.0.1:1445)"]
async fn guest_user_enumeration_lists_accounts() {
    require_samba();
    let users = users::enum_users(&samba_addr(), &guest_cred())
        .await
        .expect("guest session must enumerate SAMR accounts (unauthenticated bind)");
    let names: Vec<&str> = users.iter().map(|u| u.name.as_str()).collect();
    println!("guest enum_users: {names:?}");
    assert!(
        names.contains(&TEST_USER),
        "guest enum must list {TEST_USER}, got: {names:?}"
    );
}

/// Strictness regression: a real credential with a wrong password is
/// mapped to guest by the harness — the strict path must reject the
/// downgrade rather than hand back a guest session (that's
/// `bad_password_is_rejected` in samba_integration, restated here from
/// the credential-dispatch angle: the shape still carries a secret, so
/// guest must NOT be assumed).
#[tokio::test]
#[ignore = "requires Samba container on NETRAZE_SAMBA_ADDR (default 127.0.0.1:1445)"]
async fn secret_carrying_wrong_password_still_rejected() {
    require_samba();
    let bad_cred = SmbCredential::new(TEST_USER, TEST_DOMAIN, "definitely-not-the-password");
    let res = browser::list_directory(&samba_addr(), &bad_cred, GUEST_SHARE, "").await;
    match res {
        Err(e) => assert!(
            e.contains("downgraded to GUEST"),
            "expected the GUEST-downgrade rejection, got: {e}"
        ),
        Ok(_) => panic!("wrong password must not yield a session (guest or otherwise)"),
    }
}
