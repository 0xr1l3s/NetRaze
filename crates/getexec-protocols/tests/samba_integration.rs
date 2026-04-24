//! Integration test against the Samba container in `tests/samba/`.
//!
//! These tests are `#[ignore]` by default because they need a running Samba
//! server — spin one up before running them:
//!
//! ```shell
//! docker compose -f tests/samba/docker-compose.yml up -d
//! cargo test -p getexec-protocols --test samba_integration -- --ignored --test-threads=1
//! docker compose -f tests/samba/docker-compose.yml down
//! ```
//!
//! The server pins a known inventory (see `tests/samba/smb.conf`):
//! - user `alice` / password `wonderland` — the only authenticated account
//! - share `private` — STYPE_DISKTREE, authenticated-only, comment
//!   "Alice's private share"
//! - share `public` — STYPE_DISKTREE, guest-readable, comment
//!   "Public read-only"
//! - share `ADMIN$` — STYPE_DISKTREE, not browseable, alice admin
//!
//! The test binds port 1445 (not 445) to avoid colliding with the OS SMB
//! client on Windows/macOS dev boxes. Override with `NETRAZE_SAMBA_ADDR` if
//! you need to point at a different endpoint.
//!
//! # What the smoke test covers vs. what it doesn't
//!
//! Covers:
//! - SMB2 Negotiate (dialect, caps, security mode echoed back)
//! - NTLMSSP Negotiate → Challenge → Authenticate dance against real Samba
//! - NTLMv2 response computed from the NT-hash of `"wonderland"` is accepted
//! - Tree Connect to `\\server\IPC$` (the RPC-named-pipe entrypoint)
//!
//! Does NOT cover (yet):
//! - FSCTL_PIPE_TRANSCEIVE / DCE-RPC over named pipe — blocked on SMB2 IOCTL
//!   support in `smb2.rs`. Once that lands, a follow-up integration test in
//!   `getexec-dcerpc/tests/` will drive the full SRVSVC stack end-to-end.
//! - SMB signing / encryption — our session-setup path does the NTLM dance
//!   but does not yet negotiate/enforce SMB signing against Samba.

use std::net::TcpStream;
use std::time::Duration;

use getexec_protocols::smb::ntlm;
use getexec_protocols::smb::smb2::Smb2Session;

/// Default test endpoint — the `docker-compose.yml` binds the Samba
/// container to 127.0.0.1:1445 on the host. Override with
/// `NETRAZE_SAMBA_ADDR=<host:port>` for non-default setups (e.g. CI
/// running Samba as a service container).
const DEFAULT_SAMBA_ADDR: &str = "127.0.0.1:1445";

fn samba_addr() -> String {
    std::env::var("NETRAZE_SAMBA_ADDR").unwrap_or_else(|_| DEFAULT_SAMBA_ADDR.to_owned())
}

/// Skip-if-unreachable guard. Returns `true` if the Samba endpoint is
/// accepting TCP connections; used so that `--ignored` runs in an
/// environment without a live container don't hang on long TCP timeouts.
fn samba_reachable() -> bool {
    let addr = samba_addr();
    // Parse as a socket addr and try a short-timeout connect — if the
    // container isn't up we'll get `ECONNREFUSED` in ~1 ms, not a 10-second
    // SYN timeout.
    let sock = addr.parse::<std::net::SocketAddr>().ok().or_else(|| {
        use std::net::ToSocketAddrs;
        addr.to_socket_addrs().ok().and_then(|mut i| i.next())
    });
    match sock {
        Some(sa) => TcpStream::connect_timeout(&sa, Duration::from_millis(500)).is_ok(),
        None => false,
    }
}

/// The `alice` / `wonderland` credentials baked into the Samba container.
/// Test-only — not a secret, published in `tests/samba/docker-compose.yml`.
const TEST_USER: &str = "alice";
const TEST_PASSWORD: &str = "wonderland";
const TEST_DOMAIN: &str = "NETRAZE"; // matches `workgroup =` in smb.conf

/// Sanity check that the NT-hash-from-password helper produces a
/// 16-byte MD4. Doesn't need Samba to run — it's a precondition for the
/// auth tests below, so having it here makes failures easier to localize.
#[test]
fn nt_hash_of_wonderland_is_md4_of_utf16le() {
    let hash = ntlm::nt_hash_from_password(TEST_PASSWORD).expect("hash");
    assert_eq!(hash.len(), 16);
    // NT-hash("wonderland") — precomputed reference via pycryptodome:
    //   from Crypto.Hash import MD4
    //   h = MD4.new(); h.update("wonderland".encode("utf-16le")); h.hexdigest()
    //   → 3e057cd123205aa168af5f121716b335
    // (Python 3.11's stdlib hashlib dropped MD4 because OpenSSL did — use
    // pycryptodome or `openssl dgst -md4` if you need to regenerate.)
    let expected = [
        0x3e, 0x05, 0x7c, 0xd1, 0x23, 0x20, 0x5a, 0xa1, 0x68, 0xaf, 0x5f, 0x12, 0x17, 0x16, 0xb3,
        0x35,
    ];
    assert_eq!(hash, expected, "NT-hash(wonderland) drifted");
}

/// Plain TCP reachability — preflight for the auth tests. Surfaces
/// "container isn't up" as a clearer failure than "session setup timed
/// out" does.
#[test]
#[ignore = "requires Samba container on NETRAZE_SAMBA_ADDR (default 127.0.0.1:1445)"]
fn samba_port_is_reachable() {
    assert!(
        samba_reachable(),
        "Samba test container not reachable at {}. Start it with:\n  \
         docker compose -f tests/samba/docker-compose.yml up -d",
        samba_addr()
    );
}

/// End-to-end: Negotiate → NTLMv2 Session Setup → Tree Connect to IPC$.
///
/// This is the load-bearing smoke test for the SMB2 client. If any of the
/// three stages regresses (wrong struct packing, off-by-one in NTLMSSP
/// field layout, mis-aligned SMB2 header), this test fails against real
/// Samba — the most important signal we can get that the wire-level code
/// is actually correct.
#[test]
#[ignore = "requires Samba container on NETRAZE_SAMBA_ADDR (default 127.0.0.1:1445)"]
fn negotiate_sessionsetup_treeconnect_to_ipc() {
    if !samba_reachable() {
        panic!(
            "Samba container not running at {}. See tests/samba/README.md",
            samba_addr()
        );
    }

    let addr = samba_addr();
    let mut session =
        Smb2Session::connect_with_password(&addr, TEST_USER, TEST_DOMAIN, TEST_PASSWORD)
            .expect("connect + negotiate + session_setup must succeed against live Samba");

    // IPC$ is always present on Samba (it's the RPC named-pipe entrypoint).
    // We strip the `:port` suffix because Tree Connect builds a UNC path
    // and UNC doesn't accept ports — Samba wouldn't crash on `\\host:1445\…`
    // but it's the wrong shape to put on the wire.
    let host_only = addr.split(':').next().unwrap_or(&addr);
    let tid = session
        .tree_connect(host_only, "IPC$")
        .expect("tree connect to IPC$ must succeed");
    assert_ne!(tid, 0, "tree ID must be non-zero on success");
}

/// Wrong password must be rejected by Samba — verifies our negative-path
/// error handling doesn't silently accept garbage credentials.
#[test]
#[ignore = "requires Samba container on NETRAZE_SAMBA_ADDR (default 127.0.0.1:1445)"]
fn bad_password_is_rejected() {
    if !samba_reachable() {
        panic!(
            "Samba container not running at {}. See tests/samba/README.md",
            samba_addr()
        );
    }
    let res = Smb2Session::connect_with_password(
        &samba_addr(),
        TEST_USER,
        TEST_DOMAIN,
        "definitely-not-the-password",
    );
    assert!(
        res.is_err(),
        "Samba accepted a bogus password — NTLMv2 path is broken"
    );
}
