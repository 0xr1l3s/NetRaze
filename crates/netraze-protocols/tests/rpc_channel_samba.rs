//! Phase A.7 — End-to-end smoke test for [`RpcChannel`] against the
//! containerised Samba server in `tests/samba/`.
//!
//! This is the load-bearing validation gate for the entire Phase A stack:
//! if [`RpcChannel::bind_authenticated`] + [`RpcChannel::call`] can drive a
//! `NetrShareEnum` round-trip against real Samba and produce the four
//! pinned shares (`IPC$`, `print$`, `private`, `public`), then every
//! Phase B/C/D interface module can ride on top with confidence.
//!
//! What this test exercises end-to-end on the wire:
//!
//! 1. SMB2 Negotiate + NTLMv2 Session Setup (NT-hash of `wonderland`)
//! 2. Tree Connect to `\\server\IPC$`
//! 3. SMB2 CREATE on `\PIPE\srvsvc`
//! 4. DCE/RPC v5 Bind PDU with NTLMSSP NEGOTIATE in the auth_verifier
//! 5. BindAck parsing → strip 8-byte sec_trailer → CHALLENGE consumption
//! 6. AUTH3 PDU pushed via `transport.send_oneway` → SMB2 WRITE (not
//!    TRANSCEIVE — that would deadlock on the read half)
//! 7. PKT_PRIVACY-sealed Request for opnum 15 (`NetrShareEnum`)
//! 8. FSCTL_PIPE_TRANSCEIVE driving the IOCTL round-trip
//! 9. Multi-fragment response reassembly walked by `frag_length`
//! 10. NTLMSSP unseal of each Response stub, NDR pad trimming
//! 11. Concatenated stub fed to `decode_netr_share_enum_response`
//!
//! Any wire-level regression in *any* of those stages — NDR alignment
//! drift, off-by-one in NTLMSSP key schedule, mis-sized SMB2 header field,
//! sec_trailer prefix forgotten, FSCTL deadlock on AUTH3 — fails this
//! test against the real container.
//!
//! Marked `#[ignore]` because it needs the Samba container running:
//!
//! ```shell
//! docker compose -f tests/samba/docker-compose.yml up -d --wait
//! cargo test -p netraze-protocols --test rpc_channel_samba -- \
//!     --ignored --test-threads=1
//! ```

use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use netraze_dcerpc::RpcChannel;
use netraze_dcerpc::interfaces::srvsvc;
use netraze_protocols::smb::connection::SmbCredential;
use netraze_protocols::smb::rpc::{SmbPipeTransport, build_binder};
use netraze_protocols::smb::smb2::Smb2Session;

/// Default test endpoint — same harness as `samba_integration.rs`. The
/// `docker-compose.yml` binds the Samba container to `127.0.0.1:1445` on
/// the host. Override with `NETRAZE_SAMBA_ADDR=<host:port>` for non-default
/// setups (CI service container, dev box's native Samba, …).
const DEFAULT_SAMBA_ADDR: &str = "127.0.0.1:1445";

/// Credentials baked into the Samba container — published in
/// `tests/samba/docker-compose.yml`. Test-only; do not reuse anywhere real.
const TEST_USER: &str = "alice";
const TEST_PASSWORD: &str = "wonderland";
const TEST_DOMAIN: &str = "NETRAZE";

fn samba_addr() -> String {
    std::env::var("NETRAZE_SAMBA_ADDR").unwrap_or_else(|_| DEFAULT_SAMBA_ADDR.to_owned())
}

/// Skip-if-unreachable guard. Returns `true` if the Samba endpoint is
/// accepting TCP connections; used so that `--ignored` runs in an
/// environment without a live container fail with a clear message rather
/// than a 10-second SYN timeout from the SMB stack.
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

/// Build the test credential with the password path — `build_binder` will
/// derive the NT-hash internally via MD4(UTF-16LE("wonderland")).
fn test_credential() -> SmbCredential {
    SmbCredential::new(TEST_USER, TEST_DOMAIN, TEST_PASSWORD)
}

/// End-to-end: bind SRVSVC over a sealed NTLMSSP channel and enumerate
/// shares via opnum 15. Asserts the canonical four-share inventory pinned
/// in `tests/samba/smb.conf` (allowing for hidden / driver shares Samba
/// may add server-side).
///
/// The `Mutex<Option<…>>` dance around `session` is so we can move the
/// `Arc` into both the transport and a builder closure without clobbering
/// the session ownership. `SmbPipeTransport` keeps the Arc alive across
/// the bind handshake; the helper closure runs first, drops its borrow,
/// then the transport takes over.
#[tokio::test]
#[ignore = "requires Samba container on NETRAZE_SAMBA_ADDR (default 127.0.0.1:1445)"]
async fn rpc_channel_drives_netr_share_enum_against_samba() {
    if !samba_reachable() {
        panic!(
            "Samba container not running at {}. Start it with:\n  \
             docker compose -f tests/samba/docker-compose.yml up -d --wait\n\
             See tests/samba/README.md for details.",
            samba_addr()
        );
    }

    let addr = samba_addr();
    let cred = test_credential();

    // Stage 1 — SMB2 Negotiate + NTLMv2 Session Setup. We need the session
    // back as `Arc<Mutex<…>>` so SmbPipeTransport can serialise IOCTLs on
    // it; cloning the Arc lets the test still tree_connect afterwards.
    let session =
        Smb2Session::connect_with_password(&addr, &cred.username, &cred.domain, &cred.password)
            .expect("Smb2Session::connect_with_password against live Samba");
    let session = Arc::new(Mutex::new(session));

    // Stage 2 — Tree Connect to IPC$ (the named-pipe entrypoint).
    let host_only = addr.split(':').next().unwrap_or(&addr);
    let ipc_tid = {
        let mut s = session.lock().expect("session mutex");
        s.tree_connect(host_only, "IPC$")
            .expect("tree_connect IPC$ must succeed")
    };
    assert_ne!(ipc_tid, 0, "tree_id must be non-zero");

    // Stage 3 — Open \PIPE\srvsvc. The handle is owned by the transport
    // for the rest of the test; pipe_close runs in Drop.
    let transport = Arc::new(
        SmbPipeTransport::open(Arc::clone(&session), ipc_tid, "srvsvc")
            .expect("SmbPipeTransport::open(srvsvc) must succeed"),
    );

    // Stage 4 — 3-leg NTLMSSP bind for SRVSVC v3.0. Microsoft DCE/RPC over
    // SMB pipes always runs its own NTLMSSP handshake inside Bind PDUs,
    // independent of the SMB session key — that's what `build_binder`
    // produces from the credential.
    let binder = build_binder(&cred, 0);
    let mut channel = RpcChannel::bind_authenticated(
        Arc::clone(&transport) as Arc<dyn netraze_dcerpc::RpcTransport>,
        srvsvc::uuid(),
        (srvsvc::VERSION_MAJOR, srvsvc::VERSION_MINOR),
        binder,
    )
    .await
    .expect("RpcChannel::bind_authenticated to SRVSVC against live Samba");

    assert!(
        channel.is_authenticated(),
        "channel must be authenticated after bind_authenticated"
    );
    // Samba's typical ack is 4280 / 4280; we don't pin exactly because a
    // future Samba upgrade could legitimately raise these. Anything <2000
    // would be a red flag (router-fragmenting middlebox or misconfigured
    // server).
    assert!(
        channel.max_xmit >= 2048,
        "max_xmit suspiciously small: {}",
        channel.max_xmit
    );
    assert!(
        channel.max_recv >= 2048,
        "max_recv suspiciously small: {}",
        channel.max_recv
    );

    // Stage 5 — opnum 15 round-trip: NetrShareEnum(level=1, max=0xFFFFFFFF).
    // ServerName "" is conventionally accepted by every implementation as
    // "the server you're talking to".
    let stub = srvsvc::encode_netr_share_enum_request("", 0xFFFF_FFFF, 0);
    let response_stub = channel
        .call(srvsvc::Opnum::NetrShareEnum as u16, &stub)
        .await
        .expect("RpcChannel::call(NetrShareEnum) against live Samba");

    let resp = srvsvc::decode_netr_share_enum_response(&response_stub)
        .expect("decode_netr_share_enum_response on live Samba reply");

    // Stage 6 — semantic assertions on the share inventory. `tests/samba/
    // smb.conf` pins the user-visible shares (`private`, `public`, `IPC$`,
    // `print$`); `print$` may be hidden depending on Samba's print
    // subsystem state in the smbd-only image, so we only assert on the
    // three we control directly.
    assert_eq!(
        resp.status, 0,
        "server status must be SUCCESS, got 0x{:08x}",
        resp.status
    );
    assert!(
        resp.shares.len() >= 3,
        "expected at least 3 shares (IPC$, private, public), got {}: {:?}",
        resp.shares.len(),
        resp.shares.iter().map(|s| &s.netname).collect::<Vec<_>>()
    );
    let names: Vec<&str> = resp.shares.iter().map(|s| s.netname.as_str()).collect();
    assert!(
        names.contains(&"IPC$"),
        "IPC$ must be enumerated (it's the named-pipe carrier we just used), got {names:?}"
    );
    assert!(
        names.contains(&"private"),
        "private (alice's share) must be enumerated, got {names:?}"
    );
    assert!(
        names.contains(&"public"),
        "public must be enumerated, got {names:?}"
    );

    // Spot-check: the IPC$ entry must be typed as STYPE_IPC (3). Bit 31 is
    // the STYPE_SPECIAL flag Windows sets on hidden shares (ADMIN$, C$,
    // IPC$). We mask it off before comparing because Samba may or may not
    // set it depending on the share's `browseable` setting.
    let ipc = resp
        .shares
        .iter()
        .find(|s| s.netname == "IPC$")
        .expect("IPC$ present");
    assert_eq!(
        ipc.shi1_type & 0x0000_000F,
        3,
        "IPC$ must be STYPE_IPC, got 0x{:08x}",
        ipc.shi1_type
    );

    // Spot-check: the comment Samba advertises for `private` is pinned in
    // smb.conf. If this string drifts, smb.conf and the test must move
    // together.
    let private = resp
        .shares
        .iter()
        .find(|s| s.netname == "private")
        .expect("private share present");
    assert!(
        private.remark.contains("private") || private.remark.contains("Alice"),
        "private share remark drifted from smb.conf: {:?}",
        private.remark
    );

    // Cleanup — Smb2Session::logoff drops the session key + tells the
    // server we're done. Best-effort; the transport's Drop closes the pipe.
    {
        let mut s = session.lock().expect("session mutex for logoff");
        let _ = s.tree_disconnect(ipc_tid);
        s.logoff();
    }
}
