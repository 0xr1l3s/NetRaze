//! Integration test against the Samba container in `tests/samba/`.
//!
//! These tests are `#[ignore]` by default because they need a running Samba
//! server — spin one up before running them:
//!
//! ```shell
//! docker compose -f tests/samba/docker-compose.yml up -d
//! cargo test -p netraze-protocols --test samba_integration -- --ignored --test-threads=1
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
//! - **Phase 3**: SMB2 CREATE / IOCTL (FSCTL_PIPE_TRANSCEIVE) / CLOSE on
//!   `\PIPE\srvsvc`, with a hand-rolled DCE/RPC Bind PDU pushed through the
//!   pipe and a Bind Ack expected back. End-to-end proof that the carrier
//!   that every Phase 4-6 RPC interface will ride on actually works.
//! - **Phase 4**: Authenticated DCE/RPC bind (NTLMSSP PKT_PRIVACY) followed by
//!   a sealed `NetrShareEnum` request/response over the same pipe.

use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use netraze_dcerpc::channel::RpcChannel;
use netraze_protocols::smb::connection::SmbCredential;
use netraze_protocols::smb::ntlm;
use netraze_protocols::smb::rpc::SmbPipeTransport;
use netraze_protocols::smb::smb2::Smb2Session;

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

// ─── Phase 1: basic SMB2 session setup against Samba ──────────────────────

/// Verify that the SMB2 NTLMv2 handshake completes successfully against
/// the live Samba container and that the session id is non-zero.
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
            .expect("session_setup must succeed against live Samba");
    let host_only = addr.split(':').next().unwrap_or(&addr);
    let ipc = session
        .tree_connect(host_only, "IPC$")
        .expect("tree_connect IPC$ must succeed");
    assert_ne!(ipc, 0, "tree_id for IPC$ must be non-zero");
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

// ─── Phase 3: FSCTL_PIPE_TRANSCEIVE end-to-end against Samba ────────────

/// Hand-roll a DCE/RPC v5 Bind PDU for SRVSVC v3.0 over NDR20.
///
/// We craft the bytes here rather than going through `netraze-dcerpc::pdu`
/// so this test stays a pure protocol-level smoke check — if the dcerpc
/// PDU encoder later regresses, this test still independently proves the
/// SMB pipe carrier is correct.
///
/// Wire layout (MS-RPCE §2.2.2.13):
///   header (16 B): rpc_vers=5, type=11 (BIND), pfc_flags=0x03,
///     drep=10000000 (NDR20 LE/ASCII/IEEE), frag_len, auth_length=0, call_id=1
///   body  (56 B): max_xmit=4280, max_recv=4280, assoc_group=0,
///     n_ctx=1 + 3-byte pad, then one ctx item:
///       ctx_id=0, n_xfer=1 + 1 reserved,
///       abstract_syntax = SRVSVC UUID (16 LE) + version (3.0 = 4 B),
///       transfer_syntax = NDR20 UUID (16 LE) + version (2 = 4 B)
fn build_srvsvc_bind_pdu() -> Vec<u8> {
    // SRVSVC: 4B324FC8-1670-01D3-1278-5A47BF6EE188 — first 3 fields LE.
    const SRVSVC_UUID_LE: [u8; 16] = [
        0xC8, 0x4F, 0x32, 0x4B, 0x70, 0x16, 0xD3, 0x01, 0x12, 0x78, 0x5A, 0x47, 0xBF, 0x6E, 0xE1,
        0x88,
    ];
    // NDR20: 8A885D04-1CEB-11C9-9FE8-08002B104860 — first 3 fields LE.
    const NDR20_UUID_LE: [u8; 16] = [
        0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11, 0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48,
        0x60,
    ];

    let mut body = Vec::with_capacity(56);
    body.extend_from_slice(&4280u16.to_le_bytes()); // max_xmit_frag
    body.extend_from_slice(&4280u16.to_le_bytes()); // max_recv_frag
    body.extend_from_slice(&0u32.to_le_bytes()); // assoc_group_id
    body.push(1); // n_context_elem
    body.extend_from_slice(&[0u8; 3]); // pad
    // context item 0
    body.extend_from_slice(&0u16.to_le_bytes()); // context_id
    body.push(1); // n_transfer_syn
    body.push(0); // reserved
    body.extend_from_slice(&SRVSVC_UUID_LE); // abstract_syntax UUID
    body.extend_from_slice(&3u16.to_le_bytes()); // version major
    body.extend_from_slice(&0u16.to_le_bytes()); // version minor
    body.extend_from_slice(&NDR20_UUID_LE); // transfer_syntax UUID
    body.extend_from_slice(&2u32.to_le_bytes()); // transfer version
    debug_assert_eq!(body.len(), 56, "DCE/RPC Bind body must be 56 bytes");

    let frag_len = (16 + body.len()) as u16;
    let mut pdu = Vec::with_capacity(16 + body.len());
    pdu.push(5); // rpc_vers
    pdu.push(0); // rpc_vers_minor
    pdu.push(11); // PTYPE = BIND
    pdu.push(0x03); // pfc_flags = FIRST | LAST
    pdu.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // drep: NDR20 LE
    pdu.extend_from_slice(&frag_len.to_le_bytes());
    pdu.extend_from_slice(&0u16.to_le_bytes()); // auth_length
    pdu.extend_from_slice(&1u32.to_le_bytes()); // call_id
    pdu.extend_from_slice(&body);
    debug_assert_eq!(pdu.len(), 72);
    pdu
}

/// End-to-end: open `\PIPE\srvsvc`, push a SRVSVC Bind PDU through
/// FSCTL_PIPE_TRANSCEIVE, assert the response is a Bind Ack.
///
/// This is the load-bearing Phase 3 smoke test — it exercises every line of
/// SMB2 CREATE / IOCTL / CLOSE we just added, against a real Samba server.
#[test]
#[ignore = "requires Samba container on NETRAZE_SAMBA_ADDR (default 127.0.0.1:1445)"]
fn pipe_transceive_drives_srvsvc_bind_to_bindack() {
    if !samba_reachable() {
        panic!(
            "Samba container not running at {}. See tests/samba/README.md",
            samba_addr()
        );
    }

    let addr = samba_addr();
    let mut session =
        Smb2Session::connect_with_password(&addr, TEST_USER, TEST_DOMAIN, TEST_PASSWORD)
            .expect("session_setup must succeed against live Samba");

    let host_only = addr.split(':').next().unwrap_or(&addr);
    let ipc = session
        .tree_connect(host_only, "IPC$")
        .expect("tree_connect IPC$ must succeed");

    // Open the SRVSVC pipe over the IPC$ tree.
    let pipe = session
        .pipe_open(ipc, "srvsvc")
        .expect("pipe_open(srvsvc) must succeed against live Samba");
    assert_ne!(pipe.file_id, [0u8; 16], "FileId must be non-zero");

    // Transceive a SRVSVC Bind PDU; expect a Bind Ack back.
    let bind = build_srvsvc_bind_pdu();
    let resp = session
        .pipe_transceive(&pipe, &bind)
        .expect("FSCTL_PIPE_TRANSCEIVE must succeed");

    assert!(
        resp.len() >= 16,
        "DCE/RPC response too short for a header: {} bytes",
        resp.len()
    );
    // PDU type at byte offset 2: 12 = BIND_ACK, 13 = BIND_NAK, 11 = BIND.
    let ptype = resp[2];
    assert_eq!(
        ptype,
        12,
        "expected BIND_ACK (12), got PTYPE={ptype} (full header: {:02x?})",
        &resp[..16]
    );
    // call_id @ offset 12 must echo our 1.
    let call_id = u32::from_le_bytes(resp[12..16].try_into().unwrap());
    assert_eq!(call_id, 1, "Bind Ack must echo call_id=1");

    // Clean shutdown.
    session.pipe_close(&pipe).expect("pipe_close must succeed");
    let _ = session.tree_disconnect(ipc);
}

// ─── Phase 4: Authenticated DCE/RPC bind + sealed NetrShareEnum ─────────

/// End-to-end: authenticated NTLMSSP bind with PKT_PRIVACY on `\PIPE\srvsvc`,
/// then a sealed `NetrShareEnum` request/response round-trip.
///
/// This exercises the full Phase 4 stack: NtlmBinder, RpcChannel,
/// NtlmAuthenticator (sign+seal), and the SRVSVC request/response codecs.
#[tokio::test]
#[ignore = "requires Samba container on NETRAZE_SAMBA_ADDR (default 127.0.0.1:1445)"]
async fn srvsvc_authenticated_share_enum() {
    if !samba_reachable() {
        panic!(
            "Samba container not running at {}. See tests/samba/README.md",
            samba_addr()
        );
    }

    let addr = samba_addr();
    let mut session =
        Smb2Session::connect_with_password(&addr, TEST_USER, TEST_DOMAIN, TEST_PASSWORD)
            .expect("session_setup must succeed against live Samba");

    let host_only = addr.split(':').next().unwrap_or(&addr);
    let ipc = session
        .tree_connect(host_only, "IPC$")
        .expect("tree_connect IPC$ must succeed");

    let session_arc = Arc::new(Mutex::new(session));
    let transport =
        SmbPipeTransport::open(Arc::clone(&session_arc), ipc, "srvsvc").expect("open srvsvc pipe");
    let pipe_handle = *transport.handle();

    let cred = SmbCredential::new(TEST_USER, TEST_DOMAIN, TEST_PASSWORD);
    let binder = netraze_protocols::smb::rpc::build_binder(&cred, 0);
    let transport_arc: Arc<dyn netraze_dcerpc::transport::RpcTransport> = Arc::new(transport);

    let mut ch = RpcChannel::bind_authenticated(
        transport_arc,
        netraze_dcerpc::interfaces::srvsvc::uuid(),
        (3, 0),
        binder,
    )
    .await
    .expect("bind_authenticated must succeed");

    let request = netraze_dcerpc::interfaces::srvsvc::encode_netr_share_enum_request(
        host_only, 0xFFFFFFFF, 0,
    );
    let response_stub = ch
        .call(
            netraze_dcerpc::interfaces::srvsvc::Opnum::NetrShareEnum as u16,
            &request,
        )
        .await
        .expect("NetrShareEnum call must succeed");

    let resp = netraze_dcerpc::interfaces::srvsvc::decode_netr_share_enum_response(&response_stub)
        .expect("decode response must succeed");

    assert!(
        !resp.shares.is_empty(),
        "Samba must expose at least one share"
    );
    let names: Vec<String> = resp.shares.iter().map(|e| e.netname.clone()).collect();
    assert!(
        names.contains(&"IPC$".to_string()),
        "IPC$ must be present, got {names:?}"
    );

    // Clean shutdown: close the pipe via the shared session.
    // Samba may already have closed the pipe handle on its side after the
    // last DCE/RPC response, so we ignore STATUS_FILE_CLOSED (0xC0000128).
    drop(ch);
    {
        let mut s = session_arc.lock().unwrap();
        let _ = s.pipe_close(&pipe_handle);
        let _ = s.tree_disconnect(ipc);
    }
}
