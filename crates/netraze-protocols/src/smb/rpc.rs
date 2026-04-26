//! `SmbPipeTransport` — DCE/RPC carrier over an SMB2 named pipe via
//! `FSCTL_PIPE_TRANSCEIVE`.
//!
//! Phase 3 of the cross-platform portage plan: this is the bridge that lets
//! every Phase 4-6 RPC interface (MS-SRVS share enum, MS-SAMR user enum,
//! MS-SVCCTL service control for smbexec, MS-WKSSVC info, MS-WINREG hive
//! access for SAM / LSA dump) talk to a remote Windows host from any OS,
//! without needing the `windows` crate.
//!
//! This module lives on the `netraze-protocols` side rather than inside
//! `netraze-dcerpc` so the dependency direction stays `protocols -> dcerpc`
//! only — the dcerpc crate must remain leaf.

use std::io::Write;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use netraze_dcerpc::auth::{AuthLevel, NtlmAuthenticator, NtlmBinder};
use netraze_dcerpc::{DceRpcError, Result as RpcResult, RpcTransport};

use super::connection::SmbCredential;
use super::smb2::{PipeHandle, Smb2Session};

/// Open a fresh SMB2 session to `target` using whichever auth path
/// `cred` provides — pass-the-hash if `nt_hash` is set, otherwise the
/// password-derived hash. Used by every `*_rpc` orchestrator
/// (`info_rpc`, `shares_rpc`, `users_rpc`, `dump_rpc`, `exec_rpc`) to
/// avoid copy-pasting the same 6-line dispatch.
///
/// `target` may be `host`, `host:port`, or `[ipv6]:port` — same shapes
/// `Smb2Session::connect` accepts. Returns the session ready for
/// `tree_connect("IPC$")` plus any subsequent pipe opens.
pub fn connect_session(target: &str, cred: &SmbCredential) -> Result<Smb2Session, String> {
    if let Some(hash) = cred.nt_hash {
        Smb2Session::connect(target, &hash, &cred.username, &cred.domain)
    } else {
        Smb2Session::connect_with_password(target, &cred.username, &cred.domain, &cred.password)
    }
}

/// Default fragment caps for an SMB2 named-pipe transport. 4280 bytes is the
/// value Windows advertises in the bind exchange when the carrier is a pipe;
/// it leaves room for one PDU header + sealed payload + auth verifier inside
/// a single SMB2 IOCTL response without provoking server-side fragmentation.
const DEFAULT_MAX_FRAG: u16 = 4280;

/// One DCE/RPC carrier riding one SMB2 named pipe.
///
/// One `SmbPipeTransport` == one open pipe (e.g. `\PIPE\srvsvc`). Several
/// transports may share a single `Smb2Session` via clones of the same
/// `Arc<Mutex<…>>` — the mutex serialises the FSCTL_PIPE_TRANSCEIVE round
/// trips so `message_id` and the underlying TCP stream stay consistent.
/// Typical multiplex pattern (Phase 6 SAM dump):
///
/// ```ignore
/// let session = Arc::new(Mutex::new(Smb2Session::connect(host, &nt, u, d)?));
/// let ipc = { session.lock().unwrap().tree_connect(host, "IPC$")? };
/// let srvsvc = SmbPipeTransport::open(session.clone(), ipc, "srvsvc")?;
/// let samr   = SmbPipeTransport::open(session.clone(), ipc, "samr")?;
/// let winreg = SmbPipeTransport::open(session.clone(), ipc, "winreg")?;
/// ```
///
/// FSCTL_PIPE_TRANSCEIVE is intrinsically request/response in one shot, but
/// the `RpcTransport` contract has `send` / `recv` as separate methods. We
/// bridge that by doing the full transceive inside `send` and stashing the
/// response in a small mailbox for the matching `recv` to drain.
pub struct SmbPipeTransport {
    session: Arc<Mutex<Smb2Session>>,
    handle: PipeHandle,
    pending: Mutex<Option<Vec<u8>>>,
    max_xmit: u16,
    max_recv: u16,
}

impl SmbPipeTransport {
    /// Open `\PIPE\<pipe_name>` on an already-connected SMB2 session.
    ///
    /// The caller is responsible for tree-connecting to `IPC$` first and
    /// passing the resulting `tree_id` here. Keeping that explicit lets one
    /// session share a single IPC$ tree across several pipe transports.
    pub fn open(
        session: Arc<Mutex<Smb2Session>>,
        ipc_tree_id: u32,
        pipe_name: &str,
    ) -> Result<Self, String> {
        let handle = {
            let mut s = session
                .lock()
                .map_err(|e| format!("smb2 session mutex poisoned: {e}"))?;
            s.pipe_open(ipc_tree_id, pipe_name)?
        };
        Ok(Self {
            session,
            handle,
            pending: Mutex::new(None),
            max_xmit: DEFAULT_MAX_FRAG,
            max_recv: DEFAULT_MAX_FRAG,
        })
    }

    /// Open the pipe with explicit fragment caps. Useful for testing edge
    /// cases of the DCE/RPC layer (small frags force fragmentation).
    pub fn open_with_caps(
        session: Arc<Mutex<Smb2Session>>,
        ipc_tree_id: u32,
        pipe_name: &str,
        max_xmit: u16,
        max_recv: u16,
    ) -> Result<Self, String> {
        let mut t = Self::open(session, ipc_tree_id, pipe_name)?;
        t.max_xmit = max_xmit;
        t.max_recv = max_recv;
        Ok(t)
    }

    /// Underlying pipe handle. Exposed for diagnostics — callers should
    /// route I/O through `RpcTransport::{send,recv}` rather than poking
    /// the handle directly.
    pub fn handle(&self) -> &PipeHandle {
        &self.handle
    }
}

#[async_trait]
impl RpcTransport for SmbPipeTransport {
    async fn send(&self, pdu: &[u8]) -> RpcResult<()> {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(r"C:\temp\netraze_tx.bin")
        {
            let _ = f.write_all(pdu);
        }
        // Run the synchronous SMB I/O on a blocking thread so we don't pin
        // the tokio runtime while waiting on the network. The mutex is held
        // only for the duration of the transceive — no `.await` inside.
        let session = Arc::clone(&self.session);
        let handle = self.handle; // Copy
        let pdu_owned = pdu.to_vec();

        let resp = tokio::task::spawn_blocking(move || -> Result<Vec<u8>, String> {
            let mut s = session
                .lock()
                .map_err(|e| format!("smb2 session mutex poisoned: {e}"))?;
            s.pipe_transceive(&handle, &pdu_owned)
        })
        .await
        .map_err(|e| DceRpcError::Transport(format!("spawn_blocking failed: {e}")))?
        .map_err(DceRpcError::Transport)?;

        let mut slot = self
            .pending
            .lock()
            .map_err(|e| DceRpcError::Transport(format!("pending mutex poisoned: {e}")))?;
        if slot.is_some() {
            return Err(DceRpcError::Transport(
                "pipe transport: send() called twice without an intervening recv()".into(),
            ));
        }
        *slot = Some(resp);
        Ok(())
    }

    async fn recv(&self) -> RpcResult<Vec<u8>> {
        let data = self
            .pending
            .lock()
            .map_err(|e| DceRpcError::Transport(format!("pending mutex poisoned: {e}")))?
            .take()
            .ok_or_else(|| {
                DceRpcError::Transport(
                    "pipe transport: recv() with no prior send() — call send first".into(),
                )
            })?;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(r"C:\temp\netraze_rx.bin")
        {
            let _ = f.write_all(&data);
        }
        Ok(data)
    }

    /// Override the default-trait fallback: AUTH3 (and any other one-way
    /// PDU) MUST go out as a plain SMB2 WRITE, never as
    /// `FSCTL_PIPE_TRANSCEIVE`. The transceive IOCTL's read half blocks
    /// waiting for response data the server will never produce, deadlocking
    /// the bind dance the moment we send AUTH3.
    ///
    /// We deliberately leave `pending` untouched — there's nothing to
    /// drain on the next `recv()` because the next caller-driven exchange
    /// is the first sealed Request, which has its own response.
    async fn send_oneway(&self, pdu: &[u8]) -> RpcResult<()> {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(r"C:\temp\netraze_tx.bin")
        {
            let _ = f.write_all(pdu);
        }
        let session = Arc::clone(&self.session);
        let handle = self.handle;
        let pdu_owned = pdu.to_vec();

        tokio::task::spawn_blocking(move || -> Result<(), String> {
            let mut s = session
                .lock()
                .map_err(|e| format!("smb2 session mutex poisoned: {e}"))?;
            s.pipe_write(&handle, &pdu_owned)
        })
        .await
        .map_err(|e| DceRpcError::Transport(format!("spawn_blocking failed: {e}")))?
        .map_err(DceRpcError::Transport)?;

        Ok(())
    }

    fn max_xmit_frag(&self) -> u16 {
        self.max_xmit
    }

    fn max_recv_frag(&self) -> u16 {
        self.max_recv
    }
}

/// Build the [`NtlmBinder`] driving the DCE/RPC NTLMSSP bind handshake from
/// a credential the caller already used to set up the SMB session.
///
/// `cred.nt_hash` is preferred when present (pass-the-hash). Otherwise we
/// derive it from the plaintext password — the SMB layer would have done
/// the same thing earlier in `Smb2Session::connect`, so the derived hash
/// is identical to whatever the SMB session is using.
///
/// `ctx_id` is the per-bind `auth_context_id` carried in every subsequent
/// `sec_trailer`. Conventionally `0` for the first bind on a connection;
/// open multiple binds on one pipe (we don't yet) by incrementing.
///
/// # Why not reuse the SMB session key directly?
///
/// Some plans floated reusing `Smb2Session::exported_session_key()` to
/// short-circuit the bind dance into a fresh [`NtlmAuthenticator`]. That
/// is **not** how Microsoft DCE/RPC over SMB pipes works: the DCE/RPC
/// layer performs its own NTLMSSP handshake (NEGOTIATE → CHALLENGE →
/// AUTHENTICATE) inside the bind PDUs, producing an independent session
/// key that has nothing to do with the SMB layer's. Pretending otherwise
/// works against Samba (which is permissive about replays of session
/// keys) but breaks against any real Windows server.
pub fn build_binder(cred: &SmbCredential, ctx_id: u32) -> NtlmBinder {
    let nt_hash = cred
        .nt_hash
        .unwrap_or_else(|| netraze_dcerpc::auth::nt_hash_from_password(&cred.password));
    NtlmBinder::new(
        nt_hash,
        cred.username.clone(),
        cred.domain.clone(),
        AuthLevel::PktPrivacy,
        ctx_id,
    )
}

/// Build an [`NtlmAuthenticator`] directly from a 16-byte session key.
///
/// Reserved for callers that already drove the NTLMSSP handshake outside
/// of [`RpcChannel::bind_authenticated`] and just need to wrap the
/// resulting key into a sealing context. Most code wants
/// [`build_binder`] + [`RpcChannel::bind_authenticated`] instead — those
/// drive the handshake themselves.
///
/// [`RpcChannel::bind_authenticated`]: netraze_dcerpc::RpcChannel::bind_authenticated
pub fn build_authenticator_from_session_key(
    session_key: [u8; 16],
    ctx_id: u32,
) -> NtlmAuthenticator {
    NtlmAuthenticator::new_ntlmv2_extended(session_key, AuthLevel::PktPrivacy, ctx_id)
}

impl Drop for SmbPipeTransport {
    fn drop(&mut self) {
        // Best-effort close. If the mutex is poisoned (caller panicked mid
        // transceive) or the underlying TCP stream is dead, we silently skip
        // — the pipe handle leaks server-side until session logoff, which is
        // acceptable. We deliberately do NOT recover the poisoned guard with
        // `into_inner` because issuing more SMB ops on a half-broken session
        // would just stack errors.
        if let Ok(mut s) = self.session.lock() {
            let _ = s.pipe_close(&self.handle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `SmbPipeTransport` is `Send + Sync`, which it must be to satisfy
    /// `RpcTransport`'s `Send + Sync` super-bound. This is a compile-time
    /// check — if the type ever loses `Sync` (e.g. by adding a `Cell`),
    /// this test fails to compile.
    #[test]
    fn transport_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SmbPipeTransport>();
    }

    /// Pure-logic test for the pending slot mailbox: send → recv drains,
    /// double send rejected, recv-without-send rejected. We exercise the
    /// state machine on a bare `Mutex<Option<Vec<u8>>>` because building a
    /// real `SmbPipeTransport` needs an open SMB session.
    #[test]
    fn pending_mailbox_round_trip() {
        let slot: Mutex<Option<Vec<u8>>> = Mutex::new(None);

        // First send: populates.
        *slot.lock().unwrap() = Some(b"frag-1".to_vec());

        // Second send before recv: must detect non-empty slot.
        assert!(slot.lock().unwrap().is_some());

        // Recv: drains.
        let drained = slot.lock().unwrap().take();
        assert_eq!(drained.as_deref(), Some(b"frag-1".as_ref()));

        // Recv on empty: returns None (caller maps to error).
        assert!(slot.lock().unwrap().take().is_none());
    }
}
