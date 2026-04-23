//! `RpcTransport` — async trait all concrete transports implement.
//!
//! Two transports matter for our roadmap:
//!   1. **SMB named pipe** (`\\host\IPC$\srvsvc`, `\\host\IPC$\samr`, …) —
//!      a `FSCTL_PIPE_TRANSCEIVE` wrapped around an SMB2 session.
//!      Implementation lands in Phase 2 inside `getexec-protocols`.
//!   2. **TCP/IP 135 + EPM** — straight TCP connection talking to the
//!      endpoint mapper to resolve dynamic ports. Phase 7.
//!
//! Phase 1 ships a single built-in implementation — [`LoopbackTransport`] —
//! useful only for testing the PDU and NDR layers without a network.

use async_trait::async_trait;
use std::collections::VecDeque;
use std::sync::Mutex;

use crate::error::Result;

/// A full-duplex request/response pipe for DCE/RPC fragments.
///
/// The contract is deliberately simple: `send` writes one PDU fragment,
/// `recv` reads one. Fragmentation is the client's problem — the transport
/// never splits or reassembles.
#[async_trait]
pub trait RpcTransport: Send + Sync {
    /// Write exactly `pdu` to the peer.
    async fn send(&self, pdu: &[u8]) -> Result<()>;

    /// Read one fragment from the peer. Implementations MUST return a
    /// complete fragment (frag_length bytes) or an error — never a partial
    /// fragment.
    async fn recv(&self) -> Result<Vec<u8>>;

    /// Max fragment length we should advertise in `bind`. Windows default
    /// is 4280 on SMB pipes, 5840 over TCP.
    fn max_xmit_frag(&self) -> u16 {
        4280
    }

    fn max_recv_frag(&self) -> u16 {
        4280
    }
}

/// Loopback transport — everything `send`'d is enqueued for the next
/// `recv`. Useful for PDU-level tests that don't exercise the network.
///
/// Not `Clone` on purpose: the queue is owned state.
pub struct LoopbackTransport {
    queue: Mutex<VecDeque<Vec<u8>>>,
}

impl Default for LoopbackTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl LoopbackTransport {
    pub fn new() -> Self {
        Self { queue: Mutex::new(VecDeque::new()) }
    }

    /// Inject a canned response so the next `recv` returns it. Handy for
    /// decode tests.
    pub fn inject_response(&self, bytes: Vec<u8>) {
        self.queue.lock().expect("queue mutex").push_back(bytes);
    }
}

#[async_trait]
impl RpcTransport for LoopbackTransport {
    async fn send(&self, _pdu: &[u8]) -> Result<()> {
        // Swallow — tests don't inspect the outgoing bytes through recv.
        Ok(())
    }

    async fn recv(&self) -> Result<Vec<u8>> {
        self.queue
            .lock()
            .expect("queue mutex")
            .pop_front()
            .ok_or_else(|| crate::error::DceRpcError::Transport(
                "LoopbackTransport::recv — queue empty (call inject_response first)".into(),
            ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn loopback_returns_injected_frames_in_order() {
        let t = LoopbackTransport::new();
        t.inject_response(vec![1, 2, 3]);
        t.inject_response(vec![4, 5, 6]);
        assert_eq!(t.recv().await.unwrap(), vec![1, 2, 3]);
        assert_eq!(t.recv().await.unwrap(), vec![4, 5, 6]);
    }

    #[tokio::test]
    async fn loopback_recv_on_empty_is_error() {
        let t = LoopbackTransport::new();
        assert!(t.recv().await.is_err());
    }
}
