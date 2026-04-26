//! Pure-Rust DCE/RPC v5 client stack — Phase 1 of the cross-platform portage.
//!
//! # What this crate provides
//!
//! A minimal Microsoft-flavoured DCE/RPC client — the subset needed to drive
//! the MS-SRVS, MS-SAMR, MS-LSAT, MS-SCMR, MS-RRP, MS-TSCH, MS-EPM and
//! MS-DCOM / MS-WMI interfaces from any platform. Roughly:
//!
//! - **[`pdu`]** — CO (connection-oriented) v5 fragments: header, bind /
//!   bind_ack, alter_context, request, response, fault, auth3. Encoder +
//!   decoder, size-safe.
//! - **[`ndr`]** — NDR20 reader/writer. Supports the subset actually seen on
//!   the wire for the interfaces above: primitives, conformant/varying
//!   arrays, referent pointers with deferred layout, UTF-16 wide strings.
//! - **[`auth`]** — NTLMSSP sign+seal for `PKT_PRIVACY`. Produces the
//!   `auth_verifier` blob embedded in each fragment, handles the bind /
//!   auth3 / alter_context negotiation dance.
//! - **[`transport`]** — `RpcTransport` async trait. Phase 1 ships an
//!   in-memory loopback for tests; Phase 2 adds the SMB named-pipe adapter
//!   (`IOCTL_FSCTL_PIPE_TRANSCEIVE`) and Phase 7 adds TCP 135 + EPM.
//! - **[`interfaces`]** — one module per RPC interface. Each module owns its
//!   UUID, version, opnums, and typed request / response structs.
//!
//! # Status
//!
//! Phase 1 scaffold. The public surface exists so downstream crates
//! (`netraze-protocols`) can start taking a dependency; concrete wire
//! encoding lands opnum-by-opnum. Everything compiles and unit-tests run on
//! every platform — no `cfg(windows)` allowed inside this crate.

pub mod auth;
pub mod channel;
pub mod error;
pub mod interfaces;
pub mod ndr;
pub mod pdu;
pub mod transport;
pub mod uuid;

pub use channel::RpcChannel;
pub use error::{DceRpcError, Result};
pub use transport::RpcTransport;
pub use uuid::Uuid;
