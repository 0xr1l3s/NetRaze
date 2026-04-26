//! Concrete RPC interfaces. One module per MS-* protocol. Every interface
//! module:
//!   - exposes its `UUID` and `VERSION` constants
//!   - defines typed request/response structs
//!   - implements encoding via [`crate::ndr`] and fragment assembly via
//!     [`crate::pdu`]
//!
//! The list below grows Phase by Phase. For Phase 1 we only ship SRVSVC.

pub mod samr;
pub mod scmr;
pub mod srvsvc;
pub mod winreg;
