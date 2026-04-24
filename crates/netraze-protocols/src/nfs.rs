use crate::StaticProtocolFactory;
use netraze_core::Capability;

pub fn factory() -> StaticProtocolFactory {
    StaticProtocolFactory::new(
        "nfs",
        "NFS",
        2049,
        vec![Capability::Enumeration, Capability::FileTransfer],
    )
}
