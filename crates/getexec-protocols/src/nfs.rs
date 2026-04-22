use crate::StaticProtocolFactory;
use getexec_core::Capability;

pub fn factory() -> StaticProtocolFactory {
    StaticProtocolFactory::new(
        "nfs",
        "NFS",
        2049,
        vec![Capability::Enumeration, Capability::FileTransfer],
    )
}
