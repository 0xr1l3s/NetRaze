use crate::StaticProtocolFactory;
use netraze_core::Capability;

pub fn factory() -> StaticProtocolFactory {
    StaticProtocolFactory::new(
        "ftp",
        "FTP",
        21,
        vec![
            Capability::Authentication,
            Capability::Enumeration,
            Capability::FileTransfer,
            Capability::ModuleHooks,
        ],
    )
}
