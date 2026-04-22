use crate::StaticProtocolFactory;
use getexec_core::Capability;

pub fn factory() -> StaticProtocolFactory {
    StaticProtocolFactory::new(
        "ssh",
        "SSH",
        22,
        vec![
            Capability::Authentication,
            Capability::CommandExecution,
            Capability::Enumeration,
            Capability::FileTransfer,
            Capability::ModuleHooks,
        ],
    )
}
