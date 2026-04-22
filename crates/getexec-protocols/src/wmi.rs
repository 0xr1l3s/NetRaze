use crate::StaticProtocolFactory;
use getexec_core::Capability;

pub fn factory() -> StaticProtocolFactory {
    StaticProtocolFactory::new(
        "wmi",
        "WMI",
        135,
        vec![
            Capability::Authentication,
            Capability::CommandExecution,
            Capability::Enumeration,
            Capability::ModuleHooks,
        ],
    )
}
