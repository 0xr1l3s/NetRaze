use crate::StaticProtocolFactory;
use netraze_core::Capability;

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
