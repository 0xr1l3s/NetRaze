use crate::StaticProtocolFactory;
use netraze_core::Capability;

pub fn factory() -> StaticProtocolFactory {
    StaticProtocolFactory::new(
        "ldap",
        "LDAP",
        389,
        vec![
            Capability::Authentication,
            Capability::Enumeration,
            Capability::SecretDump,
            Capability::ModuleHooks,
        ],
    )
}
