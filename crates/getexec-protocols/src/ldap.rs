use crate::StaticProtocolFactory;
use getexec_core::Capability;

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
