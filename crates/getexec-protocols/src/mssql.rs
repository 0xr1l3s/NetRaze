use crate::StaticProtocolFactory;
use getexec_core::Capability;

pub fn factory() -> StaticProtocolFactory {
    StaticProtocolFactory::new(
        "mssql",
        "MSSQL",
        1433,
        vec![
            Capability::Authentication,
            Capability::CommandExecution,
            Capability::DatabaseAccess,
            Capability::Enumeration,
            Capability::SecretDump,
        ],
    )
}
