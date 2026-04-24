use crate::StaticProtocolFactory;
use netraze_core::Capability;

pub fn factory() -> StaticProtocolFactory {
    StaticProtocolFactory::new(
        "rdp",
        "RDP",
        3389,
        vec![
            Capability::Authentication,
            Capability::DesktopAccess,
            Capability::Enumeration,
        ],
    )
}
