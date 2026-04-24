use crate::StaticProtocolFactory;
use netraze_core::Capability;

pub fn factory() -> StaticProtocolFactory {
    StaticProtocolFactory::new(
        "vnc",
        "VNC",
        5900,
        vec![
            Capability::Authentication,
            Capability::DesktopAccess,
            Capability::Enumeration,
        ],
    )
}
