use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TargetKind {
    Hostname,
    Ipv4,
    Ipv6,
    Cidr,
    FileList,
    NmapXml,
    Nessus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TargetSpec {
    pub raw: String,
    pub kind: TargetKind,
}

pub fn classify_target(raw: &str) -> TargetSpec {
    let kind = if raw.ends_with(".xml") {
        TargetKind::NmapXml
    } else if raw.ends_with(".nessus") {
        TargetKind::Nessus
    } else if raw.contains('/') {
        TargetKind::Cidr
    } else if raw.parse::<std::net::IpAddr>().is_ok() {
        if raw.contains(':') {
            TargetKind::Ipv6
        } else {
            TargetKind::Ipv4
        }
    } else {
        TargetKind::Hostname
    };

    TargetSpec {
        raw: raw.to_owned(),
        kind,
    }
}
