use std::net::Ipv4Addr;

/// Parse a target string into individual IP addresses.
/// Supports:
/// - Single IP: "192.168.1.10"
/// - CIDR notation: "192.168.1.0/24"
/// - IP range: "192.168.1.1-192.168.1.50"
/// - Hostname: "dc01.corp.local"
pub fn expand_targets(raw: &str) -> Vec<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    // CIDR notation
    if let Some((base, prefix_str)) = trimmed.split_once('/') {
        if let (Ok(base_ip), Ok(prefix_len)) = (base.parse::<Ipv4Addr>(), prefix_str.parse::<u32>())
        {
            if prefix_len <= 32 {
                return expand_cidr(base_ip, prefix_len);
            }
        }
    }

    // IP range: 192.168.1.1-192.168.1.50
    if let Some((start_str, end_str)) = trimmed.split_once('-') {
        if let (Ok(start), Ok(end)) = (
            start_str.trim().parse::<Ipv4Addr>(),
            end_str.trim().parse::<Ipv4Addr>(),
        ) {
            return expand_range(start, end);
        }
    }

    // Single IP or hostname
    vec![trimmed.to_owned()]
}

fn expand_cidr(base: Ipv4Addr, prefix_len: u32) -> Vec<String> {
    if prefix_len == 32 {
        return vec![base.to_string()];
    }

    let base_u32 = u32::from(base);
    let mask = if prefix_len == 0 {
        0
    } else {
        !0u32 << (32 - prefix_len)
    };
    let network = base_u32 & mask;
    let host_bits = 32 - prefix_len;
    let host_count = 1u32 << host_bits;

    // Skip network address (.0) and broadcast (.255 for /24)
    // For /31 and /32, include all
    if host_bits <= 1 {
        return (0..host_count)
            .map(|i| Ipv4Addr::from(network + i).to_string())
            .collect();
    }

    (1..host_count - 1)
        .map(|i| Ipv4Addr::from(network + i).to_string())
        .collect()
}

fn expand_range(start: Ipv4Addr, end: Ipv4Addr) -> Vec<String> {
    let s = u32::from(start);
    let e = u32::from(end);
    if e < s {
        return Vec::new();
    }
    // Cap at 65536 to avoid accidental huge ranges
    let count = (e - s + 1).min(65536);
    (0..count)
        .map(|i| Ipv4Addr::from(s + i).to_string())
        .collect()
}

/// Parse multiple target entries (comma/newline/space separated) and expand each.
pub fn parse_target_list(input: &str) -> Vec<String> {
    input
        .split(|c: char| c == ',' || c == '\n')
        .flat_map(|entry| {
            let trimmed = entry.trim();
            if trimmed.is_empty() {
                Vec::new()
            } else {
                expand_targets(trimmed)
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_ip() {
        assert_eq!(expand_targets("10.0.0.1"), vec!["10.0.0.1"]);
    }

    #[test]
    fn test_cidr_24() {
        let result = expand_targets("192.168.1.0/24");
        assert_eq!(result.len(), 254);
        assert_eq!(result[0], "192.168.1.1");
        assert_eq!(result[253], "192.168.1.254");
    }

    #[test]
    fn test_cidr_30() {
        let result = expand_targets("10.0.0.0/30");
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], "10.0.0.1");
        assert_eq!(result[1], "10.0.0.2");
    }

    #[test]
    fn test_range() {
        let result = expand_targets("10.0.0.1-10.0.0.5");
        assert_eq!(result.len(), 5);
    }

    #[test]
    fn test_hostname() {
        assert_eq!(expand_targets("dc01.corp.local"), vec!["dc01.corp.local"]);
    }
}
