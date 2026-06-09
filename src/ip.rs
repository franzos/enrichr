use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// IP masking spectrum. `(ipv4_prefix, ipv6_prefix)` applied after IPv4-mapped normalization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum IpMaskMode {
    None,
    /// /24, /56
    Balanced,
    /// /28, /64
    Accurate,
    /// /32, /128 (no masking, but normalizes IPv4-mapped)
    Full,
}

impl IpMaskMode {
    fn prefixes(self) -> (u32, u32) {
        match self {
            IpMaskMode::None => (32, 128),
            IpMaskMode::Balanced => (24, 56),
            IpMaskMode::Accurate => (28, 64),
            IpMaskMode::Full => (32, 128),
        }
    }
}

pub fn mask_ip(ip: IpAddr, mode: IpMaskMode) -> IpAddr {
    if mode == IpMaskMode::None {
        return canonical(ip);
    }
    let (v4, v6) = mode.prefixes();
    match canonical(ip) {
        IpAddr::V4(a) => IpAddr::V4(mask_v4(a, v4)),
        IpAddr::V6(a) => IpAddr::V6(mask_v6(a, v6)),
    }
}

fn canonical(ip: IpAddr) -> IpAddr {
    if let IpAddr::V6(v6) = ip {
        if let Some(v4) = v6.to_ipv4_mapped() {
            return IpAddr::V4(v4);
        }
    }
    ip
}

fn mask_v4(a: Ipv4Addr, prefix: u32) -> Ipv4Addr {
    let bits = u32::from(a);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Ipv4Addr::from(bits & mask)
}

fn mask_v6(a: Ipv6Addr, prefix: u32) -> Ipv6Addr {
    let bits = u128::from(a);
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    Ipv6Addr::from(bits & mask)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn masks_ipv4_24() {
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 200));
        assert_eq!(
            mask_ip(ip, IpMaskMode::Balanced),
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 0))
        );
    }

    #[test]
    fn ipv4_mapped_v6_normalized_then_masked() {
        let mapped = IpAddr::V6("::ffff:1.2.3.200".parse::<Ipv6Addr>().unwrap());
        assert_eq!(
            mask_ip(mapped, IpMaskMode::Balanced),
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 0))
        );
    }

    #[test]
    fn none_is_identity() {
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(mask_ip(ip, IpMaskMode::None), ip);
    }
}
