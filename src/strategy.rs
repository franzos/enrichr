use crate::event::RawEvent;
use crate::hash::{base62_16, frame, Hasher, SaltProvider};
use crate::ip::{mask_ip, IpMaskMode};
use crate::visitor::VisitorId;
use std::net::IpAddr;

/// Computes the visitor id for an event. Sees the whole RawEvent.
pub trait VisitorIdStrategy: Send + Sync {
    fn visitor_id(&self, raw: &RawEvent) -> Option<VisitorId>;
}

fn ip_octets(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    }
}

fn compute<H: Hasher, S: SaltProvider>(
    h: &H,
    s: &S,
    raw: &RawEvent,
    mask: IpMaskMode,
) -> Option<VisitorId> {
    let ip = raw.ip?;
    let ip = mask_ip(ip, mask);
    let octets = ip_octets(ip);
    let salt = s.current_salt();
    let entity = raw.entity_id.as_deref().unwrap_or("").as_bytes();
    let ua = raw.user_agent.as_deref().unwrap_or("").as_bytes();
    let framed = frame(&[entity, &octets, ua, &salt]);
    Some(VisitorId::new_unchecked(base62_16(&h.hash(&framed))))
}

/// Full-precision: hashes the exact IP.
pub struct SaltedHasher<H: Hasher, S: SaltProvider> {
    hasher: H,
    salt: S,
}
impl<H: Hasher, S: SaltProvider> SaltedHasher<H, S> {
    pub fn new(hasher: H, salt: S) -> Self {
        SaltedHasher { hasher, salt }
    }
}
impl<H: Hasher, S: SaltProvider> VisitorIdStrategy for SaltedHasher<H, S> {
    fn visitor_id(&self, raw: &RawEvent) -> Option<VisitorId> {
        compute(&self.hasher, &self.salt, raw, IpMaskMode::Full)
    }
}

/// Recommended: masks the IP before hashing.
pub struct MaskedHashedStrategy<H: Hasher, S: SaltProvider> {
    hasher: H,
    salt: S,
    mask: IpMaskMode,
}
impl<H: Hasher, S: SaltProvider> MaskedHashedStrategy<H, S> {
    pub fn new(hasher: H, salt: S, mask: IpMaskMode) -> Self {
        MaskedHashedStrategy { hasher, salt, mask }
    }
}
impl<H: Hasher, S: SaltProvider> VisitorIdStrategy for MaskedHashedStrategy<H, S> {
    fn visitor_id(&self, raw: &RawEvent) -> Option<VisitorId> {
        compute(&self.hasher, &self.salt, raw, self.mask)
    }
}

#[cfg(all(test, feature = "blake3"))]
mod tests {
    use super::*;
    use crate::event::{EventKind, RawEvent};
    use crate::hash::{blake3::Blake3Hasher, StaticSalt};
    use chrono::Utc;
    use std::net::{IpAddr, Ipv4Addr};

    fn ev(ip: Option<IpAddr>, ua: Option<&str>, entity: Option<&str>) -> RawEvent {
        let mut e = RawEvent::new(EventKind::PageView, "https://x/".into(), Utc::now());
        e.ip = ip;
        e.user_agent = ua.map(Into::into);
        e.entity_id = entity.map(Into::into);
        e
    }

    #[test]
    fn none_when_ip_absent() {
        let s = SaltedHasher::new(Blake3Hasher, StaticSalt::new(vec![7; 16]));
        assert!(s.visitor_id(&ev(None, Some("ua"), None)).is_none());
    }

    #[test]
    fn stable_and_entity_isolated() {
        let s = SaltedHasher::new(Blake3Hasher, StaticSalt::new(vec![7; 16]));
        let ip = Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        let a = s.visitor_id(&ev(ip, Some("ua"), Some("siteA"))).unwrap();
        let a2 = s.visitor_id(&ev(ip, Some("ua"), Some("siteA"))).unwrap();
        let b = s.visitor_id(&ev(ip, Some("ua"), Some("siteB"))).unwrap();
        assert_eq!(a, a2);
        assert_ne!(a, b);
    }

    #[test]
    fn masked_groups_a_24() {
        let s = MaskedHashedStrategy::new(
            Blake3Hasher,
            StaticSalt::new(vec![7; 16]),
            crate::ip::IpMaskMode::Balanced,
        );
        let x = s
            .visitor_id(&ev(
                Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
                Some("ua"),
                None,
            ))
            .unwrap();
        let y = s
            .visitor_id(&ev(
                Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 99))),
                Some("ua"),
                None,
            ))
            .unwrap();
        assert_eq!(x, y);
    }
}
