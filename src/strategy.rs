use crate::event::RawEvent;
use crate::hash::{base62, frame, Hasher, SaltProvider};
use crate::ip::{mask_ip, IpMaskMode};
use crate::visitor::VisitorId;
use std::net::IpAddr;

/// Computes the visitor id for an event. Sees the whole RawEvent.
///
/// The generated ID incorporates the user-agent, so it CHANGES whenever the
/// visitor's UA changes (e.g. a browser update). It is stable per
/// `(masked-IP, user-agent, salt)` tuple, not per-person. A pre-set
/// [`RawEvent::visitor_id`] is trusted and passed through VERBATIM (never hashed).
pub trait VisitorIdStrategy: Send + Sync {
    fn visitor_id(&self, raw: &RawEvent) -> Option<VisitorId>;
}

fn ip_octets(ip: IpAddr, buf: &mut [u8; 16]) -> usize {
    match ip {
        IpAddr::V4(a) => {
            buf[..4].copy_from_slice(&a.octets());
            4
        }
        IpAddr::V6(a) => {
            buf.copy_from_slice(&a.octets());
            16
        }
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
    let mut buf = [0u8; 16];
    let n = ip_octets(ip, &mut buf);
    let octets = &buf[..n];
    let salt = s.current_salt();
    let entity = raw.entity_id.as_deref().unwrap_or("").as_bytes();
    let ua = raw.user_agent.as_deref().unwrap_or("").as_bytes();
    let framed = frame(&[entity, octets, ua, &salt]);
    Some(VisitorId::new_unchecked(base62(&h.hash(&framed))))
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
    /// Note: `IpMaskMode::None` and `IpMaskMode::Full` perform NO masking — the
    /// full-precision IP enters the hash. Pass `Balanced` or `Accurate` for actual
    /// IP coarsening; the other two are a privacy footgun if chosen by accident.
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
