use arc_swap::ArcSwap;
use std::sync::Arc;

#[cfg(feature = "blake3")]
pub mod blake3;
#[cfg(feature = "sha256")]
pub mod sha256;

/// Produces a 32-byte digest. Framing + encoding live in the strategy, not here.
pub trait Hasher: Send + Sync {
    fn hash(&self, bytes: &[u8]) -> [u8; 32];
}

/// Supplies the current salt. The consumer owns if/when it rotates.
pub trait SaltProvider: Send + Sync {
    fn current_salt(&self) -> Arc<[u8]>;
}

const ALPHABET: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// First 16 digest bytes → 16 base62 chars.
pub fn base62_16(digest: &[u8; 32]) -> String {
    digest[..16]
        .iter()
        .map(|b| ALPHABET[(*b as usize) % 62] as char)
        .collect()
}

/// Length-prefixed concatenation (8-byte LE length per part). Stable positions.
pub fn frame(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in parts {
        out.extend_from_slice(&(p.len() as u64).to_le_bytes());
        out.extend_from_slice(p);
    }
    out
}

/// A fixed salt set once.
pub struct StaticSalt(Arc<[u8]>);
impl StaticSalt {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        StaticSalt(Arc::from(bytes.into().into_boxed_slice()))
    }
}
impl SaltProvider for StaticSalt {
    fn current_salt(&self) -> Arc<[u8]> {
        self.0.clone()
    }
}

/// A hot-swappable salt. The consumer calls `set` on its own schedule.
pub struct ArcSwapSalt(ArcSwap<Arc<[u8]>>);
impl ArcSwapSalt {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        let a: Arc<[u8]> = Arc::from(bytes.into().into_boxed_slice());
        ArcSwapSalt(ArcSwap::from_pointee(a))
    }
    pub fn set(&self, bytes: impl Into<Vec<u8>>) {
        let a: Arc<[u8]> = Arc::from(bytes.into().into_boxed_slice());
        self.0.store(Arc::new(a));
    }
}
impl SaltProvider for ArcSwapSalt {
    fn current_salt(&self) -> Arc<[u8]> {
        (*self.0.load_full()).clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base62_is_16_chars_and_printable() {
        let out = base62_16(&[0u8; 32]);
        assert_eq!(out.len(), 16);
        assert!(out.bytes().all(|b| (0x21..=0x7E).contains(&b)));
    }

    #[test]
    fn framing_is_unambiguous() {
        assert_ne!(frame(&[b"ab", b"cdef"]), frame(&[b"abc", b"def"]));
    }

    #[test]
    fn static_salt_returns_same_bytes() {
        let s = StaticSalt::new(vec![1, 2, 3]);
        assert_eq!(&*s.current_salt(), &[1, 2, 3]);
    }

    #[test]
    fn arc_swap_salt_swaps() {
        let s = ArcSwapSalt::new(vec![1]);
        assert_eq!(&*s.current_salt(), &[1]);
        s.set(vec![9, 9]);
        assert_eq!(&*s.current_salt(), &[9, 9]);
    }
}
