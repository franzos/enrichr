use arc_swap::ArcSwap;
use std::sync::Arc;

#[cfg(feature = "blake3")]
pub mod blake3;
#[cfg(feature = "sha256")]
pub mod sha256;

/// Minimum salt length, in bytes, expected of a secret salt.
const MIN_SALT_LEN: usize = 16;

/// Returned by the checked salt constructors when the salt is too short to be a secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("salt must be at least {MIN_SALT_LEN} bytes of high-entropy secret")]
pub struct SaltTooShort;

/// Produces a 32-byte digest. Framing + encoding live in the strategy, not here.
pub trait Hasher: Send + Sync {
    fn hash(&self, bytes: &[u8]) -> [u8; 32];
}

/// Supplies the current salt for visitor-id hashing.
///
/// The salt is the ONLY secret protecting visitor IDs from trivial IP
/// re-identification: anyone who learns it can recompute the hash for any IP and
/// de-anonymize every visitor ID. Implementations MUST return a high-entropy
/// SECRET of at least 16 bytes and never expose it outside the process.
pub trait SaltProvider: Send + Sync {
    fn current_salt(&self) -> Arc<[u8]>;
}

const ALPHABET: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Unbiased base62 encoding of the full 32-byte digest, treated as a big-endian
/// integer (repeated divmod by 62). FROZEN: the alphabet and algorithm are stable.
pub fn base62(digest: &[u8; 32]) -> String {
    let mut bytes = *digest;
    let mut out = Vec::with_capacity(43);
    let mut start = 0;
    while start < bytes.len() {
        let mut rem = 0u32;
        for b in &mut bytes[start..] {
            let acc = (rem << 8) | u32::from(*b);
            *b = (acc / 62) as u8;
            rem = acc % 62;
        }
        out.push(ALPHABET[rem as usize]);
        if bytes[start] == 0 {
            start += 1;
        }
    }
    out.reverse();
    // SAFETY-equivalent: ALPHABET is ASCII, so the bytes are valid UTF-8.
    String::from_utf8(out).expect("base62 alphabet is ASCII")
}

/// Length-prefixed concatenation (8-byte LE length per part). Stable positions.
pub fn frame(parts: &[&[u8]]) -> Vec<u8> {
    let cap: usize = parts.iter().map(|p| 8 + p.len()).sum();
    let mut out = Vec::with_capacity(cap);
    for p in parts {
        out.extend_from_slice(&(p.len() as u64).to_le_bytes());
        out.extend_from_slice(p);
    }
    out
}

/// A fixed salt set once.
pub struct StaticSalt(Arc<[u8]>);
impl StaticSalt {
    /// The salt MUST be a high-entropy SECRET of at least 16 bytes. Anyone who
    /// learns it can de-anonymize visitor IDs by recomputing the hash for any IP.
    ///
    /// Infallible: only `debug_assert`s the length. Use [`StaticSalt::try_new`] to
    /// reject short salts at runtime.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        let bytes = bytes.into();
        debug_assert!(
            bytes.len() >= MIN_SALT_LEN,
            "salt should be at least {MIN_SALT_LEN} bytes of secret"
        );
        StaticSalt(Arc::from(bytes.into_boxed_slice()))
    }

    /// Like [`StaticSalt::new`] but returns an error for salts shorter than 16 bytes.
    pub fn try_new(bytes: impl Into<Vec<u8>>) -> Result<Self, SaltTooShort> {
        let bytes = bytes.into();
        if bytes.len() < MIN_SALT_LEN {
            return Err(SaltTooShort);
        }
        Ok(StaticSalt(Arc::from(bytes.into_boxed_slice())))
    }
}
impl SaltProvider for StaticSalt {
    fn current_salt(&self) -> Arc<[u8]> {
        self.0.clone()
    }
}

/// A hot-swappable salt. The consumer calls `set` on its own schedule.
///
/// The cell holds `Arc<Arc<[u8]>>`: `arc_swap` requires a `Sized` inner (`RefCnt`
/// is not implemented for `Arc<[u8]>`), and the inner `Arc<[u8]>` lets
/// `current_salt` hand out a cheap pointer-clone per event instead of copying the
/// salt bytes each time.
pub struct ArcSwapSalt(ArcSwap<Arc<[u8]>>);
impl ArcSwapSalt {
    /// The salt MUST be a high-entropy SECRET of at least 16 bytes. Anyone who
    /// learns it can de-anonymize visitor IDs by recomputing the hash for any IP.
    ///
    /// Infallible: only `debug_assert`s the length. Use [`ArcSwapSalt::try_new`] to
    /// reject short salts at runtime.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        let bytes = bytes.into();
        debug_assert!(
            bytes.len() >= MIN_SALT_LEN,
            "salt should be at least {MIN_SALT_LEN} bytes of secret"
        );
        let a: Arc<[u8]> = Arc::from(bytes.into_boxed_slice());
        ArcSwapSalt(ArcSwap::from_pointee(a))
    }

    /// Like [`ArcSwapSalt::new`] but returns an error for salts shorter than 16 bytes.
    pub fn try_new(bytes: impl Into<Vec<u8>>) -> Result<Self, SaltTooShort> {
        let bytes = bytes.into();
        if bytes.len() < MIN_SALT_LEN {
            return Err(SaltTooShort);
        }
        let a: Arc<[u8]> = Arc::from(bytes.into_boxed_slice());
        Ok(ArcSwapSalt(ArcSwap::from_pointee(a)))
    }

    pub fn set(&self, bytes: impl Into<Vec<u8>>) {
        let a: Arc<[u8]> = Arc::from(bytes.into().into_boxed_slice());
        self.0.store(Arc::new(a));
    }
}
impl SaltProvider for ArcSwapSalt {
    fn current_salt(&self) -> Arc<[u8]> {
        Arc::clone(&self.0.load())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base62_is_printable_and_deterministic() {
        let out = base62(&[0u8; 32]);
        assert!(out.bytes().all(|b| (0x21..=0x7E).contains(&b)));
        assert_eq!(out, base62(&[0u8; 32]));
        // distinct digests encode distinctly
        let mut d = [0u8; 32];
        d[31] = 1;
        assert_ne!(base62(&d), base62(&[0u8; 32]));
    }

    #[test]
    fn base62_uses_full_digest() {
        // a difference in a byte the old 16-byte encoder discarded must change the output
        let mut a = [7u8; 32];
        let mut b = [7u8; 32];
        a[31] = 1;
        b[31] = 2;
        assert_ne!(base62(&a), base62(&b));
    }

    #[test]
    fn framing_is_unambiguous() {
        assert_ne!(frame(&[b"ab", b"cdef"]), frame(&[b"abc", b"def"]));
    }

    #[test]
    fn static_salt_returns_same_bytes() {
        let s = StaticSalt::new(vec![1u8; 16]);
        assert_eq!(&*s.current_salt(), &[1u8; 16]);
    }

    #[test]
    fn try_new_rejects_short_salt() {
        assert!(StaticSalt::try_new(vec![1, 2, 3]).is_err());
        assert!(StaticSalt::try_new(vec![1u8; 16]).is_ok());
        assert!(ArcSwapSalt::try_new(vec![1u8; 15]).is_err());
        assert!(ArcSwapSalt::try_new(vec![1u8; 16]).is_ok());
    }

    #[test]
    fn arc_swap_salt_swaps() {
        let s = ArcSwapSalt::new(vec![1u8; 16]);
        assert_eq!(&*s.current_salt(), &[1u8; 16]);
        s.set(vec![9u8; 20]);
        assert_eq!(&*s.current_salt(), &[9u8; 20]);
    }
}
