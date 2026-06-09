use super::Hasher;
use sha2::{Digest, Sha256};

/// SHA-256-based hasher (32-byte output).
#[derive(Clone, Copy, Default)]
pub struct Sha256Hasher;

impl Hasher for Sha256Hasher {
    fn hash(&self, bytes: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(bytes);
        h.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Hasher;
    #[test]
    fn produces_32_bytes_deterministically() {
        let h = Sha256Hasher;
        assert_eq!(h.hash(b"abc"), h.hash(b"abc"));
        assert_ne!(h.hash(b"abc"), h.hash(b"abd"));
    }
}
