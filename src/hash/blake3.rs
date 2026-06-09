use super::Hasher;

/// BLAKE3-based hasher (32-byte output).
#[derive(Clone, Copy, Default)]
pub struct Blake3Hasher;

impl Hasher for Blake3Hasher {
    fn hash(&self, bytes: &[u8]) -> [u8; 32] {
        *::blake3::hash(bytes).as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Hasher;
    #[test]
    fn produces_32_bytes_deterministically() {
        let h = Blake3Hasher;
        assert_eq!(h.hash(b"abc"), h.hash(b"abc"));
        assert_ne!(h.hash(b"abc"), h.hash(b"abd"));
    }
}
