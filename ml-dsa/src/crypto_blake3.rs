use crate::module_lattice::encode::ArraySize;
use blake3::{Hasher, OutputReader};
use hybrid_array::Array;

// Heuristics (conservative and general)
const TINY_SQUEEZE_MAX: usize = 128; // tiny requests threshold
const TINY_PREFETCH: usize = 1024; // small cache size (fits L1 nicely)
const PAR_RAYON_BYTES: usize = 128 * 1024;

#[derive(Debug)]
/// Squeeze mode
pub enum SqueezeMode {
    /// Stream directly: reader.fill(out) with no extra buffering
    Direct {
        /// Reader
        reader: OutputReader,
        /// Count of recent tiny squeezes
        tiny_hits: u32,
        /// Small inline cache, allocated lazily
        cache: Option<[u8; TINY_PREFETCH]>,
        /// Read pointer into cache
        off: usize,
        /// Valid bytes in cache
        len: usize,
    },
}

#[derive(Debug)]
/// BLAKE3 hash state
pub enum Blake3State {
    /// Absorbing state
    Absorbing {
        /// Hasher
        hasher: Hasher,
        /// Buffer
        buf: Vec<u8>,
    },
    /// Squeezing state
    Squeezing(SqueezeMode),
}

impl Default for Blake3State {
    fn default() -> Self {
        Blake3State::Absorbing {
            hasher: Hasher::new(),
            buf: Vec::with_capacity(1024),
        }
    }
}

impl Blake3State {
    /// Absorb input into the hash state
    #[must_use]
    pub fn absorb(mut self, input: &[u8]) -> Self {
        match &mut self {
            Blake3State::Absorbing { hasher, buf } => {
                let total = buf.len() + input.len();
                if total >= PAR_RAYON_BYTES {
                    if !buf.is_empty() {
                        hasher.update(buf);
                        buf.clear();
                    }
                    hasher.update_rayon(input);
                } else {
                    if buf.is_empty() && input.len() >= 2 * 1024 {
                        hasher.update(input);
                    } else {
                        buf.extend_from_slice(input);
                    }
                }
            }
            Blake3State::Squeezing(_) => unreachable!("absorb after squeeze"),
        }
        self
    }

    #[inline]
    fn ensure_reader(&mut self) {
        if let Blake3State::Absorbing { hasher, buf } = self {
            if !buf.is_empty() {
                if buf.len() >= PAR_RAYON_BYTES {
                    hasher.update_rayon(buf);
                } else {
                    hasher.update(buf);
                }
                buf.clear();
            }
            let reader = hasher.finalize_xof();
            *self = Blake3State::Squeezing(SqueezeMode::Direct {
                reader,
                tiny_hits: 0,
                cache: None,
                off: 0,
                len: 0,
            });
        }
    }

    #[inline]
    fn tiny_prefetch(
        reader: &mut OutputReader,
        cache: &mut [u8; TINY_PREFETCH],
        off: &mut usize,
        len: &mut usize,
    ) {
        // Refill the tiny cache with up to TINY_PREFETCH bytes
        reader.fill(&mut cache[..]);
        *off = 0;
        *len = TINY_PREFETCH;
    }

    /// Squeeze output from the hash state
    pub fn squeeze(&mut self, out: &mut [u8]) -> &mut Self {
        self.ensure_reader();

        if let Blake3State::Squeezing(SqueezeMode::Direct {
            reader,
            tiny_hits,
            cache,
            off,
            len,
        }) = self
        {
            // Fast path: 1) tiny, 2) general direct fill
            if out.len() <= TINY_SQUEEZE_MAX {
                // If we've seen at least one previous tiny squeeze, enable small cache
                if *tiny_hits > 0 {
                    // allocate small cache lazily
                    if cache.is_none() {
                        *cache = Some([0u8; TINY_PREFETCH]);
                        *off = 0;
                        *len = 0;
                    }

                    let c = cache.as_mut().unwrap();
                    // top up cache if needed
                    if *off + out.len() > *len {
                        Self::tiny_prefetch(reader, c, off, len);
                    }
                    // serve from cache
                    out.copy_from_slice(&c[*off..*off + out.len()]);
                    *off += out.len();
                } else {
                    // First tiny: just fill directly; if we see more, we’ll turn cache on
                    reader.fill(out);
                    *tiny_hits = 1;
                }
                return self;
            }

            // Not a tiny squeeze: just stream directly in one go.
            // This avoids any cache copy cost and is optimal for 4 KiB+ and most mid sizes.
            reader.fill(out);
            // Reset tiny pattern tracking because a large request arrived
            *tiny_hits = 0;
            *off = 0;
            *len = 0;
            // keep cache allocated if it exists; no harm, can be reused
        } else {
            unreachable!();
        }
        self
    }

    #[allow(dead_code)]
    /// Squeeze output from the hash state
    pub fn squeeze_new<N: ArraySize>(&mut self) -> Array<u8, N> {
        let mut v = Array::default();
        self.squeeze(&mut v);
        v
    }
}

#[allow(dead_code)] // removing compiler warnings given feature flags
/// BLAKE3 hash state for G function
pub type G = Blake3State;
#[allow(dead_code)] // removing compiler warnings given feature flags
/// BLAKE3 hash state for H function
pub type H = Blake3State;

#[cfg(test)]
mod test {
    use super::*;
    use crate::util::B32;
    use hex_literal::hex;

    #[test]
    fn g() {
        let input = b"hello world";
        let expected1 = hex!("d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24");
        let expected2 = hex!("a020ed55aed9a6ab2eaf3fd70d2c98c949e142d8f42a10250190b699e02cf9eb");

        let mut g = G::default().absorb(input);

        let mut actual = [0u8; 32];
        g.squeeze(&mut actual);
        assert_eq!(actual, expected1);

        let actual: B32 = g.squeeze_new();
        assert_eq!(actual, expected2);
    }

    #[test]
    fn h() {
        let input = b"hello world";
        let expected1 = hex!("d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24");
        let expected2 = hex!("a020ed55aed9a6ab2eaf3fd70d2c98c949e142d8f42a10250190b699e02cf9eb");

        let mut h = H::default().absorb(input);

        let mut actual = [0u8; 32];
        h.squeeze(&mut actual);
        assert_eq!(actual, expected1);

        let actual: B32 = h.squeeze_new();
        assert_eq!(actual, expected2);
    }
}
