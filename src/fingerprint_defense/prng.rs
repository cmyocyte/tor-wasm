//! Session-seeded deterministic PRNG for fingerprint defense.
//!
//! Generates consistent noise within a session but different noise
//! across sessions. Prevents fingerprinters from averaging out the
//! perturbation across multiple reads.

use std::cell::Cell;

thread_local! {
    static SESSION_SEED: Cell<Option<u32>> = const { Cell::new(None) };
}

/// Session-scoped pseudo-random number generator.
pub struct SessionPrng;

impl SessionPrng {
    /// Get or initialize the session seed.
    /// Uses `getrandom` (backed by crypto.getRandomValues in WASM).
    pub fn seed() -> u32 {
        SESSION_SEED.with(|s| {
            if let Some(seed) = s.get() {
                return seed;
            }
            let mut bytes = [0u8; 4];
            getrandom::getrandom(&mut bytes).expect("getrandom failed");
            let seed = u32::from_le_bytes(bytes);
            s.set(Some(seed));
            seed
        })
    }

    /// Deterministic hash mixing (murmurhash-style).
    /// Exact port of the JS `seededRandom(seed, index)`.
    #[inline]
    pub fn seeded_random(seed: u32, index: u32) -> u32 {
        let mut h = seed ^ index;
        h = (h ^ (h >> 16)).wrapping_mul(0x45d9f3b);
        h = (h ^ (h >> 13)).wrapping_mul(0x45d9f3b);
        h ^ (h >> 16)
    }

    /// Returns -1, 0, or 1 for pixel perturbation.
    #[inline]
    pub fn seeded_noise(index: u32) -> i32 {
        (Self::seeded_random(Self::seed(), index) % 3) as i32 - 1
    }

    /// Check if a pixel should be perturbed (~5% rate).
    /// Returns true if the pixel at `index` should be modified.
    #[inline]
    pub fn should_perturb(seed: u32, pixel_index: u32) -> bool {
        (Self::seeded_random(seed, pixel_index) & 0x1F) == 0
    }

    /// Get the perturbation channel (0=R, 1=G, 2=B) for a pixel.
    #[inline]
    pub fn perturb_channel(seed: u32, pixel_index: u32) -> u32 {
        Self::seeded_random(seed, pixel_index.wrapping_add(0x100000)) % 3
    }

    /// Get the perturbation delta (+1 or -1) for a pixel.
    #[inline]
    pub fn perturb_delta(seed: u32, pixel_index: u32) -> i32 {
        if Self::seeded_random(seed, pixel_index.wrapping_add(0x200000)) & 1 == 1 {
            1
        } else {
            -1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_determinism() {
        let a = SessionPrng::seeded_random(42, 0);
        let b = SessionPrng::seeded_random(42, 0);
        assert_eq!(a, b);
    }

    #[test]
    fn test_different_indices() {
        let a = SessionPrng::seeded_random(42, 0);
        let b = SessionPrng::seeded_random(42, 1);
        assert_ne!(a, b);
    }

    #[test]
    fn test_noise_range() {
        for i in 0..1000 {
            let n = SessionPrng::seeded_random(12345, i) % 3;
            assert!(n <= 2);
        }
    }

    #[test]
    fn test_perturbation_rate() {
        let seed = 42;
        let mut count = 0;
        for i in 0..10000 {
            if SessionPrng::should_perturb(seed, i) {
                count += 1;
            }
        }
        // ~5% = ~500 out of 10000, allow ±150
        assert!(count > 200 && count < 800, "perturbation rate: {}/10000", count);
    }
}
