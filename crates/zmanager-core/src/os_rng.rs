//! Operating-system randomness for the rand_core 0.10 trait line.
//!
//! rand_core 0.10 ships only the trait core (no `OsRng`), and the ecosystem
//! OS-RNG provider crates have not caught up. This minimal wrapper drives
//! `getrandom` through the `TryRng`/`TryCryptoRng` markers so the RustCrypto
//! 0.14-curve crates and `signature` 3 randomized signers accept it.

use core::convert::Infallible;

/// Operating-system-backed random number generator.
#[derive(Debug, Default)]
pub struct OsRng;

impl rand_core::TryRng for OsRng {
    type Error = Infallible;

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        getrandom::fill(dst).unwrap_or_else(|error| panic!("operating-system randomness is unavailable: {error}"));
        Ok(())
    }

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_ne_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_ne_bytes(bytes))
    }
}

impl rand_core::TryCryptoRng for OsRng {}

#[cfg(test)]
mod tests {
    use super::OsRng;
    use rand_core::TryRng as _;

    #[test]
    fn os_rng_fills_bytes() {
        let mut first = [0u8; 16];
        let mut second = [0u8; 16];
        OsRng.try_fill_bytes(&mut first).unwrap();
        OsRng.try_fill_bytes(&mut second).unwrap();
        assert_ne!(first, second);
    }
}
