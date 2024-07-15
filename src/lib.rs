//! # NIST PQC: RNG for known answer tests
//!
//! This crate provides a seedable RNG that produces outputs compatible with
//! `rng.c` used by submissions to the NIST PQC project to obtain known answer
//! tests from an initial seed.

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

use aes::cipher::{
    generic_array::{
        typenum::{U16, U32, U48},
        GenericArray,
    },
    KeyIvInit, StreamCipher, StreamCipherSeek,
};
use rand_core::{CryptoRng, RngCore, SeedableRng};

type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

/// RNG used to generate known answer test values for NIST PQC competition
///
/// Warning: Do not use this RNG anywhere else. Its only use is to generate the
/// responses for the known answer tests for schemes submitted to the NIST PQC
/// competition.
pub struct NistPqcAes256CtrRng {
    key: GenericArray<u8, U32>,
    v: GenericArray<u8, U16>,
}

impl SeedableRng for NistPqcAes256CtrRng {
    type Seed = GenericArray<u8, U48>;

    fn from_seed(mut seed: Self::Seed) -> Self {
        let mut cipher = Aes256Ctr::new(&[0; 32].into(), &[0; 16].into());
        cipher.seek(16);
        cipher.apply_keystream(&mut seed);

        let key_v = seed.as_slice();
        Self {
            key: *GenericArray::from_slice(&key_v[..32]),
            v: *GenericArray::from_slice(&key_v[32..]),
        }
    }
}

impl RngCore for NistPqcAes256CtrRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut cipher = Aes256Ctr::new(&self.key, &self.v);
        cipher.seek(16);
        cipher.apply_keystream(dest);
        cipher.seek((cipher.current_pos::<usize>() + 15) / 16 * 16);

        let mut key = GenericArray::default();
        let mut v = GenericArray::default();
        cipher.apply_keystream(&mut key);
        cipher.apply_keystream(&mut v);
        self.key = key;
        self.v = v;
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for NistPqcAes256CtrRng {}

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for NistPqcAes256CtrRng {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.v.zeroize();
    }
}

#[cfg(test)]
mod test {
    use aes::cipher::generic_array::GenericArray;
    use rand_core::{RngCore, SeedableRng};

    use crate::NistPqcAes256CtrRng;

    #[test]
    fn test_all_zeros() {
        let mut rng = NistPqcAes256CtrRng::from_seed(GenericArray::default());
        assert_eq!(
            rng.key,
            [
                0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9, 0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb,
                0x73, 0x8b, 0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3,
                0xba, 0xf3, 0x9d, 0x18,
            ]
            .into()
        );
        let mut buf = [0; 8];
        rng.fill_bytes(&mut buf);
        assert_eq!(buf, [0x91, 0x61, 0x8f, 0xe9, 0x9a, 0x8f, 0x94, 0x20]);
        assert_eq!(
            rng.key,
            [
                0x19, 0x07, 0x8a, 0x9d, 0x3c, 0xa6, 0xb2, 0xa0, 0x01, 0xae, 0xc0, 0xb9, 0xe0, 0x7e,
                0x68, 0x0b, 0xaf, 0x44, 0x43, 0x92, 0x2a, 0x11, 0x91, 0x78, 0xfb, 0x81, 0x91, 0xd4,
                0xc9, 0xd0, 0xa5, 0x8f,
            ]
            .into()
        );
        let mut buf = [0; 4];
        rng.fill_bytes(&mut buf);
        assert_eq!(buf, [0xf9, 0xc1, 0x29, 0x94]);
    }

    #[test]
    fn test_all_zeros_2() {
        let mut rng = NistPqcAes256CtrRng::from_seed(GenericArray::default());
        assert_eq!(
            rng.key,
            [
                0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9, 0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb,
                0x73, 0x8b, 0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3,
                0xba, 0xf3, 0x9d, 0x18,
            ]
            .into()
        );
        let mut buf = [0; 16];
        rng.fill_bytes(&mut buf);
        assert_eq!(
            buf,
            [
                0x91, 0x61, 0x8f, 0xe9, 0x9a, 0x8f, 0x94, 0x20, 0x49, 0x7b, 0x24, 0x6f, 0x73, 0x5b,
                0x27, 0xa0
            ]
        );
        assert_eq!(
            rng.key,
            [
                0x19, 0x07, 0x8a, 0x9d, 0x3c, 0xa6, 0xb2, 0xa0, 0x01, 0xae, 0xc0, 0xb9, 0xe0, 0x7e,
                0x68, 0x0b, 0xaf, 0x44, 0x43, 0x92, 0x2a, 0x11, 0x91, 0x78, 0xfb, 0x81, 0x91, 0xd4,
                0xc9, 0xd0, 0xa5, 0x8f,
            ]
            .into()
        );
        let mut buf = [0; 4];
        rng.fill_bytes(&mut buf);
        assert_eq!(buf, [0xf9, 0xc1, 0x29, 0x94]);
    }
}
