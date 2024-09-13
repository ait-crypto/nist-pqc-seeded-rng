#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

//! ## Usage
//!
//! The RNG can be instantiated from a 48 byte seed using various options:
//! first with [SeedableRng::from_seed] as defined in the interface of seedable
//! API. To avoid the user to handle the conversion to [GenericArray] which is
//! used to represent a seed, convenience implementations of [From] for a `u8`
//! array with 48 elements as well as [TryFrom] for a `[u8]` slice is provided.
//!
//! The following three examples are functionally equivalent. Let us start with
//! initializing from [Seed]:
//! ```
//! use nist_pqc_seeded_rng::{NistPqcAes256CtrRng, Seed, SeedableRng};
//!
//! let seed: Seed = (*b"012345678901234567890123456789012345678901234567").into();
//! let rng = NistPqcAes256CtrRng::from_seed(seed);
//! ```
//!
//! Using a `u8` array:
//! ```
//! use nist_pqc_seeded_rng::{NistPqcAes256CtrRng, Seed, SeedableRng};
//!
//! let seed: [u8; 48] = *b"012345678901234567890123456789012345678901234567";
//! let rng = NistPqcAes256CtrRng::from(seed);
//! ```
//!
//! Using a slice:
//! ```
//! use nist_pqc_seeded_rng::{NistPqcAes256CtrRng, Seed, SeedableRng};
//!
//! let seed = b"012345678901234567890123456789012345678901234567".as_slice();
//! let rng = NistPqcAes256CtrRng::try_from(seed).expect("seed of invalid length");
//! ```

use core::{ops::Index, slice::SliceIndex};

use aes::cipher::{generic_array::GenericArray, KeyIvInit, StreamCipher, StreamCipherSeek};
pub use rand_core::{CryptoRng, RngCore, SeedableRng};

type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

const KEY_LENGTH: usize = 32;
const V_LENGTH: usize = 16;
const SEED_LENGTH: usize = KEY_LENGTH + V_LENGTH;

/// Represents a seed which consists of 48 bytes.
#[derive(Debug)]
#[cfg_attr(feature = "zeroize", derive(zeroize::ZeroizeOnDrop))]
pub struct Seed([u8; SEED_LENGTH]);

impl Default for Seed {
    fn default() -> Self {
        Self([0u8; SEED_LENGTH])
    }
}

impl AsRef<[u8]> for Seed {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Seed {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl<Idx> Index<Idx> for Seed
where
    Idx: SliceIndex<[u8]>,
{
    type Output = Idx::Output;

    fn index(&self, index: Idx) -> &Self::Output {
        &self.0[index]
    }
}

impl From<[u8; SEED_LENGTH]> for Seed {
    fn from(value: [u8; SEED_LENGTH]) -> Self {
        Self(value)
    }
}

impl TryFrom<&[u8]> for Seed {
    type Error = ();

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() == SEED_LENGTH {
            let mut buf = [0; SEED_LENGTH];
            buf.copy_from_slice(value);
            Ok(Self(buf))
        } else {
            Err(())
        }
    }
}

/// RNG used to generate known answer test values for NIST PQC competition
///
/// Warning: Do not use this RNG anywhere else. Its only use is to generate the
/// responses for the known answer tests for schemes submitted to the NIST PQC
/// competition.
#[derive(Debug)]
#[cfg_attr(feature = "zeroize", derive(zeroize::ZeroizeOnDrop))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NistPqcAes256CtrRng {
    key: [u8; KEY_LENGTH],
    v: [u8; V_LENGTH],
}

impl SeedableRng for NistPqcAes256CtrRng {
    type Seed = Seed;

    fn from_seed(mut seed: Self::Seed) -> Self {
        let mut cipher = Aes256Ctr::new(&GenericArray::default(), &GenericArray::default());
        cipher.seek(16);
        cipher.apply_keystream(seed.as_mut());

        let mut key = [0; KEY_LENGTH];
        let mut v = [0; V_LENGTH];
        key.copy_from_slice(&seed[..KEY_LENGTH]);
        v.copy_from_slice(&seed[KEY_LENGTH..]);
        Self { key, v }
    }
}

impl From<[u8; SEED_LENGTH]> for NistPqcAes256CtrRng {
    fn from(value: [u8; SEED_LENGTH]) -> Self {
        Self::from_seed(value.into())
    }
}

impl From<&[u8; SEED_LENGTH]> for NistPqcAes256CtrRng {
    fn from(value: &[u8; SEED_LENGTH]) -> Self {
        Self::from(*value)
    }
}

impl TryFrom<&[u8]> for NistPqcAes256CtrRng {
    type Error = ();

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Seed::try_from(value).map(Self::from_seed)
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
        let mut cipher = Aes256Ctr::new(
            GenericArray::from_slice(&self.key),
            GenericArray::from_slice(&self.v),
        );
        cipher.seek(16);
        cipher.apply_keystream(dest);
        cipher.seek((cipher.current_pos::<usize>() + (V_LENGTH - 1)) / V_LENGTH * V_LENGTH);

        let mut key = [0; KEY_LENGTH];
        let mut v = [0; V_LENGTH];
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

#[cfg(test)]
mod test {
    use rand_core::{RngCore, SeedableRng};

    use super::*;

    #[test]
    fn test_all_zeros() {
        let mut rng = NistPqcAes256CtrRng::from_seed(Seed::default());
        assert_eq!(
            rng.key,
            [
                0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9, 0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb,
                0x73, 0x8b, 0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3,
                0xba, 0xf3, 0x9d, 0x18,
            ]
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
        );
        let mut buf = [0; 4];
        rng.fill_bytes(&mut buf);
        assert_eq!(buf, [0xf9, 0xc1, 0x29, 0x94]);
    }

    #[test]
    fn test_all_zeros_2() {
        let mut rng = NistPqcAes256CtrRng::from_seed(Seed::default());
        assert_eq!(
            rng.key,
            [
                0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9, 0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb,
                0x73, 0x8b, 0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3,
                0xba, 0xf3, 0x9d, 0x18,
            ]
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
        );
        let mut buf = [0; 4];
        rng.fill_bytes(&mut buf);
        assert_eq!(buf, [0xf9, 0xc1, 0x29, 0x94]);
    }

    #[test]
    fn from() {
        let mut rng = NistPqcAes256CtrRng::from_seed(Seed::default());
        let mut seed = [0; SEED_LENGTH];
        rng.fill_bytes(&mut seed);

        let rng = NistPqcAes256CtrRng::from_seed(seed.into());
        let rng_1 = NistPqcAes256CtrRng::from(seed);
        let rng_2 = NistPqcAes256CtrRng::try_from(seed.as_slice()).expect("seed of invalid length");

        assert_eq!(rng.key, rng_1.key);
        assert_eq!(rng.key, rng_2.key);
        assert_eq!(rng.v, rng_1.v);
        assert_eq!(rng.v, rng_2.v);
    }
}
