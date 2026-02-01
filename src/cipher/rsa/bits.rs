use num_bigint::{BigUint, RandomBits};
use rand::prelude::Distribution;
use thiserror::Error;

/// Minimum prime size in bits.
/// This is 2 bits because both 1-bit values (0 and 1) are not prime.
const MIN_PRIME_BITS: u64 = 2;

/// Minimum key size in bits.
/// This is 5 bits because key generation splits the size into two primes, and at 4 bits, which yield 2+2, this allows only 3 as a prime
/// (because prime generation sets both the first and second bit), so p != q cannot hold.
const MIN_KEY_BITS: u64 = MIN_PRIME_BITS * 2 + 1;

#[derive(Debug, Error)]
#[error("key size must be at least {MIN_KEY_BITS} bits")]
pub struct KeyBitsError;

#[derive(Debug, Error)]
#[error("prime size must be at least {MIN_PRIME_BITS} bits")]
pub struct PrimeBitsError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyBits(u64);

impl KeyBits {
	pub const MIN: u64 = MIN_KEY_BITS;

	pub fn get(self) -> u64 {
		self.0
	}

	pub(crate) fn split(self) -> (PrimeBits, PrimeBits) {
		let p_bits = self.0 / 2;
		let q_bits = self.0 - p_bits;
		debug_assert!(p_bits >= PrimeBits::MIN && q_bits >= PrimeBits::MIN);
		(PrimeBits(p_bits), PrimeBits(q_bits))
	}
}

impl TryFrom<u64> for KeyBits {
	type Error = KeyBitsError;

	fn try_from(bits: u64) -> Result<Self, Self::Error> {
		if bits < Self::MIN {
			return Err(KeyBitsError);
		}
		Ok(Self(bits))
	}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrimeBits(u64);

impl PrimeBits {
	pub const MIN: u64 = MIN_PRIME_BITS;

	pub fn get(self) -> u64 {
		self.0
	}
}

impl TryFrom<u64> for PrimeBits {
	type Error = PrimeBitsError;

	fn try_from(bits: u64) -> Result<Self, Self::Error> {
		if bits < Self::MIN {
			return Err(PrimeBitsError);
		}
		Ok(Self(bits))
	}
}

pub(crate) fn generate_prime(bits: PrimeBits, rng: &mut impl rand::Rng) -> BigUint {
	let bits = bits.get();
	loop {
		let mut candidate: BigUint = RandomBits::new(bits).sample(rng);
		// Even candidates cannot be prime
		candidate.set_bit(0, true);

		// Force set the highest bit to ensure the number has the desired bit length (the random generator might set the highest bits to zero)
		candidate.set_bit(bits - 1, true);

		if miller_rabin::is_prime(&candidate, 40) {
			return candidate;
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use rand::rngs::StdRng;
	use rand::SeedableRng;

	#[test]
	fn key_bits_minimum() {
		assert!(KeyBits::try_from(KeyBits::MIN - 1).is_err());
		assert!(KeyBits::try_from(KeyBits::MIN).is_ok());
	}

	#[test]
	fn prime_bits_minimum() {
		assert!(PrimeBits::try_from(PrimeBits::MIN - 1).is_err());
		assert!(PrimeBits::try_from(PrimeBits::MIN).is_ok());
	}

	#[test]
	fn generate_prime_min_bits() {
		let bits = PrimeBits::try_from(PrimeBits::MIN).unwrap();
		let mut rng = StdRng::seed_from_u64(1);
		let prime = generate_prime(bits, &mut rng);
		assert_eq!(prime, BigUint::from(3u8));
	}
}
