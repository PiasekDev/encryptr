use num_bigint::BigUint;

use super::bits::{KeyBits, generate_prime};

#[derive(Clone, Debug)]
pub struct RSAKeyPair {
	pub public_key: RSAPublicKey,
	pub private_key: RSAPrivateKey,
}

#[derive(Clone, Debug)]
pub struct RSAPublicKey {
	pub n: BigUint,
	pub e: BigUint,
}

impl RSAPublicKey {
	/// Returns the byte length of the modulus `n`.
	///
	/// This is the number of bytes needed to represent the modulus,
	/// which determines the block size for RSA operations.
	pub fn byte_length(&self) -> usize {
		(self.n.bits() as usize).div_ceil(8)
	}
}

#[derive(Clone, Debug)]
pub struct RSAPrivateKey {
	pub n: BigUint,
	pub d: BigUint,
}

impl RSAPrivateKey {
	/// Returns the byte length of the modulus `n`.
	///
	/// This is the number of bytes needed to represent the modulus,
	/// which determines the block size for RSA operations.
	pub fn byte_length(&self) -> usize {
		(self.n.bits() as usize).div_ceil(8)
	}
}

impl RSAKeyPair {
	pub fn generate(bits: KeyBits, rng: &mut impl rand::Rng) -> Self {
		let (p, q) = generate_pq(bits, rng);

		let n = &p * &q;
		let phi_n = (&p - BigUint::from(1u8)) * (&q - BigUint::from(1u8));
		let e = choose_e(&phi_n);
		let d = e.modinv(&phi_n).expect("e should be coprime to phi_n");

		let public_key = RSAPublicKey { n: n.clone(), e };
		let private_key = RSAPrivateKey { n, d };
		Self {
			public_key,
			private_key,
		}
	}
}

pub fn generate_pq(bits: KeyBits, rng: &mut impl rand::Rng) -> (BigUint, BigUint) {
	let (p_bits, q_bits) = bits.split();

	loop {
		let p = generate_prime(p_bits, rng);
		let q = generate_prime(q_bits, rng);
		if p != q {
			return (p, q);
		}
	}
}

const DEFAULT_PUBLIC_EXPONENT: u64 = 65537;
const FALLBACK_EXPONENTS: [u64; 5] = [3, 5, 17, 257, DEFAULT_PUBLIC_EXPONENT];

fn choose_e(phi_n: &BigUint) -> BigUint {
	let mut e = BigUint::from(DEFAULT_PUBLIC_EXPONENT);

	// Try smaller exponents, since if phi_n <= 65537, e < phi_n in is_valid_public_exponent would never hold
	if phi_n <= &e {
		return FALLBACK_EXPONENTS
			.into_iter()
			.map(BigUint::from)
			.find(|e| is_valid_public_exponent(phi_n, e))
			.expect("phi_n is even for odd primes and cannot be divisible by all of 3, 5, 17, and 257, so a fallback exponent must exist");
	}

	loop {
		if is_valid_public_exponent(phi_n, &e) {
			return e;
		}

		e += BigUint::from(2u8);
	}
}

fn is_valid_public_exponent(phi_n: &BigUint, e: &BigUint) -> bool {
	BigUint::from(1u8) < *e && *e < *phi_n && gcd(e, phi_n) == BigUint::from(1u8)
}

pub fn gcd(a: &BigUint, b: &BigUint) -> BigUint {
	let mut a = a.clone();
	let mut b = b.clone();

	while b != BigUint::ZERO {
		(b, a) = (a % &b, b);
	}

	a
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn choose_e_for_small_phi() {
		let phi_n = BigUint::from(8u8);
		assert_eq!(choose_e(&phi_n), BigUint::from(3u8));
	}

	#[test]
	fn choose_e_for_small_phi_with_non_coprime_first() {
		let phi_n = BigUint::from(12u8);
		assert_eq!(choose_e(&phi_n), BigUint::from(5u8));
	}

	#[test]
	fn choose_e_prefers_default() {
		let phi_n = BigUint::from(65539u64);
		assert_eq!(choose_e(&phi_n), BigUint::from(DEFAULT_PUBLIC_EXPONENT));
	}

	#[test]
	fn byte_length_512_bit_key() {
		// 512 bits = 64 bytes
		let n: BigUint = BigUint::from(1u8) << 511; // 2^511, a 512-bit number
		let public_key = RSAPublicKey {
			n: n.clone(),
			e: BigUint::from(65537u64),
		};
		let private_key = RSAPrivateKey {
			n,
			d: BigUint::from(12345u64),
		};

		assert_eq!(public_key.byte_length(), 64);
		assert_eq!(private_key.byte_length(), 64);
	}

	#[test]
	fn byte_length_small_key() {
		// 8 bits = 1 byte
		let n = BigUint::from(200u8); // 8-bit number
		let public_key = RSAPublicKey {
			n: n.clone(),
			e: BigUint::from(3u64),
		};

		assert_eq!(public_key.byte_length(), 1);
	}

	#[test]
	fn byte_length_non_byte_aligned() {
		// 10 bits = 2 bytes (rounded up)
		let n = BigUint::from(1u16) << 9; // 2^9 = 512, a 10-bit number
		let public_key = RSAPublicKey {
			n,
			e: BigUint::from(3u64),
		};

		assert_eq!(public_key.byte_length(), 2);
	}
}
