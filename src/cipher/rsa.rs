use num_bigint::BigUint;
use thiserror::Error;

pub mod bits;
pub mod key;

pub struct RSACipher {
	pub key_pair: key::RSAKeyPair,
}

/// Returned when the input is outside the valid range [0, n).
#[derive(Debug, Error)]
#[error("RSA input too large: {input} >= {modulus} (input must be in range [0, {modulus}))")]
pub struct RSAInputTooLarge {
	pub input: BigUint,
	pub modulus: BigUint,
}

impl RSACipher {
	pub fn new(key_pair: key::RSAKeyPair) -> Self {
		Self { key_pair }
	}

	pub fn encipher(&self, plaintext: &BigUint) -> Result<BigUint, RSAInputTooLarge> {
		if plaintext >= &self.key_pair.public_key.n {
			return Err(RSAInputTooLarge {
				input: plaintext.clone(),
				modulus: self.key_pair.public_key.n.clone(),
			});
		}
		Ok(plaintext.modpow(&self.key_pair.public_key.e, &self.key_pair.public_key.n))
	}

	pub fn decipher(&self, ciphertext: &BigUint) -> Result<BigUint, RSAInputTooLarge> {
		if ciphertext >= &self.key_pair.private_key.n {
			return Err(RSAInputTooLarge {
				input: ciphertext.clone(),
				modulus: self.key_pair.private_key.n.clone(),
			});
		}
		Ok(ciphertext.modpow(&self.key_pair.private_key.d, &self.key_pair.private_key.n))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::cipher::rsa::bits::KeyBits;
	use rand::rngs::StdRng;
	use rand::SeedableRng;

	fn key_pair() -> key::RSAKeyPair {
		let bits = KeyBits::try_from(5).unwrap();
		let mut rng = StdRng::seed_from_u64(42);
		key::RSAKeyPair::generate(bits, &mut rng)
	}

	#[test]
	fn encipher_rejects_large_plaintext() {
		let cipher = RSACipher::new(key_pair());
		let modulus = cipher.key_pair.public_key.n.clone();
		let err = cipher.encipher(&modulus).unwrap_err();
		assert_eq!(err.input, modulus);
		assert_eq!(err.modulus, cipher.key_pair.public_key.n);
	}

	#[test]
	fn decipher_rejects_large_ciphertext() {
		let cipher = RSACipher::new(key_pair());
		let modulus = cipher.key_pair.private_key.n.clone();
		let err = cipher.decipher(&modulus).unwrap_err();
		assert_eq!(err.input, modulus);
		assert_eq!(err.modulus, cipher.key_pair.private_key.n);
	}

	#[test]
	fn roundtrip_small_message() {
		let cipher = RSACipher::new(key_pair());
		let plaintext = BigUint::from(2u8);
		let ciphertext = cipher.encipher(&plaintext).unwrap();
		let decoded = cipher.decipher(&ciphertext).unwrap();
		assert_eq!(decoded, plaintext);
	}
}
