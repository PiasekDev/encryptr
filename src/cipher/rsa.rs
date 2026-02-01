use num_bigint::BigUint;
use thiserror::Error;

pub mod bits;
pub mod key;
pub mod state;

use state::{CanDecrypt, CanEncrypt};

/// RSA cipher with compile-time state tracking.
///
/// This type uses the TypeState pattern to enforce correct usage at compile time:
/// - [`RSACipher<PublicOnly>`](state::PublicOnly) can only encrypt
/// - [`RSACipher<PrivateOnly>`](state::PrivateOnly) can only decrypt
/// - [`RSACipher<KeyPair>`](state::KeyPair) can both encrypt and decrypt
///
/// # Examples
///
/// Basic usage with a full key pair:
///
/// ```
/// use encryptr::cipher::rsa::{RSACipher, key::RSAKeyPair, bits::KeyBits};
/// use num_bigint::BigUint;
/// use rand::SeedableRng;
///
/// let bits = KeyBits::try_from(8).unwrap();
/// let mut rng = rand::rngs::StdRng::seed_from_u64(42);
/// let key_pair = RSAKeyPair::generate(bits, &mut rng);
///
/// let cipher = RSACipher::with_key_pair(key_pair);
/// let plaintext = BigUint::from(5u8);
/// let ciphertext = cipher.encipher(&plaintext).unwrap();
/// let decrypted = cipher.decipher(&ciphertext).unwrap();
/// assert_eq!(plaintext, decrypted);
/// ```
///
/// Using only a public key (encryption only):
///
/// ```
/// # use encryptr::cipher::rsa::{RSACipher, key::RSAKeyPair, bits::KeyBits};
/// # use num_bigint::BigUint;
/// # use rand::SeedableRng;
/// # let bits = KeyBits::try_from(8).unwrap();
/// # let mut rng = rand::rngs::StdRng::seed_from_u64(42);
/// # let key_pair = RSAKeyPair::generate(bits, &mut rng);
/// let cipher = RSACipher::with_public_key(key_pair.public_key);
/// let plaintext = BigUint::from(5u8);
/// let ciphertext = cipher.encipher(&plaintext).unwrap();
/// ```
///
/// Attempting to decrypt with only a public key will not compile:
///
/// ```compile_fail
/// # use encryptr::cipher::rsa::{RSACipher, key::RSAKeyPair, bits::KeyBits};
/// # use num_bigint::BigUint;
/// # use rand::SeedableRng;
/// # let bits = KeyBits::try_from(8).unwrap();
/// # let mut rng = rand::rngs::StdRng::seed_from_u64(42);
/// # let key_pair = RSAKeyPair::generate(bits, &mut rng);
/// let cipher = RSACipher::with_public_key(key_pair.public_key);
/// let ciphertext = BigUint::from(42u8);
/// cipher.decipher(&ciphertext).unwrap(); // Error: method not found
/// ```
///
/// Similarly, encrypting with only a private key will not compile:
///
/// ```compile_fail
/// # use encryptr::cipher::rsa::{RSACipher, key::RSAKeyPair, bits::KeyBits};
/// # use num_bigint::BigUint;
/// # use rand::SeedableRng;
/// # let bits = KeyBits::try_from(8).unwrap();
/// # let mut rng = rand::rngs::StdRng::seed_from_u64(42);
/// # let key_pair = RSAKeyPair::generate(bits, &mut rng);
/// let cipher = RSACipher::with_private_key(key_pair.private_key);
/// let plaintext = BigUint::from(5u8);
/// cipher.encipher(&plaintext).unwrap(); // Error: method not found
/// ```
pub struct RSACipher<State> {
	state: State,
}

/// Returned when the input is outside the valid range [0, n).
#[derive(Debug, Error)]
#[error("RSA input too large: {input} >= {modulus} (input must be in range [0, {modulus}))")]
pub struct RSAInputTooLarge {
	pub input: BigUint,
	pub modulus: BigUint,
}

impl<State: CanEncrypt> RSACipher<State> {
	pub fn encipher(&self, plaintext: &BigUint) -> Result<BigUint, RSAInputTooLarge> {
		let public_key = self.state.public_key();
		if plaintext >= &public_key.n {
			return Err(RSAInputTooLarge {
				input: plaintext.clone(),
				modulus: public_key.n.clone(),
			});
		}
		Ok(plaintext.modpow(&public_key.e, &public_key.n))
	}
}

impl<State: CanDecrypt> RSACipher<State> {
	pub fn decipher(&self, ciphertext: &BigUint) -> Result<BigUint, RSAInputTooLarge> {
		let private_key = self.state.private_key();
		if ciphertext >= &private_key.n {
			return Err(RSAInputTooLarge {
				input: ciphertext.clone(),
				modulus: private_key.n.clone(),
			});
		}
		Ok(ciphertext.modpow(&private_key.d, &private_key.n))
	}
}

impl RSACipher<state::PublicOnly> {
	pub fn with_public_key(public_key: key::RSAPublicKey) -> Self {
		Self {
			state: state::PublicOnly(public_key),
		}
	}

	pub fn add_private_key(self, private_key: key::RSAPrivateKey) -> RSACipher<state::KeyPair> {
		RSACipher {
			state: state::KeyPair(key::RSAKeyPair {
				public_key: self.state.0,
				private_key,
			}),
		}
	}
}

impl RSACipher<state::PrivateOnly> {
	pub fn with_private_key(private_key: key::RSAPrivateKey) -> Self {
		Self {
			state: state::PrivateOnly(private_key),
		}
	}

	pub fn add_public_key(self, public_key: key::RSAPublicKey) -> RSACipher<state::KeyPair> {
		RSACipher {
			state: state::KeyPair(key::RSAKeyPair {
				public_key,
				private_key: self.state.0,
			}),
		}
	}
}

impl RSACipher<state::KeyPair> {
	pub fn with_key_pair(key_pair: key::RSAKeyPair) -> Self {
		Self {
			state: state::KeyPair(key_pair),
		}
	}

	pub fn into_public_only(self) -> RSACipher<state::PublicOnly> {
		RSACipher {
			state: state::PublicOnly(self.state.0.public_key),
		}
	}

	pub fn into_private_only(self) -> RSACipher<state::PrivateOnly> {
		RSACipher {
			state: state::PrivateOnly(self.state.0.private_key),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::cipher::rsa::bits::KeyBits;
	use rand::SeedableRng;
	use rand::rngs::StdRng;

	fn key_pair() -> key::RSAKeyPair {
		let bits = KeyBits::try_from(5).unwrap();
		let mut rng = StdRng::seed_from_u64(42);
		key::RSAKeyPair::generate(bits, &mut rng)
	}

	#[test]
	fn encipher_rejects_large_plaintext() {
		let cipher = RSACipher::with_key_pair(key_pair());
		let modulus = cipher.state.0.public_key.n.clone();
		let err = cipher.encipher(&modulus).unwrap_err();
		assert_eq!(err.input, modulus);
		assert_eq!(err.modulus, cipher.state.0.public_key.n);
	}

	#[test]
	fn decipher_rejects_large_ciphertext() {
		let cipher = RSACipher::with_key_pair(key_pair());
		let modulus = cipher.state.0.private_key.n.clone();
		let err = cipher.decipher(&modulus).unwrap_err();
		assert_eq!(err.input, modulus);
		assert_eq!(err.modulus, cipher.state.0.private_key.n);
	}

	#[test]
	fn roundtrip_small_message() {
		let cipher = RSACipher::with_key_pair(key_pair());
		let plaintext = BigUint::from(2u8);
		let ciphertext = cipher.encipher(&plaintext).unwrap();
		let decoded = cipher.decipher(&ciphertext).unwrap();
		assert_eq!(decoded, plaintext);
	}

	#[test]
	fn upgrade_public_to_keypair() {
		let kp = key_pair();
		let public_key = kp.public_key;
		let private_key = kp.private_key;

		let public_cipher = RSACipher::with_public_key(public_key);
		let plaintext = BigUint::from(2u8);
		let ciphertext = public_cipher.encipher(&plaintext).unwrap();

		let full_cipher = public_cipher.add_private_key(private_key);
		let decoded = full_cipher.decipher(&ciphertext).unwrap();
		assert_eq!(decoded, plaintext);
	}

	#[test]
	fn upgrade_private_to_keypair() {
		let kp = key_pair();
		let public_key = kp.public_key;
		let private_key = kp.private_key;

		let private_cipher = RSACipher::with_private_key(private_key);

		let full_cipher = private_cipher.add_public_key(public_key);
		let plaintext = BigUint::from(2u8);
		let ciphertext = full_cipher.encipher(&plaintext).unwrap();
		let decoded = full_cipher.decipher(&ciphertext).unwrap();
		assert_eq!(decoded, plaintext);
	}
}
