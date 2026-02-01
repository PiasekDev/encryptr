use num_bigint::BigUint;
use thiserror::Error;

pub mod bits;
pub mod key;
pub mod padding;
pub mod serialization;
pub mod state;

use padding::biguint_to_bytes_exact;
pub use padding::{ByteEncryptionPadding, NoPadding, PKCS1v15, PaddingError, RSAPadding};
use state::{CanDecrypt, CanEncrypt};

pub use der::pem::LineEnding;
pub use der::{Decode, Encode};

/// Returned when the input is outside the valid range [0, n).
#[derive(Debug, Error)]
#[error("RSA input too large: {input} >= {modulus} (input must be in range [0, {modulus}))")]
pub struct RSAInputTooLarge {
	pub input: BigUint,
	pub modulus: BigUint,
}

/// Errors from byte-level RSA operations.
#[derive(Debug, Error)]
pub enum RSAError {
	#[error(transparent)]
	InputTooLarge(#[from] RSAInputTooLarge),

	#[error(transparent)]
	Padding(#[from] PaddingError),

	#[error("invalid ciphertext length: expected multiple of {expected} bytes, got {actual}")]
	InvalidCiphertextLength { expected: usize, actual: usize },
}

/// RSA cipher with compile-time state and padding tracking.
///
/// # Type Parameters
///
/// - `State`: The key state ([`PublicOnly`](state::PublicOnly),
///   [`PrivateOnly`](state::PrivateOnly), or [`KeyPair`](state::KeyPair))
/// - `Padding`: The padding scheme (default: [`NoPadding`])
///
/// # BigUint API vs Byte API
///
/// The cipher provides two levels of API:
///
/// 1. **BigUint API** (`encipher`/`decipher`): Works with raw `BigUint` values.
///    Available with any padding scheme.
///
/// 2. **Byte API** (`encrypt`/`decrypt`): Works with `&[u8]` and `Vec<u8>`.
///    Only available with padding schemes that implement [`ByteEncryptionPadding`]
///    (currently only [`PKCS1v15`]).
///
/// # Examples
///
/// ## BigUint API with NoPadding (default)
///
/// ```
/// use encryptr::cipher::rsa::{RSACipher, key::RSAKeyPair, bits::KeyBits};
/// use num_bigint::BigUint;
/// use rand::SeedableRng;
///
/// let bits = KeyBits::try_from(64).unwrap();
/// let mut rng = rand::rngs::StdRng::seed_from_u64(42);
/// let key_pair = RSAKeyPair::generate(bits, &mut rng);
///
/// let cipher = RSACipher::with_key_pair(key_pair);
/// let plaintext = BigUint::from(42u64);
/// let ciphertext = cipher.encipher(&plaintext).unwrap();
/// let decrypted = cipher.decipher(&ciphertext).unwrap();
/// assert_eq!(plaintext, decrypted);
/// ```
///
/// ## Byte API with PKCS#1 v1.5 padding
///
/// ```
/// use encryptr::cipher::rsa::{RSACipher, PKCS1v15, key::RSAKeyPair, bits::KeyBits};
/// use rand::SeedableRng;
///
/// let bits = KeyBits::try_from(512).unwrap();
/// let mut rng = rand::rngs::StdRng::seed_from_u64(42);
/// let key_pair = RSAKeyPair::generate(bits, &mut rng);
///
/// let padding = PKCS1v15::new(rand::rngs::StdRng::seed_from_u64(123));
/// let mut cipher = RSACipher::with_key_pair_and_padding(key_pair, padding);
///
/// let message = b"Hello, RSA!";
/// let ciphertext = cipher.encrypt(message).unwrap();
/// let plaintext = cipher.decrypt(&ciphertext).unwrap();
/// assert_eq!(plaintext, message);
/// ```
pub struct RSACipher<State, Padding: RSAPadding = NoPadding> {
	state: State,
	padding: Padding,
}

impl RSACipher<state::PublicOnly, NoPadding> {
	/// Create a cipher with only a public key (encryption only).
	///
	/// Uses [`NoPadding`] by default. For byte-level encryption, use
	/// [`with_public_key_and_padding`](Self::with_public_key_and_padding) with [`PKCS1v15`].
	pub fn with_public_key(public_key: key::RSAPublicKey) -> Self {
		Self {
			state: state::PublicOnly(public_key),
			padding: NoPadding,
		}
	}
}

impl RSACipher<state::PrivateOnly, NoPadding> {
	/// Create a cipher with only a private key (decryption only).
	///
	/// Uses [`NoPadding`] by default. For byte-level decryption, use
	/// [`with_private_key_and_padding`](Self::with_private_key_and_padding) with [`PKCS1v15`].
	pub fn with_private_key(private_key: key::RSAPrivateKey) -> Self {
		Self {
			state: state::PrivateOnly(private_key),
			padding: NoPadding,
		}
	}
}

impl RSACipher<state::KeyPair, NoPadding> {
	/// Create a cipher with a full key pair.
	///
	/// Uses [`NoPadding`] by default. For byte-level encryption, use
	/// [`with_key_pair_and_padding`](Self::with_key_pair_and_padding) with [`PKCS1v15`].
	pub fn with_key_pair(key_pair: key::RSAKeyPair) -> Self {
		Self {
			state: state::KeyPair(key_pair),
			padding: NoPadding,
		}
	}
}

impl<P: RSAPadding> RSACipher<state::PublicOnly, P> {
	pub fn with_public_key_and_padding(public_key: key::RSAPublicKey, padding: P) -> Self {
		Self {
			state: state::PublicOnly(public_key),
			padding,
		}
	}
}

impl<P: RSAPadding> RSACipher<state::PrivateOnly, P> {
	pub fn with_private_key_and_padding(private_key: key::RSAPrivateKey, padding: P) -> Self {
		Self {
			state: state::PrivateOnly(private_key),
			padding,
		}
	}
}

impl<P: RSAPadding> RSACipher<state::KeyPair, P> {
	pub fn with_key_pair_and_padding(key_pair: key::RSAKeyPair, padding: P) -> Self {
		Self {
			state: state::KeyPair(key_pair),
			padding,
		}
	}
}

impl<P: RSAPadding> RSACipher<state::PublicOnly, P> {
	pub fn add_private_key(self, private_key: key::RSAPrivateKey) -> RSACipher<state::KeyPair, P> {
		RSACipher {
			state: state::KeyPair(key::RSAKeyPair {
				public_key: self.state.0,
				private_key,
			}),
			padding: self.padding,
		}
	}
}

impl<P: RSAPadding> RSACipher<state::PrivateOnly, P> {
	pub fn add_public_key(self, public_key: key::RSAPublicKey) -> RSACipher<state::KeyPair, P> {
		RSACipher {
			state: state::KeyPair(key::RSAKeyPair {
				public_key,
				private_key: self.state.0,
			}),
			padding: self.padding,
		}
	}
}

impl<P: RSAPadding> RSACipher<state::KeyPair, P> {
	pub fn into_public_only(self) -> RSACipher<state::PublicOnly, P> {
		RSACipher {
			state: state::PublicOnly(self.state.0.public_key),
			padding: self.padding,
		}
	}

	pub fn into_private_only(self) -> RSACipher<state::PrivateOnly, P> {
		RSACipher {
			state: state::PrivateOnly(self.state.0.private_key),
			padding: self.padding,
		}
	}
}

impl<State: CanEncrypt, P: RSAPadding> RSACipher<State, P> {
	/// Encrypt a `BigUint` value using raw RSA.
	///
	/// This is the low-level API that works directly with `BigUint` values.
	/// The plaintext must be in the range `[0, n)`.
	///
	/// For byte-level encryption with padding, use [`encrypt`](Self::encrypt)
	/// (requires [`PKCS1v15`] padding).
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

impl<State: CanDecrypt, P: RSAPadding> RSACipher<State, P> {
	/// Decrypt a `BigUint` ciphertext using raw RSA.
	///
	/// This is the low-level API that works directly with `BigUint` values.
	/// The ciphertext must be in the range `[0, n)`.
	///
	/// For byte-level decryption with padding, use [`decrypt`](Self::decrypt)
	/// (requires [`PKCS1v15`] padding).
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

impl<State: CanEncrypt, P: ByteEncryptionPadding> RSACipher<State, P> {
	/// Encrypt bytes using RSA with the configured padding scheme.
	///
	/// For messages longer than [`max_message_len`](Self::max_message_len),
	/// the message is automatically split into blocks and each block is
	/// encrypted separately. The ciphertext blocks are concatenated.
	pub fn encrypt(&mut self, message: &[u8]) -> Result<Vec<u8>, RSAError> {
		let key_bytes = self.state.public_key().byte_length();
		let max_len = P::max_message_len(key_bytes);

		if max_len == 0 {
			return Err(RSAError::Padding(PaddingError::KeyTooSmall));
		}

		if message.len() <= max_len {
			self.encrypt_block(message)
		} else {
			let num_blocks = message.len().div_ceil(max_len);
			let mut result = Vec::with_capacity(num_blocks * key_bytes);

			for chunk in message.chunks(max_len) {
				result.extend(self.encrypt_block(chunk)?);
			}

			Ok(result)
		}
	}

	fn encrypt_block(&mut self, block: &[u8]) -> Result<Vec<u8>, RSAError> {
		let public_key = self.state.public_key();
		let key_bytes = public_key.byte_length();

		let padded = self.padding.pad(block, key_bytes)?;

		if padded >= public_key.n {
			return Err(RSAError::InputTooLarge(RSAInputTooLarge {
				input: padded,
				modulus: public_key.n.clone(),
			}));
		}

		let ciphertext = padded.modpow(&public_key.e, &public_key.n);

		Ok(biguint_to_bytes_exact(&ciphertext, key_bytes))
	}

	/// Returns the maximum message length for single-block encryption.
	pub fn max_message_len(&self) -> usize {
		P::max_message_len(self.state.public_key().byte_length())
	}
}

impl<State: CanDecrypt, P: ByteEncryptionPadding> RSACipher<State, P> {
	/// Decrypt bytes using RSA with the configured padding scheme.
	///
	/// The ciphertext must be a multiple of the key byte length.
	/// For multi-block ciphertext, each block is decrypted separately
	/// and the plaintext blocks are concatenated.
	pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, RSAError> {
		let key_bytes = self.state.private_key().byte_length();

		if ciphertext.is_empty() {
			return Err(RSAError::InvalidCiphertextLength {
				expected: key_bytes,
				actual: 0,
			});
		}

		if !ciphertext.len().is_multiple_of(key_bytes) {
			return Err(RSAError::InvalidCiphertextLength {
				expected: key_bytes,
				actual: ciphertext.len(),
			});
		}

		let mut result = Vec::new();

		for chunk in ciphertext.chunks(key_bytes) {
			result.extend(self.decrypt_block(chunk)?);
		}

		Ok(result)
	}

	fn decrypt_block(&self, block: &[u8]) -> Result<Vec<u8>, RSAError> {
		let private_key = self.state.private_key();
		let key_bytes = private_key.byte_length();

		let c = BigUint::from_bytes_be(block);
		let plaintext = c.modpow(&private_key.d, &private_key.n);
		let message = P::unpad(&plaintext, key_bytes)?;

		Ok(message)
	}
}

impl<State, P: RSAPadding> RSACipher<State, P> {
	pub fn padding(&self) -> &P {
		&self.padding
	}

	pub fn padding_mut(&mut self) -> &mut P {
		&mut self.padding
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::cipher::rsa::bits::KeyBits;
	use rand::SeedableRng;
	use rand::rngs::StdRng;

	fn key_pair_small() -> key::RSAKeyPair {
		let bits = KeyBits::try_from(64).unwrap();
		let mut rng = StdRng::seed_from_u64(42);
		key::RSAKeyPair::generate(bits, &mut rng)
	}

	fn key_pair_512() -> key::RSAKeyPair {
		let bits = KeyBits::try_from(512).unwrap();
		let mut rng = StdRng::seed_from_u64(42);
		key::RSAKeyPair::generate(bits, &mut rng)
	}

	#[test]
	fn encipher_rejects_large_plaintext() {
		let cipher = RSACipher::with_key_pair(key_pair_small());
		let modulus = cipher.state.0.public_key.n.clone();
		let err = cipher.encipher(&modulus).unwrap_err();
		assert_eq!(err.input, modulus);
		assert_eq!(err.modulus, cipher.state.0.public_key.n);
	}

	#[test]
	fn decipher_rejects_large_ciphertext() {
		let cipher = RSACipher::with_key_pair(key_pair_small());
		let modulus = cipher.state.0.private_key.n.clone();
		let err = cipher.decipher(&modulus).unwrap_err();
		assert_eq!(err.input, modulus);
		assert_eq!(err.modulus, cipher.state.0.private_key.n);
	}

	#[test]
	fn roundtrip_biguint() {
		let cipher = RSACipher::with_key_pair(key_pair_small());
		let plaintext = BigUint::from(42u64);
		let ciphertext = cipher.encipher(&plaintext).unwrap();
		let decoded = cipher.decipher(&ciphertext).unwrap();
		assert_eq!(decoded, plaintext);
	}

	#[test]
	fn upgrade_public_to_keypair() {
		let kp = key_pair_small();
		let public_key = kp.public_key;
		let private_key = kp.private_key;

		let public_cipher = RSACipher::with_public_key(public_key);
		let plaintext = BigUint::from(42u64);
		let ciphertext = public_cipher.encipher(&plaintext).unwrap();

		let full_cipher = public_cipher.add_private_key(private_key);
		let decoded = full_cipher.decipher(&ciphertext).unwrap();
		assert_eq!(decoded, plaintext);
	}

	#[test]
	fn upgrade_private_to_keypair() {
		let kp = key_pair_small();
		let public_key = kp.public_key;
		let private_key = kp.private_key;

		let private_cipher = RSACipher::with_private_key(private_key);

		let full_cipher = private_cipher.add_public_key(public_key);
		let plaintext = BigUint::from(42u64);
		let ciphertext = full_cipher.encipher(&plaintext).unwrap();
		let decoded = full_cipher.decipher(&ciphertext).unwrap();
		assert_eq!(decoded, plaintext);
	}

	#[test]
	fn encrypt_decrypt_single_block() {
		let key_pair = key_pair_512();
		let padding = PKCS1v15::new(StdRng::seed_from_u64(123));
		let mut cipher = RSACipher::with_key_pair_and_padding(key_pair, padding);

		let message = b"Hello, RSA with PKCS#1 v1.5!";
		let ciphertext = cipher.encrypt(message).unwrap();
		let plaintext = cipher.decrypt(&ciphertext).unwrap();

		assert_eq!(plaintext, message);
	}

	#[test]
	fn encrypt_decrypt_empty_message() {
		let key_pair = key_pair_512();
		let padding = PKCS1v15::new(StdRng::seed_from_u64(123));
		let mut cipher = RSACipher::with_key_pair_and_padding(key_pair, padding);

		let message = b"";
		let ciphertext = cipher.encrypt(message).unwrap();
		let plaintext = cipher.decrypt(&ciphertext).unwrap();

		assert_eq!(plaintext, message);
	}

	#[test]
	fn encrypt_decrypt_max_length_message() {
		let key_pair = key_pair_512();
		let padding = PKCS1v15::new(StdRng::seed_from_u64(123));
		let mut cipher = RSACipher::with_key_pair_and_padding(key_pair, padding);

		let max_len = cipher.max_message_len();
		let message = vec![0x42u8; max_len];

		let ciphertext = cipher.encrypt(&message).unwrap();
		let plaintext = cipher.decrypt(&ciphertext).unwrap();

		assert_eq!(plaintext, message);
	}

	#[test]
	fn encrypt_decrypt_multi_block() {
		let key_pair = key_pair_512();
		let padding = PKCS1v15::new(StdRng::seed_from_u64(123));
		let mut cipher = RSACipher::with_key_pair_and_padding(key_pair, padding);

		let max_len = cipher.max_message_len();
		// Create a message that spans 3 blocks
		let message = vec![0x42u8; max_len * 2 + 10];

		let ciphertext = cipher.encrypt(&message).unwrap();

		// Ciphertext should be 3 blocks
		let key_bytes = 64; // 512 bits
		assert_eq!(ciphertext.len(), key_bytes * 3);

		let plaintext = cipher.decrypt(&ciphertext).unwrap();
		assert_eq!(plaintext, message);
	}

	#[test]
	fn encrypt_decrypt_preserves_leading_zeros() {
		let key_pair = key_pair_512();
		let padding = PKCS1v15::new(StdRng::seed_from_u64(123));
		let mut cipher = RSACipher::with_key_pair_and_padding(key_pair, padding);

		// Message with leading zeros
		let message = &[0x00, 0x00, 0x42, 0x43, 0x00, 0x00];
		let ciphertext = cipher.encrypt(message).unwrap();
		let plaintext = cipher.decrypt(&ciphertext).unwrap();

		assert_eq!(plaintext.as_slice(), message);
	}

	#[test]
	fn ciphertext_has_fixed_length() {
		let key_pair = key_pair_512();
		let padding = PKCS1v15::new(StdRng::seed_from_u64(123));
		let mut cipher = RSACipher::with_key_pair_and_padding(key_pair, padding);

		// Short message
		let message = b"Hi";
		let ciphertext = cipher.encrypt(message).unwrap();

		// Ciphertext should always be key_bytes long for single block
		assert_eq!(ciphertext.len(), 64); // 512 bits = 64 bytes
	}

	#[test]
	fn decrypt_invalid_ciphertext_length() {
		let key_pair = key_pair_512();
		let padding = PKCS1v15::new(StdRng::seed_from_u64(123));
		let cipher = RSACipher::with_key_pair_and_padding(key_pair, padding);

		// Ciphertext with wrong length (not multiple of key_bytes)
		let ciphertext = vec![0x42u8; 65]; // 65 is not a multiple of 64
		let result = cipher.decrypt(&ciphertext);

		assert!(matches!(
			result,
			Err(RSAError::InvalidCiphertextLength {
				expected: 64,
				actual: 65
			})
		));
	}

	#[test]
	fn decrypt_empty_ciphertext() {
		let key_pair = key_pair_512();
		let padding = PKCS1v15::new(StdRng::seed_from_u64(123));
		let cipher = RSACipher::with_key_pair_and_padding(key_pair, padding);

		let result = cipher.decrypt(&[]);

		assert!(matches!(
			result,
			Err(RSAError::InvalidCiphertextLength {
				expected: 64,
				actual: 0
			})
		));
	}

	#[test]
	fn different_padding_produces_different_ciphertext() {
		let key_pair = key_pair_512();

		let padding1 = PKCS1v15::new(StdRng::seed_from_u64(1));
		let mut cipher1 = RSACipher::with_key_pair_and_padding(key_pair.clone(), padding1);

		let padding2 = PKCS1v15::new(StdRng::seed_from_u64(2));
		let mut cipher2 = RSACipher::with_key_pair_and_padding(key_pair, padding2);

		let message = b"Same message";

		let ciphertext1 = cipher1.encrypt(message).unwrap();
		let ciphertext2 = cipher2.encrypt(message).unwrap();

		// Different random padding should produce different ciphertext
		assert_ne!(ciphertext1, ciphertext2);

		// But both should decrypt to the same message
		let plaintext1 = cipher1.decrypt(&ciphertext1).unwrap();
		let plaintext2 = cipher2.decrypt(&ciphertext2).unwrap();
		assert_eq!(plaintext1, message);
		assert_eq!(plaintext2, message);
	}

	#[test]
	fn state_transition_preserves_padding() {
		let kp = key_pair_512();
		let public_key = kp.public_key;
		let private_key = kp.private_key;

		let padding = PKCS1v15::new(StdRng::seed_from_u64(123));
		let mut public_cipher = RSACipher::with_public_key_and_padding(public_key.clone(), padding);

		let message = b"Test message";
		let ciphertext = public_cipher.encrypt(message).unwrap();

		// Add private key (padding is preserved)
		let full_cipher = public_cipher.add_private_key(private_key);
		let plaintext = full_cipher.decrypt(&ciphertext).unwrap();

		assert_eq!(plaintext, message);
	}

	#[test]
	fn into_public_only_preserves_padding() {
		let key_pair = key_pair_512();
		let padding = PKCS1v15::new(StdRng::seed_from_u64(123));
		let mut full_cipher = RSACipher::with_key_pair_and_padding(key_pair.clone(), padding);

		let message = b"Test";
		let ciphertext = full_cipher.encrypt(message).unwrap();

		// Convert to public-only (padding preserved)
		let mut public_cipher = full_cipher.into_public_only();

		// Should still be able to encrypt with same padding
		let _ = public_cipher.encrypt(b"Another message").unwrap();

		// Need a new full cipher to decrypt
		let padding2 = PKCS1v15::new(StdRng::seed_from_u64(456));
		let full_cipher2 = RSACipher::with_key_pair_and_padding(key_pair, padding2);
		let plaintext = full_cipher2.decrypt(&ciphertext).unwrap();
		assert_eq!(plaintext, message);
	}
}
