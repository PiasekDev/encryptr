use std::num::NonZeroU8;

use itertools::Itertools;
use num_bigint::BigUint;
use sealed::sealed;
use thiserror::Error;

const LEADING_BYTE: u8 = 0x00;
const LEADING_BYTE_LEN: usize = 1;
const BLOCK_TYPE_ENCRYPT: u8 = 0x02;
const BLOCK_TYPE_LEN: usize = 1;
const MIN_PADDING_STRING_LEN: usize = 8;
const SEPARATOR_BYTE: u8 = 0x00;
const SEPARATOR_LEN: usize = 1;

const PKCS1_OVERHEAD: usize = LEADING_BYTE_LEN + BLOCK_TYPE_LEN + SEPARATOR_LEN;
const PKCS1_MIN_KEY_BYTES: usize = PKCS1_OVERHEAD + MIN_PADDING_STRING_LEN;

#[derive(Debug, Error)]
pub enum PaddingError {
	#[error("message too long for key size (max {max} bytes, got {actual} bytes)")]
	MessageTooLong { max: usize, actual: usize },

	#[error("key too small for PKCS#1 v1.5 (minimum {PKCS1_MIN_KEY_BYTES} bytes)")]
	KeyTooSmall,

	#[error("invalid padding: missing leading zero")]
	MissingLeadingZero,

	#[error("invalid padding: data too short")]
	DataTooShort,

	#[error("invalid padding: separator not found")]
	SeparatorNotFound,

	#[error("invalid padding: padding string too short (minimum {MIN_PADDING_STRING_LEN} bytes)")]
	PaddingStringTooShort,

	#[error("invalid block type: expected {BLOCK_TYPE_ENCRYPT:#04x}, got {actual:#04x}")]
	InvalidBlockType { actual: u8 },
}

#[sealed]
pub trait RSAPadding {
	fn pad(&mut self, message: &[u8], key_byte_len: usize) -> Result<BigUint, PaddingError>;
	fn unpad(plaintext: &BigUint, key_byte_len: usize) -> Result<Vec<u8>, PaddingError>;
	fn max_message_len(key_byte_len: usize) -> usize;
}

/// Marker trait for padding schemes that support byte-level encryption.
///
/// This trait is sealed and automatically implemented for padding schemes
/// that preserve message boundaries (like PKCS#1 v1.5).
///
/// [`NoPadding`] does not implement this trait because it cannot preserve
/// leading zeros, making byte-accurate roundtrips impossible for multi-block
/// encryption.
#[sealed]
pub trait ByteEncryptionPadding: RSAPadding {}

/// No padding (textbook RSA).
pub struct NoPadding;

#[sealed]
impl RSAPadding for NoPadding {
	fn pad(&mut self, message: &[u8], key_byte_len: usize) -> Result<BigUint, PaddingError> {
		if message.len() > key_byte_len {
			return Err(PaddingError::MessageTooLong {
				max: key_byte_len,
				actual: message.len(),
			});
		}
		Ok(BigUint::from_bytes_be(message))
	}

	fn unpad(plaintext: &BigUint, _key_byte_len: usize) -> Result<Vec<u8>, PaddingError> {
		Ok(plaintext.to_bytes_be())
	}

	fn max_message_len(key_byte_len: usize) -> usize {
		key_byte_len
	}
}

/// PKCS#1 v1.5 encryption padding.
///
/// The padding format is:
/// ```text
/// 0x00 || 0x02 || PS || 0x00 || Message
/// ```
/// Where:
/// - `0x00`: Leading byte (ensures padded value < n)
/// - `0x02`: Block type for encryption
/// - `PS`: Random non-zero bytes (at least 8 bytes)
/// - `0x00`: Separator
/// - `M`: Message
///
/// # Key Size Requirements
///
/// The key must be at least 11 bytes (88 bits) to accommodate the minimum
/// padding overhead. In practice, RSA keys should be at least 2048 bits
/// for security.
///
/// # Example
///
/// ```
/// use encryptr::cipher::rsa::{RSACipher, PKCS1v15, bits::KeyBits, key::RSAKeyPair};
/// use rand::SeedableRng;
///
/// let bits = KeyBits::try_from(512).unwrap();
/// let mut rng = rand::rngs::StdRng::seed_from_u64(42);
/// let key_pair = RSAKeyPair::generate(bits, &mut rng);
///
/// let padding = PKCS1v15::new(rand::rngs::StdRng::seed_from_u64(123));
/// let mut cipher = RSACipher::with_key_pair_and_padding(key_pair, padding);
///
/// let message = b"Hello, PKCS#1 v1.5!";
/// let ciphertext = cipher.encrypt(message).unwrap();
/// let plaintext = cipher.decrypt(&ciphertext).unwrap();
/// assert_eq!(plaintext, message);
/// ```
pub struct PKCS1v15<R: rand::Rng> {
	rng: R,
}

impl<R: rand::Rng> PKCS1v15<R> {
	pub fn new(rng: R) -> Self {
		Self { rng }
	}
}

#[sealed]
impl<R: rand::Rng> RSAPadding for PKCS1v15<R> {
	fn pad(&mut self, message: &[u8], key_byte_len: usize) -> Result<BigUint, PaddingError> {
		if key_byte_len < PKCS1_MIN_KEY_BYTES {
			return Err(PaddingError::KeyTooSmall);
		}

		let max_len = Self::max_message_len(key_byte_len);
		if message.len() > max_len {
			return Err(PaddingError::MessageTooLong {
				max: max_len,
				actual: message.len(),
			});
		}

		let ps_len = key_byte_len - PKCS1_OVERHEAD - message.len();
		let random_padding_bytes = (0..ps_len)
			.map(|_| self.rng.r#gen::<NonZeroU8>().get())
			.collect_vec();

		let mut padded = Vec::with_capacity(key_byte_len);
		padded.push(LEADING_BYTE);
		padded.push(BLOCK_TYPE_ENCRYPT);
		padded.extend_from_slice(&random_padding_bytes);
		padded.push(SEPARATOR_BYTE);
		padded.extend_from_slice(message);

		Ok(BigUint::from_bytes_be(&padded))
	}

	fn unpad(plaintext: &BigUint, key_byte_len: usize) -> Result<Vec<u8>, PaddingError> {
		let bytes = biguint_to_bytes_exact(plaintext, key_byte_len);

		if bytes.len() < PKCS1_MIN_KEY_BYTES {
			return Err(PaddingError::DataTooShort);
		}
		if bytes[0] != LEADING_BYTE {
			return Err(PaddingError::MissingLeadingZero);
		}
		if bytes[1] != BLOCK_TYPE_ENCRYPT {
			return Err(PaddingError::InvalidBlockType { actual: bytes[1] });
		}

		let ps_start = LEADING_BYTE_LEN + BLOCK_TYPE_LEN;
		let min_separator_pos = ps_start + MIN_PADDING_STRING_LEN;

		let separator_pos = bytes[ps_start..]
			.iter()
			.position(|&b| b == SEPARATOR_BYTE)
			.map(|pos| ps_start + pos);

		match separator_pos {
			Some(pos) if pos >= min_separator_pos => Ok(bytes[pos + 1..].to_vec()),
			Some(_) => Err(PaddingError::PaddingStringTooShort),
			None => Err(PaddingError::SeparatorNotFound),
		}
	}

	fn max_message_len(key_byte_len: usize) -> usize {
		key_byte_len.saturating_sub(PKCS1_MIN_KEY_BYTES)
	}
}

#[sealed]
impl<R: rand::Rng> ByteEncryptionPadding for PKCS1v15<R> {}

/// Convert `BigUint` to bytes with specified length (zero-padded on left).
///
/// If the `BigUint` has more bytes than `len`, the most significant bytes
/// are truncated (takes least significant `len` bytes).
pub(crate) fn biguint_to_bytes_exact(n: &BigUint, len: usize) -> Vec<u8> {
	let bytes = n.to_bytes_be();
	if bytes.len() >= len {
		bytes[bytes.len() - len..].to_vec()
	} else {
		let mut padded = vec![0u8; len - bytes.len()];
		padded.extend(bytes);
		padded
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use rand::SeedableRng;
	use rand::rngs::StdRng;

	fn test_rng() -> StdRng {
		StdRng::seed_from_u64(42)
	}

	#[test]
	fn biguint_to_bytes_exact_zero() {
		let n = BigUint::ZERO;
		assert_eq!(biguint_to_bytes_exact(&n, 4), vec![0, 0, 0, 0]);
	}

	#[test]
	fn biguint_to_bytes_exact_small_value() {
		let n = BigUint::from(0x42u64);
		assert_eq!(biguint_to_bytes_exact(&n, 4), vec![0, 0, 0, 0x42]);
	}

	#[test]
	fn biguint_to_bytes_exact_exact_size() {
		let n = BigUint::from(0x01020304u64);
		assert_eq!(biguint_to_bytes_exact(&n, 4), vec![0x01, 0x02, 0x03, 0x04]);
	}

	#[test]
	fn biguint_to_bytes_exact_truncates() {
		let n = BigUint::from(0x0102030405u64);
		// Truncates most significant byte
		assert_eq!(biguint_to_bytes_exact(&n, 4), vec![0x02, 0x03, 0x04, 0x05]);
	}

	#[test]
	fn no_padding_roundtrip() {
		let mut padding = NoPadding;
		let message = b"Hello, World!";
		let key_byte_len = 64;

		let padded = padding.pad(message, key_byte_len).unwrap();
		assert_eq!(NoPadding::unpad(&padded, key_byte_len).unwrap(), message);
	}

	#[test]
	fn no_padding_too_long() {
		let mut padding = NoPadding;
		let message = vec![0u8; 65];
		let key_byte_len = 64;

		assert!(matches!(
			padding.pad(&message, key_byte_len),
			Err(PaddingError::MessageTooLong {
				max: 64,
				actual: 65
			})
		));
	}

	#[test]
	fn no_padding_loses_leading_zeros() {
		let mut padding = NoPadding;
		// Message with leading zeros
		let message = &[0x00, 0x00, 0x42, 0x43];
		let key_byte_len = 64;
		let padded = padding.pad(message, key_byte_len).unwrap();
		let unpadded = NoPadding::unpad(&padded, key_byte_len).unwrap();

		// Leading zeros are lost due to BigUint normalization
		assert_eq!(unpadded, vec![0x42, 0x43]);
		assert_ne!(unpadded.as_slice(), message);
	}

	#[test]
	fn pkcs1v15_roundtrip() {
		let mut padding = PKCS1v15::new(test_rng());
		let message = b"Hello, RSA!";
		let key_byte_len = 64;

		let padded = padding.pad(message, key_byte_len).unwrap();
		let unpadded = PKCS1v15::<StdRng>::unpad(&padded, key_byte_len).unwrap();

		assert_eq!(unpadded, message);
	}

	#[test]
	fn pkcs1v15_empty_message() {
		let mut padding = PKCS1v15::new(test_rng());
		let message = b"";
		let key_byte_len = 64;

		let padded = padding.pad(message, key_byte_len).unwrap();
		let unpadded = PKCS1v15::<StdRng>::unpad(&padded, key_byte_len).unwrap();

		assert_eq!(unpadded, message);
	}

	#[test]
	fn pkcs1v15_max_length() {
		let mut padding = PKCS1v15::new(test_rng());
		let key_byte_len = 64;
		let max_len = PKCS1v15::<StdRng>::max_message_len(key_byte_len);

		let message = vec![0x42u8; max_len];
		let padded = padding.pad(&message, key_byte_len).unwrap();
		let unpadded = PKCS1v15::<StdRng>::unpad(&padded, key_byte_len).unwrap();

		assert_eq!(unpadded, message);
	}

	#[test]
	fn pkcs1v15_too_long() {
		let mut padding = PKCS1v15::new(test_rng());
		let key_byte_len = 64;
		let max_len = PKCS1v15::<StdRng>::max_message_len(key_byte_len);

		let message = vec![0x42u8; max_len + 1];
		let result = padding.pad(&message, key_byte_len);
		assert!(matches!(
			result,
			Err(PaddingError::MessageTooLong { max, actual }) if max == max_len && actual == max_len + 1
		));
	}

	#[test]
	fn pkcs1v15_key_too_small() {
		let mut padding = PKCS1v15::new(test_rng());
		let message = b"Hi";
		assert!(matches!(
			padding.pad(message, 10),
			Err(PaddingError::KeyTooSmall)
		));
	}

	#[test]
	fn pkcs1v15_preserves_leading_zeros() {
		let mut padding = PKCS1v15::new(test_rng());
		let msg = &[0x00, 0x00, 0x42];
		let padded = padding.pad(msg, 64).unwrap();
		assert_eq!(PKCS1v15::<StdRng>::unpad(&padded, 64).unwrap(), msg);
	}

	#[test]
	fn pkcs1v15_format() {
		let mut padding = PKCS1v15::new(test_rng());
		let message = b"Test";
		let padded = padding.pad(message, 32).unwrap();
		let bytes = biguint_to_bytes_exact(&padded, 32);

		assert_eq!(bytes[0], LEADING_BYTE);
		assert_eq!(bytes[1], BLOCK_TYPE_ENCRYPT);
		assert!(bytes[2..27].iter().all(|&b| b != 0)); // PS non-zero
		assert_eq!(bytes[27], SEPARATOR_BYTE);
		assert_eq!(&bytes[28..], message);
	}

	#[test]
	fn pkcs1v15_unpad_wrong_leading_byte() {
		let key_len = 32;
		// Create invalid padding: wrong first byte (should be 0x00)
		let mut bytes = vec![0x01, 0x02]; // Wrong: first byte is 0x01
		bytes.extend(vec![0xFF; 8]); // PS (8 bytes)
		bytes.push(0x00); // separator
		bytes.extend(b"message");
		bytes.resize(key_len, 0x00);

		let padded = BigUint::from_bytes_be(&bytes);
		let result = PKCS1v15::<StdRng>::unpad(&padded, key_len);

		assert!(matches!(result, Err(PaddingError::MissingLeadingZero)));
	}

	#[test]
	fn pkcs1v15_unpad_wrong_block_type() {
		let key_len = 32;
		// Create invalid padding: wrong block type (should be 0x02)
		let mut bytes = vec![0x00, 0x01]; // Wrong: block type is 0x01 (signature padding)
		bytes.extend(vec![0xFF; 8]); // PS (8 bytes)
		bytes.push(0x00); // separator
		bytes.extend(b"message");
		bytes.resize(key_len, 0x00);

		let padded = BigUint::from_bytes_be(&bytes);
		let result = PKCS1v15::<StdRng>::unpad(&padded, key_len);

		assert!(matches!(
			result,
			Err(PaddingError::InvalidBlockType { actual: 0x01 })
		));
	}

	#[test]
	fn pkcs1v15_unpad_ps_too_short() {
		let key_len = 32;
		// Create invalid padding: PS only 3 bytes (must be at least 8)
		let mut bytes = vec![0x00, 0x02];
		bytes.extend(vec![0xFF; 3]); // PS only 3 bytes (too short)
		bytes.push(0x00); // separator at index 5
		bytes.extend(b"message");
		bytes.resize(key_len, 0x00);

		let padded = BigUint::from_bytes_be(&bytes);
		let result = PKCS1v15::<StdRng>::unpad(&padded, key_len);

		assert!(matches!(result, Err(PaddingError::PaddingStringTooShort)));
	}

	#[test]
	fn pkcs1v15_unpad_missing_separator() {
		let key_len = 32;
		// Create invalid padding: no separator (all non-zero)
		let mut bytes = vec![0x00, 0x02];
		bytes.extend(vec![0xFF; key_len - 2]); // All non-zero, no separator

		let padded = BigUint::from_bytes_be(&bytes);
		let result = PKCS1v15::<StdRng>::unpad(&padded, key_len);

		assert!(matches!(result, Err(PaddingError::SeparatorNotFound)));
	}

	#[test]
	fn pkcs1v15_unpad_data_too_short() {
		let key_len = 10; // Less than minimum 11
		let padded = BigUint::from_bytes_be(&[0x00, 0x02, 0xFF, 0xFF, 0x00]);
		let result = PKCS1v15::<StdRng>::unpad(&padded, key_len);

		assert!(matches!(result, Err(PaddingError::DataTooShort)));
	}

	#[test]
	fn pkcs1v15_different_padding_each_time() {
		let mut padding1 = PKCS1v15::new(StdRng::seed_from_u64(1));
		let mut padding2 = PKCS1v15::new(StdRng::seed_from_u64(2));

		let message = b"Same message";
		let key_len = 64;

		let padded1 = padding1.pad(message, key_len).unwrap();
		let padded2 = padding2.pad(message, key_len).unwrap();

		// Different RNG seeds should produce different padding
		assert_ne!(padded1, padded2);

		// But both should unpad to the same message
		let unpadded1 = PKCS1v15::<StdRng>::unpad(&padded1, key_len).unwrap();
		let unpadded2 = PKCS1v15::<StdRng>::unpad(&padded2, key_len).unwrap();
		assert_eq!(unpadded1, message);
		assert_eq!(unpadded2, message);
	}
}
