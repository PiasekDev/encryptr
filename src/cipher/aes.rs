//! AES (Advanced Encryption Standard) cipher implementation.
//!
//! This module implements AES encryption and decryption as specified in
//! [NIST FIPS 197](https://csrc.nist.gov/files/pubs/fips/197/final/docs/fips-197.pdf).
//!
//! # Supported Key Sizes
//!
//! - **AES-128**: 128-bit key, 10 rounds
//! - **AES-192**: 192-bit key, 12 rounds
//! - **AES-256**: 256-bit key, 14 rounds
//!
//! # Supported Modes
//!
//! - **ECB** (Electronic Codebook): Each block encrypted independently
//! - **CBC** (Cipher Block Chaining): Each block XORed with previous ciphertext
//!
//! # Example Usage
//!
//! ```
//! use encryptr::cipher::aes::{AES128, AES256, ECB, CBC};
//!
//! // AES-128 in ECB mode
//! let cipher = AES128::builder()
//!     .key([0u8; 16])
//!     .ecb()
//!     .build();
//! let ciphertext = cipher.encode(b"Hello, World!");
//! let plaintext = cipher.decode(&ciphertext).unwrap();
//!
//! // AES-256 in CBC mode with random IV
//! let cipher = AES256::builder()
//!     .key([0u8; 32])
//!     .cbc_random_iv()
//!     .build();
//! let ciphertext = cipher.encode(b"Secret message");
//! // IV is prepended to ciphertext, extracted automatically on decode
//! let plaintext = cipher.decode(&ciphertext).unwrap();
//! ```

use std::marker::PhantomData;

use thiserror::Error;

use crate::common::padding::{PKCS7PaddedData, PaddingParseError};

pub mod constants;
mod key_schedule;
mod mode;
mod state;

pub use mode::{Key128, Key192, Key256, KeySize, CBC, ECB};

use key_schedule::AESKeySchedule;
use mode::{Mode, NoKey, NoMode, WithKey};
use state::State;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during AES decryption.
#[derive(Debug, Error)]
pub enum AESDecodeError {
	/// The ciphertext length is not a multiple of 16 bytes.
	#[error("Invalid ciphertext length: must be a multiple of 16 bytes")]
	InvalidLength,

	/// The ciphertext is too short (e.g., missing IV for CBC mode).
	#[error("Ciphertext too short: expected at least {expected} bytes, got {actual}")]
	CiphertextTooShort { expected: usize, actual: usize },

	/// Invalid PKCS7 padding in the decrypted data.
	#[error("Padding error: {0:?}")]
	PaddingError(PaddingParseError),
}

impl From<PaddingParseError> for AESDecodeError {
	fn from(err: PaddingParseError) -> Self {
		AESDecodeError::PaddingError(err)
	}
}

// ============================================================================
// Main Cipher Type
// ============================================================================

/// AES cipher with compile-time enforced key size and mode.
///
/// Use the builder pattern to construct an instance:
/// ```
/// use encryptr::cipher::aes::{AES128, ECB};
///
/// let cipher = AES128::builder()
///     .key([0u8; 16])
///     .ecb()
///     .build();
/// ```
#[derive(Clone, Debug)]
pub struct AESCipher<K: KeySize, M: Mode> {
	key: K::KeyArray,
	mode: M,
	_marker: PhantomData<K>,
}

/// Type alias for AES-128 cipher.
pub type AES128<M = ECB> = AESCipher<Key128, M>;

/// Type alias for AES-192 cipher.
pub type AES192<M = ECB> = AESCipher<Key192, M>;

/// Type alias for AES-256 cipher.
pub type AES256<M = ECB> = AESCipher<Key256, M>;

// ============================================================================
// Builder Pattern
// ============================================================================

/// Builder for constructing AES ciphers with compile-time safety.
///
/// The builder uses typestate to ensure that:
/// - A key must be set before building
/// - A mode must be chosen before building
#[derive(Clone, Debug)]
pub struct AESBuilder<K: KeySize, KeyState, ModeState> {
	key_state: KeyState,
	mode_state: ModeState,
	_marker: PhantomData<K>,
}

// Entry points for the builder
impl AES128 {
	/// Create a builder for AES-128.
	pub fn builder() -> AESBuilder<Key128, NoKey, NoMode> {
		AESBuilder {
			key_state: NoKey,
			mode_state: NoMode,
			_marker: PhantomData,
		}
	}

	/// Create AES-128 in ECB mode (shortcut).
	pub fn new(key: [u8; 16]) -> Self {
		Self::builder().key(key).ecb().build()
	}

	/// Create AES-128 in CBC mode with specified IV (shortcut).
	pub fn with_cbc(key: [u8; 16], iv: [u8; 16]) -> AES128<CBC> {
		Self::builder().key(key).cbc_with_iv(iv).build()
	}

	/// Create AES-128 in CBC mode with random IV (shortcut).
	pub fn with_cbc_random_iv(key: [u8; 16]) -> AES128<CBC> {
		Self::builder().key(key).cbc_random_iv().build()
	}
}

impl AES192 {
	/// Create a builder for AES-192.
	pub fn builder() -> AESBuilder<Key192, NoKey, NoMode> {
		AESBuilder {
			key_state: NoKey,
			mode_state: NoMode,
			_marker: PhantomData,
		}
	}

	/// Create AES-192 in ECB mode (shortcut).
	pub fn new(key: [u8; 24]) -> Self {
		Self::builder().key(key).ecb().build()
	}

	/// Create AES-192 in CBC mode with specified IV (shortcut).
	pub fn with_cbc(key: [u8; 24], iv: [u8; 16]) -> AES192<CBC> {
		Self::builder().key(key).cbc_with_iv(iv).build()
	}

	/// Create AES-192 in CBC mode with random IV (shortcut).
	pub fn with_cbc_random_iv(key: [u8; 24]) -> AES192<CBC> {
		Self::builder().key(key).cbc_random_iv().build()
	}
}

impl AES256 {
	/// Create a builder for AES-256.
	pub fn builder() -> AESBuilder<Key256, NoKey, NoMode> {
		AESBuilder {
			key_state: NoKey,
			mode_state: NoMode,
			_marker: PhantomData,
		}
	}

	/// Create AES-256 in ECB mode (shortcut).
	pub fn new(key: [u8; 32]) -> Self {
		Self::builder().key(key).ecb().build()
	}

	/// Create AES-256 in CBC mode with specified IV (shortcut).
	pub fn with_cbc(key: [u8; 32], iv: [u8; 16]) -> AES256<CBC> {
		Self::builder().key(key).cbc_with_iv(iv).build()
	}

	/// Create AES-256 in CBC mode with random IV (shortcut).
	pub fn with_cbc_random_iv(key: [u8; 32]) -> AES256<CBC> {
		Self::builder().key(key).cbc_random_iv().build()
	}
}

// Builder: Set key
impl<K: KeySize, M> AESBuilder<K, NoKey, M> {
	/// Set the encryption key.
	pub fn key(self, key: K::KeyArray) -> AESBuilder<K, WithKey<K>, M> {
		AESBuilder {
			key_state: WithKey(key),
			mode_state: self.mode_state,
			_marker: PhantomData,
		}
	}
}

// Builder: Set mode (requires no mode set yet)
impl<K: KeySize, KS> AESBuilder<K, KS, NoMode> {
	/// Use ECB (Electronic Codebook) mode.
	pub fn ecb(self) -> AESBuilder<K, KS, ECB> {
		AESBuilder {
			key_state: self.key_state,
			mode_state: ECB,
			_marker: PhantomData,
		}
	}

	/// Use CBC (Cipher Block Chaining) mode with the specified IV.
	pub fn cbc_with_iv(self, iv: [u8; 16]) -> AESBuilder<K, KS, CBC> {
		AESBuilder {
			key_state: self.key_state,
			mode_state: CBC::with_iv(iv),
			_marker: PhantomData,
		}
	}

	/// Use CBC (Cipher Block Chaining) mode with a randomly generated IV.
	pub fn cbc_random_iv(self) -> AESBuilder<K, KS, CBC> {
		AESBuilder {
			key_state: self.key_state,
			mode_state: CBC::with_random_iv(),
			_marker: PhantomData,
		}
	}
}

// Builder: Build (requires key and mode to be set)
impl AESBuilder<Key128, WithKey<Key128>, ECB> {
	/// Build the AES-128 ECB cipher.
	pub fn build(self) -> AES128<ECB> {
		AESCipher {
			key: self.key_state.0,
			mode: self.mode_state,
			_marker: PhantomData,
		}
	}
}

impl AESBuilder<Key128, WithKey<Key128>, CBC> {
	/// Build the AES-128 CBC cipher.
	pub fn build(self) -> AES128<CBC> {
		AESCipher {
			key: self.key_state.0,
			mode: self.mode_state,
			_marker: PhantomData,
		}
	}
}

impl AESBuilder<Key192, WithKey<Key192>, ECB> {
	/// Build the AES-192 ECB cipher.
	pub fn build(self) -> AES192<ECB> {
		AESCipher {
			key: self.key_state.0,
			mode: self.mode_state,
			_marker: PhantomData,
		}
	}
}

impl AESBuilder<Key192, WithKey<Key192>, CBC> {
	/// Build the AES-192 CBC cipher.
	pub fn build(self) -> AES192<CBC> {
		AESCipher {
			key: self.key_state.0,
			mode: self.mode_state,
			_marker: PhantomData,
		}
	}
}

impl AESBuilder<Key256, WithKey<Key256>, ECB> {
	/// Build the AES-256 ECB cipher.
	pub fn build(self) -> AES256<ECB> {
		AESCipher {
			key: self.key_state.0,
			mode: self.mode_state,
			_marker: PhantomData,
		}
	}
}

impl AESBuilder<Key256, WithKey<Key256>, CBC> {
	/// Build the AES-256 CBC cipher.
	pub fn build(self) -> AES256<CBC> {
		AESCipher {
			key: self.key_state.0,
			mode: self.mode_state,
			_marker: PhantomData,
		}
	}
}

// ============================================================================
// Block Encryption/Decryption
// ============================================================================

/// Encrypt a single 16-byte block using AES-128.
fn encipher_block_128(block: &[u8; 16], key_schedule: &AESKeySchedule<11>) -> [u8; 16] {
	encipher_block_generic(block, key_schedule.round_keys())
}

/// Decrypt a single 16-byte block using AES-128.
fn decipher_block_128(block: &[u8; 16], key_schedule: &AESKeySchedule<11>) -> [u8; 16] {
	decipher_block_generic(block, key_schedule.round_keys())
}

/// Encrypt a single 16-byte block using AES-192.
fn encipher_block_192(block: &[u8; 16], key_schedule: &AESKeySchedule<13>) -> [u8; 16] {
	encipher_block_generic(block, key_schedule.round_keys())
}

/// Decrypt a single 16-byte block using AES-192.
fn decipher_block_192(block: &[u8; 16], key_schedule: &AESKeySchedule<13>) -> [u8; 16] {
	decipher_block_generic(block, key_schedule.round_keys())
}

/// Encrypt a single 16-byte block using AES-256.
fn encipher_block_256(block: &[u8; 16], key_schedule: &AESKeySchedule<15>) -> [u8; 16] {
	encipher_block_generic(block, key_schedule.round_keys())
}

/// Decrypt a single 16-byte block using AES-256.
fn decipher_block_256(block: &[u8; 16], key_schedule: &AESKeySchedule<15>) -> [u8; 16] {
	decipher_block_generic(block, key_schedule.round_keys())
}

/// Generic block encryption (works for any number of rounds).
fn encipher_block_generic<const ROUND_KEYS: usize>(
	block: &[u8; 16],
	round_keys: &[[u8; 16]; ROUND_KEYS],
) -> [u8; 16] {
	let mut state = State::from_block(block);

	// Initial round: AddRoundKey only
	state.add_round_key(&round_keys[0]);

	// Main rounds: SubBytes, ShiftRows, MixColumns, AddRoundKey
	for round_key in &round_keys[1..ROUND_KEYS - 1] {
		state.sub_bytes();
		state.shift_rows();
		state.mix_columns();
		state.add_round_key(round_key);
	}

	// Final round: SubBytes, ShiftRows, AddRoundKey (no MixColumns)
	state.sub_bytes();
	state.shift_rows();
	state.add_round_key(&round_keys[ROUND_KEYS - 1]);

	state.into_block()
}

/// Generic block decryption (works for any number of rounds).
fn decipher_block_generic<const ROUND_KEYS: usize>(
	block: &[u8; 16],
	round_keys: &[[u8; 16]; ROUND_KEYS],
) -> [u8; 16] {
	let mut state = State::from_block(block);

	// Initial round: AddRoundKey (with last round key)
	state.add_round_key(&round_keys[ROUND_KEYS - 1]);

	// Main rounds: InvShiftRows, InvSubBytes, AddRoundKey, InvMixColumns
	for round_key in round_keys[1..ROUND_KEYS - 1].iter().rev() {
		state.inv_shift_rows();
		state.inv_sub_bytes();
		state.add_round_key(round_key);
		state.inv_mix_columns();
	}

	// Final round: InvShiftRows, InvSubBytes, AddRoundKey (no InvMixColumns)
	state.inv_shift_rows();
	state.inv_sub_bytes();
	state.add_round_key(&round_keys[0]);

	state.into_block()
}

/// XOR two 16-byte blocks.
fn xor_blocks(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
	let mut result = [0u8; 16];
	for i in 0..16 {
		result[i] = a[i] ^ b[i];
	}
	result
}

// ============================================================================
// ECB Mode Implementation
// ============================================================================

impl AES128<ECB> {
	/// Encrypt data using AES-128 in ECB mode.
	pub fn encode(&self, input: &[u8]) -> Vec<u8> {
		let key_schedule = AESKeySchedule::from_key_128(self.key);
		PKCS7PaddedData::<16>::pad(input)
			.into_iter()
			.flat_map(|block| encipher_block_128(&block, &key_schedule))
			.collect()
	}

	/// Decrypt data using AES-128 in ECB mode.
	pub fn decode(&self, input: &[u8]) -> Result<Vec<u8>, AESDecodeError> {
		let (chunks, remainder) = input.as_chunks::<16>();
		if !remainder.is_empty() {
			return Err(AESDecodeError::InvalidLength);
		}

		let key_schedule = AESKeySchedule::from_key_128(self.key);
		let decrypted_blocks: Vec<[u8; 16]> = chunks
			.iter()
			.map(|block| decipher_block_128(block, &key_schedule))
			.collect();

		PKCS7PaddedData::try_from_blocks(decrypted_blocks)
			.map(|padded| padded.into_unpadded())
			.map_err(AESDecodeError::from)
	}
}

impl AES192<ECB> {
	/// Encrypt data using AES-192 in ECB mode.
	pub fn encode(&self, input: &[u8]) -> Vec<u8> {
		let key_schedule = AESKeySchedule::from_key_192(self.key);
		PKCS7PaddedData::<16>::pad(input)
			.into_iter()
			.flat_map(|block| encipher_block_192(&block, &key_schedule))
			.collect()
	}

	/// Decrypt data using AES-192 in ECB mode.
	pub fn decode(&self, input: &[u8]) -> Result<Vec<u8>, AESDecodeError> {
		let (chunks, remainder) = input.as_chunks::<16>();
		if !remainder.is_empty() {
			return Err(AESDecodeError::InvalidLength);
		}

		let key_schedule = AESKeySchedule::from_key_192(self.key);
		let decrypted_blocks: Vec<[u8; 16]> = chunks
			.iter()
			.map(|block| decipher_block_192(block, &key_schedule))
			.collect();

		PKCS7PaddedData::try_from_blocks(decrypted_blocks)
			.map(|padded| padded.into_unpadded())
			.map_err(AESDecodeError::from)
	}
}

impl AES256<ECB> {
	/// Encrypt data using AES-256 in ECB mode.
	pub fn encode(&self, input: &[u8]) -> Vec<u8> {
		let key_schedule = AESKeySchedule::from_key_256(self.key);
		PKCS7PaddedData::<16>::pad(input)
			.into_iter()
			.flat_map(|block| encipher_block_256(&block, &key_schedule))
			.collect()
	}

	/// Decrypt data using AES-256 in ECB mode.
	pub fn decode(&self, input: &[u8]) -> Result<Vec<u8>, AESDecodeError> {
		let (chunks, remainder) = input.as_chunks::<16>();
		if !remainder.is_empty() {
			return Err(AESDecodeError::InvalidLength);
		}

		let key_schedule = AESKeySchedule::from_key_256(self.key);
		let decrypted_blocks: Vec<[u8; 16]> = chunks
			.iter()
			.map(|block| decipher_block_256(block, &key_schedule))
			.collect();

		PKCS7PaddedData::try_from_blocks(decrypted_blocks)
			.map(|padded| padded.into_unpadded())
			.map_err(AESDecodeError::from)
	}
}

// ============================================================================
// CBC Mode Implementation
// ============================================================================

impl AES128<CBC> {
	/// Get the IV used for this cipher.
	pub fn iv(&self) -> &[u8; 16] {
		self.mode.iv()
	}

	/// Encrypt data using AES-128 in CBC mode.
	///
	/// The IV is prepended to the ciphertext.
	pub fn encode(&self, input: &[u8]) -> Vec<u8> {
		let key_schedule = AESKeySchedule::from_key_128(self.key);
		let mut result = self.mode.iv.to_vec();
		let mut prev_ciphertext = self.mode.iv;

		for block in PKCS7PaddedData::<16>::pad(input) {
			let xored = xor_blocks(&block, &prev_ciphertext);
			let encrypted = encipher_block_128(&xored, &key_schedule);
			result.extend_from_slice(&encrypted);
			prev_ciphertext = encrypted;
		}

		result
	}

	/// Decrypt data using AES-128 in CBC mode.
	///
	/// Expects the IV to be prepended to the ciphertext.
	pub fn decode(&self, input: &[u8]) -> Result<Vec<u8>, AESDecodeError> {
		if input.len() < 16 {
			return Err(AESDecodeError::CiphertextTooShort {
				expected: 16,
				actual: input.len(),
			});
		}

		// Extract IV from input
		let iv: [u8; 16] = input[..16].try_into().unwrap();
		let ciphertext = &input[16..];

		let (chunks, remainder) = ciphertext.as_chunks::<16>();
		if !remainder.is_empty() {
			return Err(AESDecodeError::InvalidLength);
		}

		let key_schedule = AESKeySchedule::from_key_128(self.key);
		let mut prev_ciphertext = iv;
		let mut decrypted_blocks = Vec::with_capacity(chunks.len());

		for block in chunks {
			let decrypted = decipher_block_128(block, &key_schedule);
			let plaintext = xor_blocks(&decrypted, &prev_ciphertext);
			decrypted_blocks.push(plaintext);
			prev_ciphertext = *block;
		}

		PKCS7PaddedData::try_from_blocks(decrypted_blocks)
			.map(|padded| padded.into_unpadded())
			.map_err(AESDecodeError::from)
	}
}

impl AES192<CBC> {
	/// Get the IV used for this cipher.
	pub fn iv(&self) -> &[u8; 16] {
		self.mode.iv()
	}

	/// Encrypt data using AES-192 in CBC mode.
	///
	/// The IV is prepended to the ciphertext.
	pub fn encode(&self, input: &[u8]) -> Vec<u8> {
		let key_schedule = AESKeySchedule::from_key_192(self.key);
		let mut result = self.mode.iv.to_vec();
		let mut prev_ciphertext = self.mode.iv;

		for block in PKCS7PaddedData::<16>::pad(input) {
			let xored = xor_blocks(&block, &prev_ciphertext);
			let encrypted = encipher_block_192(&xored, &key_schedule);
			result.extend_from_slice(&encrypted);
			prev_ciphertext = encrypted;
		}

		result
	}

	/// Decrypt data using AES-192 in CBC mode.
	///
	/// Expects the IV to be prepended to the ciphertext.
	pub fn decode(&self, input: &[u8]) -> Result<Vec<u8>, AESDecodeError> {
		if input.len() < 16 {
			return Err(AESDecodeError::CiphertextTooShort {
				expected: 16,
				actual: input.len(),
			});
		}

		let iv: [u8; 16] = input[..16].try_into().unwrap();
		let ciphertext = &input[16..];

		let (chunks, remainder) = ciphertext.as_chunks::<16>();
		if !remainder.is_empty() {
			return Err(AESDecodeError::InvalidLength);
		}

		let key_schedule = AESKeySchedule::from_key_192(self.key);
		let mut prev_ciphertext = iv;
		let mut decrypted_blocks = Vec::with_capacity(chunks.len());

		for block in chunks {
			let decrypted = decipher_block_192(block, &key_schedule);
			let plaintext = xor_blocks(&decrypted, &prev_ciphertext);
			decrypted_blocks.push(plaintext);
			prev_ciphertext = *block;
		}

		PKCS7PaddedData::try_from_blocks(decrypted_blocks)
			.map(|padded| padded.into_unpadded())
			.map_err(AESDecodeError::from)
	}
}

impl AES256<CBC> {
	/// Get the IV used for this cipher.
	pub fn iv(&self) -> &[u8; 16] {
		self.mode.iv()
	}

	/// Encrypt data using AES-256 in CBC mode.
	///
	/// The IV is prepended to the ciphertext.
	pub fn encode(&self, input: &[u8]) -> Vec<u8> {
		let key_schedule = AESKeySchedule::from_key_256(self.key);
		let mut result = self.mode.iv.to_vec();
		let mut prev_ciphertext = self.mode.iv;

		for block in PKCS7PaddedData::<16>::pad(input) {
			let xored = xor_blocks(&block, &prev_ciphertext);
			let encrypted = encipher_block_256(&xored, &key_schedule);
			result.extend_from_slice(&encrypted);
			prev_ciphertext = encrypted;
		}

		result
	}

	/// Decrypt data using AES-256 in CBC mode.
	///
	/// Expects the IV to be prepended to the ciphertext.
	pub fn decode(&self, input: &[u8]) -> Result<Vec<u8>, AESDecodeError> {
		if input.len() < 16 {
			return Err(AESDecodeError::CiphertextTooShort {
				expected: 16,
				actual: input.len(),
			});
		}

		let iv: [u8; 16] = input[..16].try_into().unwrap();
		let ciphertext = &input[16..];

		let (chunks, remainder) = ciphertext.as_chunks::<16>();
		if !remainder.is_empty() {
			return Err(AESDecodeError::InvalidLength);
		}

		let key_schedule = AESKeySchedule::from_key_256(self.key);
		let mut prev_ciphertext = iv;
		let mut decrypted_blocks = Vec::with_capacity(chunks.len());

		for block in chunks {
			let decrypted = decipher_block_256(block, &key_schedule);
			let plaintext = xor_blocks(&decrypted, &prev_ciphertext);
			decrypted_blocks.push(plaintext);
			prev_ciphertext = *block;
		}

		PKCS7PaddedData::try_from_blocks(decrypted_blocks)
			.map(|padded| padded.into_unpadded())
			.map_err(AESDecodeError::from)
	}
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;

	// ========================================================================
	// FIPS 197 Test Vectors
	// ========================================================================

	mod fips_197 {
		use super::*;

		/// FIPS 197 Appendix B - AES-128 Example
		#[test]
		fn aes128_example() {
			let key: [u8; 16] = [
				0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
				0x4f, 0x3c,
			];
			let plaintext: [u8; 16] = [
				0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
				0x07, 0x34,
			];
			let expected_ciphertext: [u8; 16] = [
				0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a,
				0x0b, 0x32,
			];

			let key_schedule = AESKeySchedule::from_key_128(key);
			let ciphertext = encipher_block_128(&plaintext, &key_schedule);
			assert_eq!(ciphertext, expected_ciphertext);

			let decrypted = decipher_block_128(&ciphertext, &key_schedule);
			assert_eq!(decrypted, plaintext);
		}

		/// FIPS 197 Appendix C.1 - AES-128 Example
		#[test]
		fn aes128_appendix_c1() {
			let key: [u8; 16] = [
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
				0x0e, 0x0f,
			];
			let plaintext: [u8; 16] = [
				0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
				0xee, 0xff,
			];
			let expected_ciphertext: [u8; 16] = [
				0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
				0xc5, 0x5a,
			];

			let key_schedule = AESKeySchedule::from_key_128(key);
			let ciphertext = encipher_block_128(&plaintext, &key_schedule);
			assert_eq!(ciphertext, expected_ciphertext);

			let decrypted = decipher_block_128(&ciphertext, &key_schedule);
			assert_eq!(decrypted, plaintext);
		}

		/// FIPS 197 Appendix C.2 - AES-192 Example
		#[test]
		fn aes192_appendix_c2() {
			let key: [u8; 24] = [
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
				0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			];
			let plaintext: [u8; 16] = [
				0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
				0xee, 0xff,
			];
			let expected_ciphertext: [u8; 16] = [
				0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d,
				0x71, 0x91,
			];

			let key_schedule = AESKeySchedule::from_key_192(key);
			let ciphertext = encipher_block_192(&plaintext, &key_schedule);
			assert_eq!(ciphertext, expected_ciphertext);

			let decrypted = decipher_block_192(&ciphertext, &key_schedule);
			assert_eq!(decrypted, plaintext);
		}

		/// FIPS 197 Appendix C.3 - AES-256 Example
		#[test]
		fn aes256_appendix_c3() {
			let key: [u8; 32] = [
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
				0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
				0x1c, 0x1d, 0x1e, 0x1f,
			];
			let plaintext: [u8; 16] = [
				0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
				0xee, 0xff,
			];
			let expected_ciphertext: [u8; 16] = [
				0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49,
				0x60, 0x89,
			];

			let key_schedule = AESKeySchedule::from_key_256(key);
			let ciphertext = encipher_block_256(&plaintext, &key_schedule);
			assert_eq!(ciphertext, expected_ciphertext);

			let decrypted = decipher_block_256(&ciphertext, &key_schedule);
			assert_eq!(decrypted, plaintext);
		}
	}

	// ========================================================================
	// NIST CAVP Known Answer Tests (selected vectors)
	// ========================================================================

	mod cavp_kat {
		use super::*;

		/// GFSbox test - tests S-box functionality
		#[test]
		fn aes128_gfsbox() {
			// From NIST CAVP GFSbox KAT
			let key: [u8; 16] = [0x00; 16];
			let plaintext: [u8; 16] = [
				0xf3, 0x44, 0x81, 0xec, 0x3c, 0xc6, 0x27, 0xba, 0xcd, 0x5d, 0xc3, 0xfb, 0x08, 0xf2,
				0x73, 0xe6,
			];
			let expected: [u8; 16] = [
				0x03, 0x36, 0x76, 0x3e, 0x96, 0x6d, 0x92, 0x59, 0x5a, 0x56, 0x7c, 0xc9, 0xce, 0x53,
				0x7f, 0x5e,
			];

			let key_schedule = AESKeySchedule::from_key_128(key);
			let ciphertext = encipher_block_128(&plaintext, &key_schedule);
			assert_eq!(ciphertext, expected);
		}

		/// KeySbox test - tests key schedule functionality
		#[test]
		fn aes128_keysbox() {
			// From NIST CAVP KeySbox KAT
			let key: [u8; 16] = [
				0x10, 0xa5, 0x88, 0x69, 0xd7, 0x4b, 0xe5, 0xa3, 0x74, 0xcf, 0x86, 0x7c, 0xfb, 0x47,
				0x38, 0x59,
			];
			let plaintext: [u8; 16] = [0x00; 16];
			let expected: [u8; 16] = [
				0x6d, 0x25, 0x1e, 0x69, 0x44, 0xb0, 0x51, 0xe0, 0x4e, 0xaa, 0x6f, 0xb4, 0xdb, 0xf7,
				0x84, 0x65,
			];

			let key_schedule = AESKeySchedule::from_key_128(key);
			let ciphertext = encipher_block_128(&plaintext, &key_schedule);
			assert_eq!(ciphertext, expected);
		}

		/// VarKey test - tests with varying keys
		#[test]
		fn aes128_varkey() {
			// Key with single bit set
			let key: [u8; 16] = [
				0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00,
			];
			let plaintext: [u8; 16] = [0x00; 16];
			let expected: [u8; 16] = [
				0x0e, 0xdd, 0x33, 0xd3, 0xc6, 0x21, 0xe5, 0x46, 0x45, 0x5b, 0xd8, 0xba, 0x14, 0x18,
				0xbe, 0xc8,
			];

			let key_schedule = AESKeySchedule::from_key_128(key);
			let ciphertext = encipher_block_128(&plaintext, &key_schedule);
			assert_eq!(ciphertext, expected);
		}

		/// VarTxt test - tests with varying plaintexts
		#[test]
		fn aes128_vartxt() {
			// Plaintext with single bit set
			let key: [u8; 16] = [0x00; 16];
			let plaintext: [u8; 16] = [
				0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00,
			];
			let expected: [u8; 16] = [
				0x3a, 0xd7, 0x8e, 0x72, 0x6c, 0x1e, 0xc0, 0x2b, 0x7e, 0xbf, 0xe9, 0x2b, 0x23, 0xd9,
				0xec, 0x34,
			];

			let key_schedule = AESKeySchedule::from_key_128(key);
			let ciphertext = encipher_block_128(&plaintext, &key_schedule);
			assert_eq!(ciphertext, expected);
		}
	}

	// ========================================================================
	// Roundtrip Tests (following DES pattern)
	// ========================================================================

	mod roundtrip {
		use super::*;

		const KEY_128: [u8; 16] = [
			0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
			0x4f, 0x3c,
		];

		const KEY_192: [u8; 24] = [
			0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90,
			0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
		];

		const KEY_256: [u8; 32] = [
			0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
			0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
			0x09, 0x14, 0xdf, 0xf4,
		];

		// AES-128 ECB roundtrip tests

		#[test]
		fn aes128_ecb_roundtrip_empty() {
			let cipher = AES128::new(KEY_128);
			let encoded = cipher.encode(&[]);
			let decoded = cipher.decode(&encoded).unwrap();
			assert_eq!(decoded, vec![]);
		}

		#[test]
		fn aes128_ecb_roundtrip_partial_block() {
			let cipher = AES128::new(KEY_128);
			let input = b"hello";
			let encoded = cipher.encode(input);
			assert_eq!(encoded.len(), 16); // padded to one block
			let decoded = cipher.decode(&encoded).unwrap();
			assert_eq!(decoded, input);
		}

		#[test]
		fn aes128_ecb_roundtrip_exact_block() {
			let cipher = AES128::new(KEY_128);
			let input = b"0123456789abcdef"; // exactly 16 bytes
			let encoded = cipher.encode(input);
			assert_eq!(encoded.len(), 32); // needs extra block for padding
			let decoded = cipher.decode(&encoded).unwrap();
			assert_eq!(decoded, input);
		}

		#[test]
		fn aes128_ecb_roundtrip_multiple_blocks() {
			let cipher = AES128::new(KEY_128);
			let input = b"hello world, this is a longer message that spans multiple blocks!";
			let encoded = cipher.encode(input);
			let decoded = cipher.decode(&encoded).unwrap();
			assert_eq!(decoded, input);
		}

		// AES-192 ECB roundtrip tests

		#[test]
		fn aes192_ecb_roundtrip_multiple_blocks() {
			let cipher = AES192::new(KEY_192);
			let input = b"hello world, this is a longer message that spans multiple blocks!";
			let encoded = cipher.encode(input);
			let decoded = cipher.decode(&encoded).unwrap();
			assert_eq!(decoded, input);
		}

		// AES-256 ECB roundtrip tests

		#[test]
		fn aes256_ecb_roundtrip_multiple_blocks() {
			let cipher = AES256::new(KEY_256);
			let input = b"hello world, this is a longer message that spans multiple blocks!";
			let encoded = cipher.encode(input);
			let decoded = cipher.decode(&encoded).unwrap();
			assert_eq!(decoded, input);
		}

		// CBC roundtrip tests

		#[test]
		fn aes128_cbc_roundtrip_empty() {
			let cipher = AES128::with_cbc_random_iv(KEY_128);
			let encoded = cipher.encode(&[]);
			let decoded = cipher.decode(&encoded).unwrap();
			assert_eq!(decoded, vec![]);
		}

		#[test]
		fn aes128_cbc_roundtrip_partial_block() {
			let iv = [0u8; 16];
			let cipher = AES128::with_cbc(KEY_128, iv);
			let input = b"hello";
			let encoded = cipher.encode(input);
			assert_eq!(encoded.len(), 32); // IV (16) + one padded block (16)
			let decoded = cipher.decode(&encoded).unwrap();
			assert_eq!(decoded, input);
		}

		#[test]
		fn aes128_cbc_roundtrip_multiple_blocks() {
			let cipher = AES128::with_cbc_random_iv(KEY_128);
			let input = b"hello world, this is a longer message that spans multiple blocks!";
			let encoded = cipher.encode(input);
			let decoded = cipher.decode(&encoded).unwrap();
			assert_eq!(decoded, input);
		}

		#[test]
		fn aes256_cbc_roundtrip_multiple_blocks() {
			let cipher = AES256::with_cbc_random_iv(KEY_256);
			let input = b"hello world, this is a longer message that spans multiple blocks!";
			let encoded = cipher.encode(input);
			let decoded = cipher.decode(&encoded).unwrap();
			assert_eq!(decoded, input);
		}
	}

	// ========================================================================
	// Error Condition Tests
	// ========================================================================

	mod errors {
		use super::*;

		#[test]
		fn decode_invalid_length() {
			let cipher = AES128::new([0u8; 16]);
			let result = cipher.decode(&[1, 2, 3]); // not multiple of 16
			assert!(matches!(result, Err(AESDecodeError::InvalidLength)));
		}

		#[test]
		fn cbc_decode_too_short() {
			let cipher = AES128::with_cbc([0u8; 16], [0u8; 16]);
			let result = cipher.decode(&[1, 2, 3, 4, 5]); // less than 16 bytes
			assert!(matches!(
				result,
				Err(AESDecodeError::CiphertextTooShort { .. })
			));
		}
	}

	// ========================================================================
	// CBC Mode Specific Tests
	// ========================================================================

	mod cbc_mode {
		use super::*;

		#[test]
		fn different_iv_produces_different_ciphertext() {
			let key = [0u8; 16];
			let plaintext = b"test message";

			let cipher1 = AES128::with_cbc(key, [0u8; 16]);
			let cipher2 = AES128::with_cbc(key, [1u8; 16]);

			let ct1 = cipher1.encode(plaintext);
			let ct2 = cipher2.encode(plaintext);

			// Same plaintext, same key, different IV = different ciphertext
			assert_ne!(ct1, ct2);
		}

		#[test]
		fn iv_is_prepended_to_ciphertext() {
			let key = [0u8; 16];
			let iv = [0x42u8; 16];
			let cipher = AES128::with_cbc(key, iv);

			let ciphertext = cipher.encode(b"hello");

			// First 16 bytes should be the IV
			assert_eq!(&ciphertext[..16], &iv);
		}

		#[test]
		fn random_iv_changes_each_time() {
			let key = [0u8; 16];

			let cipher1 = AES128::with_cbc_random_iv(key);
			let cipher2 = AES128::with_cbc_random_iv(key);

			// Random IVs should be different (extremely unlikely to be the same)
			assert_ne!(cipher1.iv(), cipher2.iv());
		}
	}

	// ========================================================================
	// Builder Pattern Tests
	// ========================================================================

	mod builder {
		use super::*;

		#[test]
		fn builder_aes128_ecb() {
			let cipher = AES128::builder().key([0u8; 16]).ecb().build();

			let plaintext = b"test";
			let ciphertext = cipher.encode(plaintext);
			let decrypted = cipher.decode(&ciphertext).unwrap();
			assert_eq!(decrypted, plaintext);
		}

		#[test]
		fn builder_aes256_cbc() {
			let cipher = AES256::builder()
				.key([0u8; 32])
				.cbc_with_iv([1u8; 16])
				.build();

			let plaintext = b"test";
			let ciphertext = cipher.encode(plaintext);
			let decrypted = cipher.decode(&ciphertext).unwrap();
			assert_eq!(decrypted, plaintext);
		}

		#[test]
		fn builder_order_independent() {
			// Can set key first, then mode
			let _cipher1 = AES128::builder().key([0u8; 16]).ecb().build();

			// Both orders should work and produce equivalent ciphers
			// (The builder enforces key + mode are set, order doesn't matter
			// since both are required before build())
		}
	}
}
