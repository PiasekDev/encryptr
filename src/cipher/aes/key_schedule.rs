//! AES Key Schedule (Key Expansion).
//!
//! The key schedule expands the cipher key into a series of round keys.
//! - AES-128: 16-byte key → 11 round keys (176 bytes)
//! - AES-192: 24-byte key → 13 round keys (208 bytes)
//! - AES-256: 32-byte key → 15 round keys (240 bytes)
//!
//! Based on FIPS 197, Section 5.2.

use super::constants::{RCON, S_BOX};

/// Type alias for a round key (16 bytes = 128 bits).
pub type RoundKey = [u8; 16];

/// AES Key Schedule containing all round keys.
///
/// The number of round keys depends on the key size:
/// - AES-128: 11 round keys
/// - AES-192: 13 round keys
/// - AES-256: 15 round keys
#[derive(Clone, Debug)]
pub struct AESKeySchedule<const ROUND_KEYS: usize> {
	round_keys: [RoundKey; ROUND_KEYS],
}

impl AESKeySchedule<11> {
	/// Create key schedule from a 128-bit (16-byte) key.
	///
	/// AES-128 uses 10 rounds plus an initial AddRoundKey, requiring 11 round keys.
	pub fn from_key_128(key: [u8; 16]) -> Self {
		let mut w = [[0u8; 4]; 44]; // 44 words for AES-128

		// Copy the original key into the first Nk words
		for i in 0..4 {
			w[i] = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
		}

		// Expand the key
		for i in 4..44 {
			let mut temp = w[i - 1];
			if i % 4 == 0 {
				temp = sub_word(rot_word(temp));
				temp[0] ^= RCON[i / 4];
			}
			w[i] = xor_words(w[i - 4], temp);
		}

		// Convert words to round keys
		let mut round_keys = [[0u8; 16]; 11];
		for (round, chunk) in w.chunks(4).enumerate() {
			for (word_idx, word) in chunk.iter().enumerate() {
				for (byte_idx, &byte) in word.iter().enumerate() {
					round_keys[round][word_idx * 4 + byte_idx] = byte;
				}
			}
		}

		AESKeySchedule { round_keys }
	}
}

impl AESKeySchedule<13> {
	/// Create key schedule from a 192-bit (24-byte) key.
	///
	/// AES-192 uses 12 rounds plus an initial AddRoundKey, requiring 13 round keys.
	pub fn from_key_192(key: [u8; 24]) -> Self {
		let mut w = [[0u8; 4]; 52]; // 52 words for AES-192

		// Copy the original key into the first Nk words
		for i in 0..6 {
			w[i] = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
		}

		// Expand the key
		for i in 6..52 {
			let mut temp = w[i - 1];
			if i % 6 == 0 {
				temp = sub_word(rot_word(temp));
				temp[0] ^= RCON[i / 6];
			}
			w[i] = xor_words(w[i - 6], temp);
		}

		// Convert words to round keys
		let mut round_keys = [[0u8; 16]; 13];
		for (round, chunk) in w.chunks(4).enumerate() {
			for (word_idx, word) in chunk.iter().enumerate() {
				for (byte_idx, &byte) in word.iter().enumerate() {
					round_keys[round][word_idx * 4 + byte_idx] = byte;
				}
			}
		}

		AESKeySchedule { round_keys }
	}
}

impl AESKeySchedule<15> {
	/// Create key schedule from a 256-bit (32-byte) key.
	///
	/// AES-256 uses 14 rounds plus an initial AddRoundKey, requiring 15 round keys.
	pub fn from_key_256(key: [u8; 32]) -> Self {
		let mut w = [[0u8; 4]; 60]; // 60 words for AES-256

		// Copy the original key into the first Nk words
		for i in 0..8 {
			w[i] = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
		}

		// Expand the key
		for i in 8..60 {
			let mut temp = w[i - 1];
			if i % 8 == 0 {
				temp = sub_word(rot_word(temp));
				temp[0] ^= RCON[i / 8];
			} else if i % 8 == 4 {
				// Additional SubWord for AES-256
				temp = sub_word(temp);
			}
			w[i] = xor_words(w[i - 8], temp);
		}

		// Convert words to round keys
		let mut round_keys = [[0u8; 16]; 15];
		for (round, chunk) in w.chunks(4).enumerate() {
			for (word_idx, word) in chunk.iter().enumerate() {
				for (byte_idx, &byte) in word.iter().enumerate() {
					round_keys[round][word_idx * 4 + byte_idx] = byte;
				}
			}
		}

		AESKeySchedule { round_keys }
	}
}

impl<const ROUND_KEYS: usize> AESKeySchedule<ROUND_KEYS> {
	/// Returns the round keys in reversed order (for decryption).
	#[allow(dead_code)]
	pub fn reversed(mut self) -> Self {
		self.round_keys.reverse();
		self
	}

	/// Get a reference to a specific round key.
	#[allow(dead_code)]
	pub fn get(&self, index: usize) -> Option<&RoundKey> {
		self.round_keys.get(index)
	}

	/// Get a reference to all round keys.
	pub fn round_keys(&self) -> &[RoundKey; ROUND_KEYS] {
		&self.round_keys
	}
}

impl<const ROUND_KEYS: usize> IntoIterator for AESKeySchedule<ROUND_KEYS> {
	type Item = RoundKey;
	type IntoIter = std::array::IntoIter<RoundKey, ROUND_KEYS>;

	fn into_iter(self) -> Self::IntoIter {
		self.round_keys.into_iter()
	}
}

/// RotWord: circular left shift of a 4-byte word by one byte.
/// [a0, a1, a2, a3] → [a1, a2, a3, a0]
fn rot_word(word: [u8; 4]) -> [u8; 4] {
	[word[1], word[2], word[3], word[0]]
}

/// SubWord: apply S-box to each byte of a word.
fn sub_word(word: [u8; 4]) -> [u8; 4] {
	[
		S_BOX[word[0] as usize],
		S_BOX[word[1] as usize],
		S_BOX[word[2] as usize],
		S_BOX[word[3] as usize],
	]
}

/// XOR two 4-byte words.
fn xor_words(a: [u8; 4], b: [u8; 4]) -> [u8; 4] {
	[a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]]
}

#[cfg(test)]
mod tests {
	use super::*;

	/// Test vectors from FIPS 197 Appendix A.1 (AES-128)
	#[test]
	fn key_expansion_128_fips197() {
		// Key from FIPS 197 Appendix A.1
		let key: [u8; 16] = [
			0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
			0x4f, 0x3c,
		];

		let schedule = AESKeySchedule::from_key_128(key);

		// First round key should be the original key
		assert_eq!(schedule.round_keys[0], key);

		// Round key 1 (from FIPS 197)
		let expected_rk1: [u8; 16] = [
			0xa0, 0xfa, 0xfe, 0x17, 0x88, 0x54, 0x2c, 0xb1, 0x23, 0xa3, 0x39, 0x39, 0x2a, 0x6c,
			0x76, 0x05,
		];
		assert_eq!(schedule.round_keys[1], expected_rk1);

		// Round key 10 (last, from FIPS 197)
		let expected_rk10: [u8; 16] = [
			0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee, 0x25, 0x89, 0xe1, 0x3f, 0x0c, 0xc8, 0xb6, 0x63,
			0x0c, 0xa6,
		];
		assert_eq!(schedule.round_keys[10], expected_rk10);
	}

	/// Test vectors from FIPS 197 Appendix A.2 (AES-192)
	#[test]
	fn key_expansion_192_fips197() {
		// Key from FIPS 197 Appendix A.2
		let key: [u8; 24] = [
			0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90,
			0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
		];

		let schedule = AESKeySchedule::from_key_192(key);

		// First round key should be first 16 bytes of key
		let expected_rk0: [u8; 16] = key[0..16].try_into().unwrap();
		assert_eq!(schedule.round_keys[0], expected_rk0);

		// Round key 12 (last, from FIPS 197)
		// Note: FIPS 197 provides w[48]..w[51] which form round key 12
		// Let's verify round key 1 instead (more straightforward)
		// Round key 1 = w[4]..w[7]
		// w[4..5] are from the key, w[6..7] are expanded
		let expected_rk1: [u8; 16] = [
			0x62, 0xf8, 0xea, 0xd2, // w[4] - last 8 bytes of key
			0x52, 0x2c, 0x6b, 0x7b, // w[5]
			0xfe, 0x0c, 0x91, 0xf7, // w[6] - expanded
			0x24, 0x02, 0xf5, 0xa5, // w[7]
		];
		assert_eq!(schedule.round_keys[1], expected_rk1);
	}

	/// Test vectors from FIPS 197 Appendix A.3 (AES-256)
	#[test]
	fn key_expansion_256_fips197() {
		// Key from FIPS 197 Appendix A.3
		let key: [u8; 32] = [
			0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
			0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
			0x09, 0x14, 0xdf, 0xf4,
		];

		let schedule = AESKeySchedule::from_key_256(key);

		// First round key should be first 16 bytes of key
		let expected_rk0: [u8; 16] = key[0..16].try_into().unwrap();
		assert_eq!(schedule.round_keys[0], expected_rk0);

		// Second round key should be second 16 bytes of key
		let expected_rk1: [u8; 16] = key[16..32].try_into().unwrap();
		assert_eq!(schedule.round_keys[1], expected_rk1);

		// Round key 2 (from FIPS 197)
		let expected_rk2: [u8; 16] = [
			0x9b, 0xa3, 0x54, 0x11, 0x8e, 0x69, 0x25, 0xaf, 0xa5, 0x1a, 0x8b, 0x5f, 0x20, 0x67,
			0xfc, 0xde,
		];
		assert_eq!(schedule.round_keys[2], expected_rk2);
	}

	#[test]
	fn rot_word_test() {
		assert_eq!(rot_word([0x09, 0xcf, 0x4f, 0x3c]), [0xcf, 0x4f, 0x3c, 0x09]);
	}

	#[test]
	fn sub_word_test() {
		// SubWord applies S-box to each byte
		assert_eq!(
			sub_word([0xcf, 0x4f, 0x3c, 0x09]),
			[
				S_BOX[0xcf],
				S_BOX[0x4f],
				S_BOX[0x3c],
				S_BOX[0x09]
			]
		);
		assert_eq!(sub_word([0xcf, 0x4f, 0x3c, 0x09]), [0x8a, 0x84, 0xeb, 0x01]);
	}

	#[test]
	fn reversed_key_schedule() {
		let key: [u8; 16] = [
			0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
			0x4f, 0x3c,
		];

		let schedule = AESKeySchedule::from_key_128(key);
		let reversed = schedule.clone().reversed();

		// First key of reversed should be last key of original
		assert_eq!(reversed.round_keys[0], schedule.round_keys[10]);
		assert_eq!(reversed.round_keys[10], schedule.round_keys[0]);
	}

	#[test]
	fn into_iterator() {
		let key: [u8; 16] = [0u8; 16];
		let schedule = AESKeySchedule::from_key_128(key);

		let keys: Vec<_> = schedule.into_iter().collect();
		assert_eq!(keys.len(), 11);
	}
}
