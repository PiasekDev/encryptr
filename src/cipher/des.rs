use itertools::Itertools;
use tap::Pipe;

use crate::{
	cipher::des::{
		input::{PKCS7PaddedData, PaddingParseError},
		key_schedule::{KeyBits, KeySchedule},
		sequence::ContinuousBitSequence,
	},
	extension::u8::{BitByBitAdditionMod2, SelectExt, ToHalvesExt},
};

pub mod sequence;

mod input;
mod key_schedule;
mod permutation;

/// Data Encryption Standard (DES) cipher implementation.
///
/// Based on the description from [FIPS PUB 46-3](https://csrc.nist.gov/files/pubs/fips/46-3/final/docs/fips46-3.pdf).
pub struct DESCipher {
	key: [u8; 8],
}

#[derive(Debug)]
pub enum DESDecodeError {
	InvalidLength,
	PaddingError(PaddingParseError),
}

impl DESCipher {
	pub fn new(key: [u8; 8]) -> Self {
		DESCipher { key }
	}

	pub fn encode(&self, input: &[u8]) -> Vec<u8> {
		PKCS7PaddedData::<8>::pad(input)
			.into_iter()
			.flat_map(|block| encipher_block(&block, self.key))
			.collect()
	}

	pub fn decode(&self, input: &[u8]) -> Result<Vec<u8>, DESDecodeError> {
		let (chunks, remainder) = input.as_chunks();
		if !remainder.is_empty() {
			return Err(DESDecodeError::InvalidLength);
		}

		let decrypted_blocks = chunks
			.iter()
			.map(|block| decipher_block(block, self.key))
			.collect_vec();

		PKCS7PaddedData::try_from_blocks(decrypted_blocks)
			.map(|padded| padded.into_unpadded())
			.map_err(DESDecodeError::PaddingError)
	}
}

fn encipher_block(block: &[u8; 8], key: [u8; 8]) -> [u8; 8] {
	let key_schedule = KeySchedule::new(key);
	apply_des_rounds(block, key_schedule)
}

fn decipher_block(block: &[u8; 8], key: [u8; 8]) -> [u8; 8] {
	let reversed_schedule = KeySchedule::new(key).reversed();
	apply_des_rounds(block, reversed_schedule)
}

fn apply_des_rounds(block: &[u8; 8], key_schedule: impl IntoIterator<Item = KeyBits>) -> [u8; 8] {
	let permuted = constants::IP.permute(block);
	let (mut left, mut right) = permuted.to_halves();
	for subkey in key_schedule {
		(left, right) = (right, left.xor(&cipher_function(right, subkey)));
	}
	let preoutput: [u8; 8] = [right, left].as_flattened().try_into().unwrap();
	constants::IP_INV.permute(&preoutput)
}

fn cipher_function(right: [u8; 4], subkey: [u8; 6]) -> [u8; 4] {
	constants::E
		.permute(&right)
		.pipe(|permuted| permuted.xor(&subkey))
		.pipe(ContinuousBitSequence::from)
		.bit_chunks::<6>()
		.enumerate()
		.map(|(i, chunk)| (constants::S_BOXES[i], chunk))
		.map(|(s_box, chunk)| s_box.select(chunk))
		.collect_array::<8>()
		.expect("There should be exactly 8 chunks from 8 S-boxes")
		.chunks(2)
		.map(|chunk| chunk.iter().collect_tuple().unwrap())
		.map(|(high, low)| (high << 4) | low)
		.collect_array::<4>()
		.expect("The output of 8 S-boxes should be 8 nibbles, which can be packed into 4 bytes")
		.pipe(|bytes| constants::P.permute(&bytes))
}

mod constants {
	use crate::cipher::des::permutation::perm_table;

	perm_table!(
		IP,
		INPUT_BITS = 64,
		[
			58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22,
			14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27,
			19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
		]
	);

	perm_table!(
		IP_INV,
		INPUT_BITS = 64,
		[
			40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22,
			62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11,
			51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
		]
	);

	perm_table!(
		E,
		INPUT_BITS = 32,
		[
			32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16,
			17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,
			1,
		]
	);

	pub const S_BOXES: [[[u8; 16]; 4]; 8] = [
		[
			[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
			[0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
			[4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
			[15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
		],
		[
			[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
			[3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
			[0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
			[13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
		],
		[
			[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
			[13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
			[13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
			[1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
		],
		[
			[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
			[13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
			[10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
			[3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
		],
		[
			[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
			[14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
			[4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
			[11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
		],
		[
			[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
			[10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
			[9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
			[4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
		],
		[
			[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
			[13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
			[1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
			[6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
		],
		[
			[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
			[1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
			[7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
			[2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
		],
	];

	perm_table!(
		P,
		INPUT_BITS = 32,
		[
			16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3,
			9, 19, 13, 30, 6, 22, 11, 4, 25,
		]
	);
}

#[cfg(test)]
mod tests {
	use super::*;

	const KEY: [u8; 8] = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1];
	const MESSAGE: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
	const CIPHERTEXT: [u8; 8] = [0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05];

	/// Test taken from [The DES Algorithm Illustrated](https://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm)
	#[test]
	fn orlin_grabbe() {
		let ciphertext = encipher_block(&MESSAGE, KEY);
		assert_eq!(ciphertext, CIPHERTEXT);
		let deciphered = decipher_block(&ciphertext, KEY);
		assert_eq!(deciphered, MESSAGE);
	}

	const KEYS: [[u8; 8]; 19] = [
		[0x7C, 0xA1, 0x10, 0x45, 0x4A, 0x1A, 0x6E, 0x57],
		[0x01, 0x31, 0xD9, 0x61, 0x9D, 0xC1, 0x37, 0x6E],
		[0x07, 0xA1, 0x13, 0x3E, 0x4A, 0x0B, 0x26, 0x86],
		[0x38, 0x49, 0x67, 0x4C, 0x26, 0x02, 0x31, 0x9E],
		[0x04, 0xB9, 0x15, 0xBA, 0x43, 0xFE, 0xB5, 0xB6],
		[0x01, 0x13, 0xB9, 0x70, 0xFD, 0x34, 0xF2, 0xCE],
		[0x01, 0x70, 0xF1, 0x75, 0x46, 0x8F, 0xB5, 0xE6],
		[0x43, 0x29, 0x7F, 0xAD, 0x38, 0xE3, 0x73, 0xFE],
		[0x07, 0xA7, 0x13, 0x70, 0x45, 0xDA, 0x2A, 0x16],
		[0x04, 0x68, 0x91, 0x04, 0xC2, 0xFD, 0x3B, 0x2F],
		[0x37, 0xD0, 0x6B, 0xB5, 0x16, 0xCB, 0x75, 0x46],
		[0x1F, 0x08, 0x26, 0x0D, 0x1A, 0xC2, 0x46, 0x5E],
		[0x58, 0x40, 0x23, 0x64, 0x1A, 0xBA, 0x61, 0x76],
		[0x02, 0x58, 0x16, 0x16, 0x46, 0x29, 0xB0, 0x07],
		[0x49, 0x79, 0x3E, 0xBC, 0x79, 0xB3, 0x25, 0x8F],
		[0x4F, 0xB0, 0x5E, 0x15, 0x15, 0xAB, 0x73, 0xA7],
		[0x49, 0xE9, 0x5D, 0x6D, 0x4C, 0xA2, 0x29, 0xBF],
		[0x01, 0x83, 0x10, 0xDC, 0x40, 0x9B, 0x26, 0xD6],
		[0x1C, 0x58, 0x7F, 0x1C, 0x13, 0x92, 0x4F, 0xEF],
	];

	const PLAINS: [[u8; 8]; 19] = [
		[0x01, 0xA1, 0xD6, 0xD0, 0x39, 0x77, 0x67, 0x42],
		[0x5C, 0xD5, 0x4C, 0xA8, 0x3D, 0xEF, 0x57, 0xDA],
		[0x02, 0x48, 0xD4, 0x38, 0x06, 0xF6, 0x71, 0x72],
		[0x51, 0x45, 0x4B, 0x58, 0x2D, 0xDF, 0x44, 0x0A],
		[0x42, 0xFD, 0x44, 0x30, 0x59, 0x57, 0x7F, 0xA2],
		[0x05, 0x9B, 0x5E, 0x08, 0x51, 0xCF, 0x14, 0x3A],
		[0x07, 0x56, 0xD8, 0xE0, 0x77, 0x47, 0x61, 0xD2],
		[0x76, 0x25, 0x14, 0xB8, 0x29, 0xBF, 0x48, 0x6A],
		[0x3B, 0xDD, 0x11, 0x90, 0x49, 0x37, 0x28, 0x02],
		[0x26, 0x95, 0x5F, 0x68, 0x35, 0xAF, 0x60, 0x9A],
		[0x16, 0x4D, 0x5E, 0x40, 0x4F, 0x27, 0x52, 0x32],
		[0x6B, 0x05, 0x6E, 0x18, 0x75, 0x9F, 0x5C, 0xCA],
		[0x00, 0x4B, 0xD6, 0xEF, 0x09, 0x17, 0x60, 0x62],
		[0x48, 0x0D, 0x39, 0x00, 0x6E, 0xE7, 0x62, 0xF2],
		[0x43, 0x75, 0x40, 0xC8, 0x69, 0x8F, 0x3C, 0xFA],
		[0x07, 0x2D, 0x43, 0xA0, 0x77, 0x07, 0x52, 0x92],
		[0x02, 0xFE, 0x55, 0x77, 0x81, 0x17, 0xF1, 0x2A],
		[0x1D, 0x9D, 0x5C, 0x50, 0x18, 0xF7, 0x28, 0xC2],
		[0x30, 0x55, 0x32, 0x28, 0x6D, 0x6F, 0x29, 0x5A],
	];

	const CIPHERS: [[u8; 8]; 19] = [
		[0x69, 0x0F, 0x5B, 0x0D, 0x9A, 0x26, 0x93, 0x9B],
		[0x7A, 0x38, 0x9D, 0x10, 0x35, 0x4B, 0xD2, 0x71],
		[0x86, 0x8E, 0xBB, 0x51, 0xCA, 0xB4, 0x59, 0x9A],
		[0x71, 0x78, 0x87, 0x6E, 0x01, 0xF1, 0x9B, 0x2A],
		[0xAF, 0x37, 0xFB, 0x42, 0x1F, 0x8C, 0x40, 0x95],
		[0x86, 0xA5, 0x60, 0xF1, 0x0E, 0xC6, 0xD8, 0x5B],
		[0x0C, 0xD3, 0xDA, 0x02, 0x00, 0x21, 0xDC, 0x09],
		[0xEA, 0x67, 0x6B, 0x2C, 0xB7, 0xDB, 0x2B, 0x7A],
		[0xDF, 0xD6, 0x4A, 0x81, 0x5C, 0xAF, 0x1A, 0x0F],
		[0x5C, 0x51, 0x3C, 0x9C, 0x48, 0x86, 0xC0, 0x88],
		[0x0A, 0x2A, 0xEE, 0xAE, 0x3F, 0xF4, 0xAB, 0x77],
		[0xEF, 0x1B, 0xF0, 0x3E, 0x5D, 0xFA, 0x57, 0x5A],
		[0x88, 0xBF, 0x0D, 0xB6, 0xD7, 0x0D, 0xEE, 0x56],
		[0xA1, 0xF9, 0x91, 0x55, 0x41, 0x02, 0x0B, 0x56],
		[0x6F, 0xBF, 0x1C, 0xAF, 0xCF, 0xFD, 0x05, 0x56],
		[0x2F, 0x22, 0xE4, 0x9B, 0xAB, 0x7C, 0xA1, 0xAC],
		[0x5A, 0x6B, 0x61, 0x2C, 0xC2, 0x6C, 0xCE, 0x4A],
		[0x5F, 0x4C, 0x03, 0x8E, 0xD1, 0x2B, 0x2E, 0x41],
		[0x63, 0xFA, 0xC0, 0xD0, 0x34, 0xD9, 0xF7, 0x93],
	];

	/// Test: 19 Key data pairs which exercise every S-box entry
	///
	/// Taken from NBS Special Publication 500-20, 1980.
	/// "Validating the Correctness of Hardware Implementations of the NBS Data Encryption Standard"
	/// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nbsspecialpublication500-20e1980.pdf
	#[test]
	fn nist() {
		for i in 0..KEYS.len() {
			let ciphered = encipher_block(&PLAINS[i], KEYS[i]);
			assert_eq!(ciphered, CIPHERS[i]);

			let deciphered = decipher_block(&ciphered, KEYS[i]);
			assert_eq!(deciphered, PLAINS[i]);
		}
	}

	#[test]
	fn roundtrip_empty() {
		let cipher = DESCipher::new(KEY);
		let encoded = cipher.encode(&[]);
		let decoded = cipher.decode(&encoded).unwrap();
		assert_eq!(decoded, vec![]);
	}

	#[test]
	fn roundtrip_partial_block() {
		let cipher = DESCipher::new(KEY);
		let input = b"hello";
		let encoded = cipher.encode(input);
		assert_eq!(encoded.len(), 8); // padded to one block
		let decoded = cipher.decode(&encoded).unwrap();
		assert_eq!(decoded, input);
	}

	#[test]
	fn roundtrip_exact_block() {
		let cipher = DESCipher::new(KEY);
		let input = b"12345678";
		let encoded = cipher.encode(input);
		assert_eq!(encoded.len(), 16); // needs extra block for padding
		let decoded = cipher.decode(&encoded).unwrap();
		assert_eq!(decoded, input);
	}

	#[test]
	fn roundtrip_multiple_blocks() {
		let cipher = DESCipher::new(KEY);
		let input = b"hello world, this is a longer message!";
		let encoded = cipher.encode(input);
		let decoded = cipher.decode(&encoded).unwrap();
		assert_eq!(decoded, input);
	}

	#[test]
	fn decode_invalid_length() {
		let cipher = DESCipher::new(KEY);
		let result = cipher.decode(&[1, 2, 3]); // not multiple of 8
		assert!(matches!(result, Err(DESDecodeError::InvalidLength)));
	}
}
