//! AES State representation and operations.
//!
//! The AES state is a 4x4 matrix of bytes, arranged in column-major order:
//!
//! ```text
//! | s0,0  s0,1  s0,2  s0,3 |
//! | s1,0  s1,1  s1,2  s1,3 |
//! | s2,0  s2,1  s2,2  s2,3 |
//! | s3,0  s3,1  s3,2  s3,3 |
//! ```
//!
//! Where the input block bytes [b0, b1, ..., b15] map to:
//! - Column 0: b0, b1, b2, b3
//! - Column 1: b4, b5, b6, b7
//! - Column 2: b8, b9, b10, b11
//! - Column 3: b12, b13, b14, b15

use super::constants::{INV_S_BOX, S_BOX};

/// The AES state: a 4x4 byte matrix stored in column-major order.
///
/// `state[col][row]` accesses the byte at the given column and row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct State([[u8; 4]; 4]);

impl State {
	/// Creates a new State from a 16-byte block.
	///
	/// The bytes are arranged in column-major order:
	/// bytes 0-3 become column 0, bytes 4-7 become column 1, etc.
	pub fn from_block(block: &[u8; 16]) -> Self {
		let mut state = [[0u8; 4]; 4];
		for col in 0..4 {
			for row in 0..4 {
				state[col][row] = block[col * 4 + row];
			}
		}
		State(state)
	}

	/// Converts the State back into a 16-byte block.
	pub fn into_block(self) -> [u8; 16] {
		let mut block = [0u8; 16];
		for col in 0..4 {
			for row in 0..4 {
				block[col * 4 + row] = self.0[col][row];
			}
		}
		block
	}

	/// SubBytes transformation: applies the S-box to each byte.
	///
	/// This provides non-linearity in the cipher.
	/// FIPS 197, Section 5.1.1
	pub fn sub_bytes(&mut self) {
		for col in 0..4 {
			for row in 0..4 {
				self.0[col][row] = S_BOX[self.0[col][row] as usize];
			}
		}
	}

	/// InvSubBytes transformation: applies the inverse S-box to each byte.
	///
	/// FIPS 197, Section 5.3.2
	pub fn inv_sub_bytes(&mut self) {
		for col in 0..4 {
			for row in 0..4 {
				self.0[col][row] = INV_S_BOX[self.0[col][row] as usize];
			}
		}
	}

	/// ShiftRows transformation: cyclically shifts rows to the left.
	///
	/// - Row 0: no shift
	/// - Row 1: shift left by 1
	/// - Row 2: shift left by 2
	/// - Row 3: shift left by 3
	///
	/// FIPS 197, Section 5.1.2
	pub fn shift_rows(&mut self) {
		// Row 1: shift left by 1
		let temp = self.0[0][1];
		self.0[0][1] = self.0[1][1];
		self.0[1][1] = self.0[2][1];
		self.0[2][1] = self.0[3][1];
		self.0[3][1] = temp;

		// Row 2: shift left by 2
		let temp0 = self.0[0][2];
		let temp1 = self.0[1][2];
		self.0[0][2] = self.0[2][2];
		self.0[1][2] = self.0[3][2];
		self.0[2][2] = temp0;
		self.0[3][2] = temp1;

		// Row 3: shift left by 3 (same as shift right by 1)
		let temp = self.0[3][3];
		self.0[3][3] = self.0[2][3];
		self.0[2][3] = self.0[1][3];
		self.0[1][3] = self.0[0][3];
		self.0[0][3] = temp;
	}

	/// InvShiftRows transformation: cyclically shifts rows to the right.
	///
	/// - Row 0: no shift
	/// - Row 1: shift right by 1
	/// - Row 2: shift right by 2
	/// - Row 3: shift right by 3
	///
	/// FIPS 197, Section 5.3.1
	pub fn inv_shift_rows(&mut self) {
		// Row 1: shift right by 1
		let temp = self.0[3][1];
		self.0[3][1] = self.0[2][1];
		self.0[2][1] = self.0[1][1];
		self.0[1][1] = self.0[0][1];
		self.0[0][1] = temp;

		// Row 2: shift right by 2
		let temp0 = self.0[0][2];
		let temp1 = self.0[1][2];
		self.0[0][2] = self.0[2][2];
		self.0[1][2] = self.0[3][2];
		self.0[2][2] = temp0;
		self.0[3][2] = temp1;

		// Row 3: shift right by 3 (same as shift left by 1)
		let temp = self.0[0][3];
		self.0[0][3] = self.0[1][3];
		self.0[1][3] = self.0[2][3];
		self.0[2][3] = self.0[3][3];
		self.0[3][3] = temp;
	}

	/// MixColumns transformation: mixes the bytes in each column.
	///
	/// Each column is treated as a polynomial over GF(2^8) and multiplied
	/// by a fixed polynomial a(x) = {03}x^3 + {01}x^2 + {01}x + {02}.
	///
	/// FIPS 197, Section 5.1.3
	pub fn mix_columns(&mut self) {
		for col in 0..4 {
			let s0 = self.0[col][0];
			let s1 = self.0[col][1];
			let s2 = self.0[col][2];
			let s3 = self.0[col][3];

			// The MixColumns matrix multiplication in GF(2^8):
			// [02 03 01 01]   [s0]
			// [01 02 03 01] * [s1]
			// [01 01 02 03]   [s2]
			// [03 01 01 02]   [s3]
			self.0[col][0] = gf_mul(0x02, s0) ^ gf_mul(0x03, s1) ^ s2 ^ s3;
			self.0[col][1] = s0 ^ gf_mul(0x02, s1) ^ gf_mul(0x03, s2) ^ s3;
			self.0[col][2] = s0 ^ s1 ^ gf_mul(0x02, s2) ^ gf_mul(0x03, s3);
			self.0[col][3] = gf_mul(0x03, s0) ^ s1 ^ s2 ^ gf_mul(0x02, s3);
		}
	}

	/// InvMixColumns transformation: inverse of MixColumns.
	///
	/// Each column is multiplied by the inverse polynomial
	/// a^-1(x) = {0b}x^3 + {0d}x^2 + {09}x + {0e}.
	///
	/// FIPS 197, Section 5.3.3
	pub fn inv_mix_columns(&mut self) {
		for col in 0..4 {
			let s0 = self.0[col][0];
			let s1 = self.0[col][1];
			let s2 = self.0[col][2];
			let s3 = self.0[col][3];

			// The InvMixColumns matrix multiplication in GF(2^8):
			// [0e 0b 0d 09]   [s0]
			// [09 0e 0b 0d] * [s1]
			// [0d 09 0e 0b]   [s2]
			// [0b 0d 09 0e]   [s3]
			self.0[col][0] =
				gf_mul(0x0e, s0) ^ gf_mul(0x0b, s1) ^ gf_mul(0x0d, s2) ^ gf_mul(0x09, s3);
			self.0[col][1] =
				gf_mul(0x09, s0) ^ gf_mul(0x0e, s1) ^ gf_mul(0x0b, s2) ^ gf_mul(0x0d, s3);
			self.0[col][2] =
				gf_mul(0x0d, s0) ^ gf_mul(0x09, s1) ^ gf_mul(0x0e, s2) ^ gf_mul(0x0b, s3);
			self.0[col][3] =
				gf_mul(0x0b, s0) ^ gf_mul(0x0d, s1) ^ gf_mul(0x09, s2) ^ gf_mul(0x0e, s3);
		}
	}

	/// AddRoundKey transformation: XORs the state with a round key.
	///
	/// FIPS 197, Section 5.1.4
	pub fn add_round_key(&mut self, round_key: &[u8; 16]) {
		for col in 0..4 {
			for row in 0..4 {
				self.0[col][row] ^= round_key[col * 4 + row];
			}
		}
	}
}

/// Multiplication in GF(2^8) with the AES irreducible polynomial
/// m(x) = x^8 + x^4 + x^3 + x + 1 (0x11b).
///
/// This is the "xtime" operation when a = 2, and uses the Russian peasant
/// multiplication algorithm for general a.
fn gf_mul(a: u8, b: u8) -> u8 {
	let mut result = 0u8;
	let mut a = a;
	let mut b = b;

	while a != 0 {
		if a & 1 != 0 {
			result ^= b;
		}
		a >>= 1;
		// xtime operation: multiply b by x (i.e., by 2) in GF(2^8)
		let high_bit = b & 0x80;
		b <<= 1;
		if high_bit != 0 {
			b ^= 0x1b; // Reduce by the irreducible polynomial
		}
	}

	result
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn state_from_block_and_back() {
		let block: [u8; 16] = [
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
			0xee, 0xff,
		];
		let state = State::from_block(&block);
		let result = state.into_block();
		assert_eq!(result, block);
	}

	#[test]
	fn sub_bytes_known_values() {
		// Test with known S-box values
		let block: [u8; 16] = [
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
			0x0e, 0x0f,
		];
		let mut state = State::from_block(&block);
		state.sub_bytes();
		let result = state.into_block();

		// S_BOX[0x00] = 0x63, S_BOX[0x01] = 0x7c, etc.
		assert_eq!(result[0], 0x63);
		assert_eq!(result[1], 0x7c);
		assert_eq!(result[2], 0x77);
		assert_eq!(result[3], 0x7b);
	}

	#[test]
	fn sub_bytes_inv_sub_bytes_roundtrip() {
		let block: [u8; 16] = [
			0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
			0x07, 0x34,
		];
		let mut state = State::from_block(&block);
		state.sub_bytes();
		state.inv_sub_bytes();
		assert_eq!(state.into_block(), block);
	}

	#[test]
	fn shift_rows_inv_shift_rows_roundtrip() {
		let block: [u8; 16] = [
			0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
			0x07, 0x34,
		];
		let mut state = State::from_block(&block);
		state.shift_rows();
		state.inv_shift_rows();
		assert_eq!(state.into_block(), block);
	}

	#[test]
	fn mix_columns_inv_mix_columns_roundtrip() {
		let block: [u8; 16] = [
			0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
			0x07, 0x34,
		];
		let mut state = State::from_block(&block);
		state.mix_columns();
		state.inv_mix_columns();
		assert_eq!(state.into_block(), block);
	}

	#[test]
	fn gf_mul_known_values() {
		// Test multiplication by 2 (xtime)
		assert_eq!(gf_mul(0x02, 0x57), 0xae);
		assert_eq!(gf_mul(0x02, 0xae), 0x47); // 0xae * 2 with reduction

		// Test multiplication by 3
		assert_eq!(gf_mul(0x03, 0x57), 0xf9); // 0x57 * 3 = 0x57 * 2 XOR 0x57

		// Test commutativity
		assert_eq!(gf_mul(0x57, 0x83), gf_mul(0x83, 0x57));

		// Test identity
		assert_eq!(gf_mul(0x01, 0x57), 0x57);
		assert_eq!(gf_mul(0x57, 0x01), 0x57);

		// Test zero
		assert_eq!(gf_mul(0x00, 0x57), 0x00);
		assert_eq!(gf_mul(0x57, 0x00), 0x00);
	}

	#[test]
	fn shift_rows_known_values() {
		// From FIPS 197 example
		// Input state (column-major):
		// d4 e0 b8 1e
		// 27 bf b4 41
		// 11 98 5d 52
		// ae f1 e5 30
		let block: [u8; 16] = [
			0xd4, 0x27, 0x11, 0xae, // col 0
			0xe0, 0xbf, 0x98, 0xf1, // col 1
			0xb8, 0xb4, 0x5d, 0xe5, // col 2
			0x1e, 0x41, 0x52, 0x30, // col 3
		];

		let mut state = State::from_block(&block);
		state.shift_rows();
		let result = state.into_block();

		// Expected after ShiftRows:
		// d4 e0 b8 1e  (row 0: no shift)
		// bf b4 41 27  (row 1: shift left 1)
		// 5d 52 11 98  (row 2: shift left 2)
		// 30 ae f1 e5  (row 3: shift left 3)
		let expected: [u8; 16] = [
			0xd4, 0xbf, 0x5d, 0x30, // col 0
			0xe0, 0xb4, 0x52, 0xae, // col 1
			0xb8, 0x41, 0x11, 0xf1, // col 2
			0x1e, 0x27, 0x98, 0xe5, // col 3
		];
		assert_eq!(result, expected);
	}

	#[test]
	fn mix_columns_known_values() {
		// From FIPS 197 example
		// Input state (after ShiftRows):
		// d4 e0 b8 1e
		// bf b4 41 27
		// 5d 52 11 98
		// 30 ae f1 e5
		let block: [u8; 16] = [
			0xd4, 0xbf, 0x5d, 0x30, // col 0
			0xe0, 0xb4, 0x52, 0xae, // col 1
			0xb8, 0x41, 0x11, 0xf1, // col 2
			0x1e, 0x27, 0x98, 0xe5, // col 3
		];

		let mut state = State::from_block(&block);
		state.mix_columns();
		let result = state.into_block();

		// Expected after MixColumns:
		// 04 e0 48 28
		// 66 cb f8 06
		// 81 19 d3 26
		// e5 9a 7a 4c
		let expected: [u8; 16] = [
			0x04, 0x66, 0x81, 0xe5, // col 0
			0xe0, 0xcb, 0x19, 0x9a, // col 1
			0x48, 0xf8, 0xd3, 0x7a, // col 2
			0x28, 0x06, 0x26, 0x4c, // col 3
		];
		assert_eq!(result, expected);
	}

	#[test]
	fn add_round_key_known_values() {
		let block: [u8; 16] = [
			0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
			0x07, 0x34,
		];
		let key: [u8; 16] = [
			0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
			0x4f, 0x3c,
		];

		let mut state = State::from_block(&block);
		state.add_round_key(&key);
		let result = state.into_block();

		// XOR of each byte
		let expected: [u8; 16] = [
			0x32 ^ 0x2b,
			0x43 ^ 0x7e,
			0xf6 ^ 0x15,
			0xa8 ^ 0x16,
			0x88 ^ 0x28,
			0x5a ^ 0xae,
			0x30 ^ 0xd2,
			0x8d ^ 0xa6,
			0x31 ^ 0xab,
			0x31 ^ 0xf7,
			0x98 ^ 0x15,
			0xa2 ^ 0x88,
			0xe0 ^ 0x09,
			0x37 ^ 0xcf,
			0x07 ^ 0x4f,
			0x34 ^ 0x3c,
		];
		assert_eq!(result, expected);
	}

	#[test]
	fn add_round_key_self_inverse() {
		let block: [u8; 16] = [
			0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
			0x07, 0x34,
		];
		let key: [u8; 16] = [
			0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
			0x4f, 0x3c,
		];

		let mut state = State::from_block(&block);
		state.add_round_key(&key);
		state.add_round_key(&key); // Apply twice = identity
		assert_eq!(state.into_block(), block);
	}
}
