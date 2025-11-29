use bit_ops::BitOps;

use crate::extension::u8::PermuteExt;

pub type KeyBits = [u8; 6];

pub struct KeySchedule {
	subkeys: [KeyBits; 16],
}

impl KeySchedule {
	pub fn new(key: [u8; 8]) -> Self {
		let permuted: [u8; 7] = constants::PC_1.permute(&key);

		let mut c = C::from(&permuted);
		let mut d = D::from(&permuted);

		let mut subkeys = [[0u8; 6]; 16];
		for (i, subkey) in subkeys.iter_mut().enumerate() {
			c.shift_left(constants::SHIFTS[i]);
			d.shift_left(constants::SHIFTS[i]);

			let cd = combine(&c, &d);
			let permuted_subkey: [u8; 6] = constants::PC_2.permute(&cd);
			*subkey = permuted_subkey;
		}

		KeySchedule { subkeys }
	}

	pub fn reversed(mut self) -> Self {
		self.subkeys.reverse();
		self
	}
}

impl IntoIterator for KeySchedule {
	type Item = KeyBits;
	type IntoIter = std::array::IntoIter<KeyBits, 16>;

	fn into_iter(self) -> Self::IntoIter {
		self.subkeys.into_iter()
	}
}

/// C part of the key
/// 32 bits (but only 28 used)
/// The rightmost 4 bits are unused and should be treated as garbage data
struct C(u32);

impl From<&[u8; 7]> for C {
	fn from(value: &[u8; 7]) -> Self {
		let bytes: [u8; 4] = (&value[0..4])
			.try_into()
			.expect("Slice with incorrect length");

		C(u32::from_be_bytes(bytes))
	}
}

impl C {
	fn shift_left(&mut self, shifts: u8) {
		for _ in 0..shifts {
			let first_bit = self.0.get_bit(31).is_set(0);
			self.0 <<= 1;
			self.0 = self.0.set_bit_exact(4, first_bit);
		}
	}
}

/// D part of the key
/// 32 bits (but only 28 used)
/// The leftmost 4 bits are unused and should be treated as garbage data
struct D(u32);

impl From<&[u8; 7]> for D {
	fn from(value: &[u8; 7]) -> Self {
		let bytes: [u8; 4] = (&value[3..7])
			.try_into()
			.expect("Slice with incorrect length");

		D(u32::from_be_bytes(bytes))
	}
}

impl D {
	fn shift_left(&mut self, shifts: u8) {
		for _ in 0..shifts {
			let first_bit = self.0.get_bit(27).is_set(0);
			self.0 <<= 1;
			self.0 = self.0.set_bit_exact(0, first_bit);
		}
	}
}

fn combine(c: &C, d: &D) -> [u8; 7] {
	let mut cd = [0u8; 7];
	cd[0..3].copy_from_slice(&c.0.to_be_bytes()[..3]);
	cd[3] |= (c.0.get_bits(4, 4) as u8) << 4;
	cd[3] |= d.0.get_bits(4, 3 * 8) as u8;
	cd[4..7].copy_from_slice(&d.0.to_be_bytes()[1..]);
	cd
}

mod constants {
	pub const PC_1: [u8; 56] = [
		57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3,
		60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45,
		37, 29, 21, 13, 5, 28, 20, 12, 4,
	];

	pub const PC_2: [u8; 48] = [
		14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41,
		52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
	];

	pub const SHIFTS: [u8; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
}

#[cfg(test)]
mod tests {
	use super::*;

	const KEY: [u8; 8] = [
		0b00010011, 0b00110100, 0b01010111, 0b01111001, 0b10011011, 0b10111100, 0b11011111,
		0b11110001,
	];

	const EXPECTED_SUBKEYS: [[u8; 6]; 16] = [
		[
			0b00011011, 0b00000010, 0b11101111, 0b11111100, 0b01110000, 0b01110010,
		],
		[
			0b01111001, 0b10101110, 0b11011001, 0b11011011, 0b11001001, 0b11100101,
		],
		[
			0b01010101, 0b11111100, 0b10001010, 0b01000010, 0b11001111, 0b10011001,
		],
		[
			0b01110010, 0b10101101, 0b11010110, 0b11011011, 0b00110101, 0b00011101,
		],
		[
			0b01111100, 0b11101100, 0b00000111, 0b11101011, 0b01010011, 0b10101000,
		],
		[
			0b01100011, 0b10100101, 0b00111110, 0b01010000, 0b01111011, 0b00101111,
		],
		[
			0b11101100, 0b10000100, 0b10110111, 0b11110110, 0b00011000, 0b10111100,
		],
		[
			0b11110111, 0b10001010, 0b00111010, 0b11000001, 0b00111011, 0b11111011,
		],
		[
			0b11100000, 0b11011011, 0b11101011, 0b11101101, 0b11100111, 0b10000001,
		],
		[
			0b10110001, 0b11110011, 0b01000111, 0b10111010, 0b01000110, 0b01001111,
		],
		[
			0b00100001, 0b01011111, 0b11010011, 0b11011110, 0b11010011, 0b10000110,
		],
		[
			0b01110101, 0b01110001, 0b11110101, 0b10010100, 0b01100111, 0b11101001,
		],
		[
			0b10010111, 0b11000101, 0b11010001, 0b11111010, 0b10111010, 0b01000001,
		],
		[
			0b01011111, 0b01000011, 0b10110111, 0b11110010, 0b11100111, 0b00111010,
		],
		[
			0b10111111, 0b10010001, 0b10001101, 0b00111101, 0b00111111, 0b00001010,
		],
		[
			0b11001011, 0b00111101, 0b10001011, 0b00001110, 0b00010111, 0b11110101,
		],
	];

	#[test]
	fn test_key_schedule() {
		let key_schedule = KeySchedule::new(KEY);
		for (i, subkey) in key_schedule.subkeys.iter().enumerate() {
			assert_eq!(*subkey, EXPECTED_SUBKEYS[i]);
		}
	}
}
