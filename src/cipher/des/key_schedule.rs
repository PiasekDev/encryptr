use bit_ops::BitOps;

use crate::extension::u8::PermuteExt;

type KeyBits = [u8; 6];

pub struct KeySchedule {
	subkeys: [KeyBits; 16],
}

impl KeySchedule {
	pub fn new(key: [u8; 8]) -> Self {
		let permuted: [u8; 7] = constants::PC_1
			.permute(&key)
			.try_into()
			.expect("The permutation should produce 56 bits");

		let mut c = C::from(&permuted);
		let mut d = D::from(&permuted);

		let mut subkeys = [[0u8; 6]; 16];
		for (i, subkey) in subkeys.iter_mut().enumerate() {
			c.shift_left(constants::SHIFTS[i]);
			d.shift_left(constants::SHIFTS[i]);

			let cd = combine(&c, &d);
			let permuted_subkey: [u8; 6] = constants::PC_2
				.permute(&cd)
				.try_into()
				.expect("The permutation should produce 48 bits");
			*subkey = permuted_subkey;
		}

		KeySchedule { subkeys }
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

		C(u32::from_ne_bytes(bytes))
	}
}

impl C {
	fn shift_left(&mut self, shifts: u8) {
		for _ in 0..shifts {
			let first_bit = self.0.get_bit(31);
			self.0 <<= 1;
			self.0 |= first_bit << 4;
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

		D(u32::from_ne_bytes(bytes))
	}
}

impl D {
	fn shift_left(&mut self, shifts: u8) {
		for _ in 0..shifts {
			let first_bit = self.0.get_bit(27);
			self.0 <<= 1;
			self.0 |= first_bit;
		}
	}
}

fn combine(c: &C, d: &D) -> [u8; 7] {
	let mut cd = [0u8; 7];
	cd[0..4].copy_from_slice(&c.0.to_ne_bytes());
	cd[3..7].copy_from_slice(&d.0.to_ne_bytes());
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
