pub struct DESCipher {
	key: [u8; 8],
}

impl DESCipher {
	pub fn new(key: [u8; 8]) -> Self {
		DESCipher { key }
	}

	pub fn encode(&self, input: &[u8]) -> Vec<u8> {
		let _permuted = constants::IP.permute(input);
		vec![]
	}

	pub fn decode(&self, _input: &[u8]) -> Vec<u8> {
		// Placeholder for DES decoding logic
		vec![]
	}
}

struct KeySchedule {
	subkeys: Vec<[u8; 6]>,
}

mod constants {
	pub const IP: [usize; 64] = [
		58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14,
		6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11,
		3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
	];

	pub const IP_INV: [usize; 64] = [
		40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62,
		30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19,
		59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
	];

	pub const PC_1: [usize; 56] = [
		57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3,
		60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45,
		37, 29, 21, 13, 5, 28, 20, 12, 4,
	];

	pub const PC_2: [usize; 48] = [
		14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41,
		52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
	];
}

pub trait PermuteExt {
	fn permute(&self, input: &[u8]) -> Vec<u8>;
}

impl PermuteExt for [usize] {
	fn permute(&self, input: &[u8]) -> Vec<u8> {
		let mut output = vec![0u8; self.len().div_ceil(8)];

		for (i, &pos) in self.iter().enumerate() {
			let b_in = (pos - 1) / 8;
			let k_in = 7 - ((pos - 1) % 8);
			let bit = (input[b_in] >> k_in) & 1;
			let b_out = i / 8;
			let k_out = 7 - (i % 8);
			output[b_out] |= bit << k_out;
		}

		output
	}
}
