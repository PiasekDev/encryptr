use std::mem;

use bit_ops::BitOps;

pub trait PermuteExt<const N: usize> {
	fn permute(&self, input: &[u8]) -> [u8; N];
}

impl PermuteExt<4> for [u8; 32] {
	fn permute(&self, input: &[u8]) -> [u8; 4] {
		permute::<4>(self, input)
	}
}

impl PermuteExt<5> for [u8; 40] {
	fn permute(&self, input: &[u8]) -> [u8; 5] {
		permute::<5>(self, input)
	}
}

impl PermuteExt<6> for [u8; 48] {
	fn permute(&self, input: &[u8]) -> [u8; 6] {
		permute::<6>(self, input)
	}
}

impl PermuteExt<7> for [u8; 56] {
	fn permute(&self, input: &[u8]) -> [u8; 7] {
		permute::<7>(self, input)
	}
}

impl PermuteExt<8> for [u8; 64] {
	fn permute(&self, input: &[u8]) -> [u8; 8] {
		permute::<8>(self, input)
	}
}

fn permute<const N: usize>(table: &[u8], input: &[u8]) -> [u8; N] {
	let mut output = [0u8; N];

	for (i, &pos) in table.iter().enumerate() {
		let b_in = (pos - 1) / 8;
		let k_in = 7 - ((pos - 1) % 8);
		let bit = (input[b_in as usize] >> k_in) & 1;
		let b_out = i / 8;
		let k_out = 7 - (i % 8);
		output[b_out] |= bit << k_out;
	}

	output
}

pub trait ToHalvesExt<const N: usize> {
	fn to_halves(self) -> ([u8; N], [u8; N]);
}

impl ToHalvesExt<4> for [u8; 8] {
	fn to_halves(self) -> ([u8; 4], [u8; 4]) {
		unsafe { mem::transmute(self) }
	}
}

pub trait ToBitChunks {
	fn to_bit_chunks<const N: usize>(self) -> [u8; N];
}

pub trait BitByBitAdditionMod2 {
	fn xor(&self, other: &Self) -> Self;
}

impl<const N: usize> BitByBitAdditionMod2 for [u8; N] {
	fn xor(&self, other: &Self) -> Self {
		let mut result = [0u8; N];
		for i in 0..N {
			result[i] = self[i] ^ other[i];
		}
		result
	}
}

pub trait SelectExt {
	fn select(&self, input: u8) -> u8;
}

impl SelectExt for [[u8; 16]; 4] {
	fn select(&self, input: u8) -> u8 {
		let first_bit = input.get_bit(5);
		let last_bit = input.get_bit(0);
		let row = (first_bit << 1) | last_bit;
		let column = input.get_bits(4, 1);
		self[row as usize][column as usize]
	}
}
