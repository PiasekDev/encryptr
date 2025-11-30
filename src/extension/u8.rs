use std::mem;

use bit_ops::BitOps;

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
