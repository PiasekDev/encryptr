use bit_ops::BitOps;

use crate::cipher::des::sequence::ContinuousBitSequence;

/// A compile-time validated permutation table.
///
/// # Type Parameters
/// - `N`: The length of the table.
/// - `MAX_POS`: The maximum valid bit position (inclusive, MSB, 1-based - in accordance with DES specification) that can be in the table.
pub struct PermutationTable<const N: usize, const MAX_POS: u8>([u8; N]);

impl<const N: usize, const MAX_POS: u8> PermutationTable<N, MAX_POS> {
	/// Creates a new `PermutationTable`, validating its contents at compile-time.
	pub const fn new(table: [u8; N]) -> Self {
		let mut i = 0;
		while i < table.len() {
			let pos = table[i];
			assert!(
				1 <= pos && pos <= MAX_POS,
				"Permutation table position out of range!"
			);

			i += 1;
		}
		Self(table)
	}
}

impl PermutationTable<32, 32> {
	pub fn permute(&self, input: &[u8]) -> [u8; 4] {
		permute::<4>(&self.0, input)
	}
}

impl PermutationTable<40, 40> {
	pub fn permute(&self, input: &[u8]) -> [u8; 5] {
		permute::<5>(&self.0, input)
	}
}

impl PermutationTable<48, 56> {
	pub fn permute(&self, input: &[u8]) -> [u8; 6] {
		permute::<6>(&self.0, input)
	}
}

impl PermutationTable<48, 48> {
	pub fn permute(&self, input: &[u8]) -> [u8; 6] {
		permute::<6>(&self.0, input)
	}
}

impl PermutationTable<48, 32> {
	pub fn permute(&self, input: &[u8]) -> [u8; 6] {
		permute::<6>(&self.0, input)
	}
}

impl PermutationTable<56, 56> {
	pub fn permute(&self, input: &[u8]) -> [u8; 7] {
		permute::<7>(&self.0, input)
	}
}

impl PermutationTable<56, 64> {
	pub fn permute(&self, input: &[u8]) -> [u8; 7] {
		permute::<7>(&self.0, input)
	}
}

impl PermutationTable<64, 64> {
	pub fn permute(&self, input: &[u8]) -> [u8; 8] {
		permute::<8>(&self.0, input)
	}
}

fn permute<const N: usize>(table: &[u8], input: &[u8]) -> [u8; N] {
	let input_bits = ContinuousBitSequence::from(input);
	let mut output_bits = ContinuousBitSequence::from([0u8; N]);

	for (bit_num, pos) in table.iter().map(to_0_based_pos).enumerate() {
		let bit_value = input_bits.get_msb_bit(pos).is_set(0);
		output_bits.set_msb_bit_exact(bit_num as u8, bit_value);
	}

	output_bits.into_inner()
}

fn to_0_based_pos(pos: &u8) -> u8 {
	pos - 1
}
