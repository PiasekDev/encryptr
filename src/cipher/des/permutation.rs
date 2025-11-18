use bit_ops::BitOps;

use crate::cipher::des::sequence::ContinuousBitSequence;

/// A compile-time validated permutation table.
///
/// # Type Parameters
/// - `N`: The length of the table.
/// - `MAX_POS`: The maximum valid bit position (inclusive, MSB, 1-based - in accordance with DES specification) that can be in the table.
pub struct PermutationTable<const N: usize, const MAX_POS: u8>([u8; N]);

/// Helper macro to define a validated permutation table of an inferred length.
///
/// Usage: perm_table!(CONST_NAME, MaxValue, [ ... data ... ]);
macro_rules! perm_table {
	($name:ident, $max:expr, [ $($val:expr),* $(,)? ] ) => {
		pub const $name: $crate::cipher::des::permutation::PermutationTable<{[$($val),*].len()}, $max> =
			$crate::cipher::des::permutation::PermutationTable::new([$($val),*]);
	};
}

pub(crate) use perm_table;

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

macro_rules! perm_table_impl {
	($N:expr, $MAX:expr) => {
		impl PermutationTable<$N, $MAX> {
			const N: usize = $N / 8;

			pub fn permute(&self, input: &[u8]) -> [u8; Self::N] {
				permute::<{ Self::N }>(&self.0, input)
			}
		}
	};
}

perm_table_impl!(32, 32);
perm_table_impl!(48, 56);
perm_table_impl!(48, 32);
perm_table_impl!(56, 64);
perm_table_impl!(64, 64);

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
