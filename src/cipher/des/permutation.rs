use bit_ops::BitOps;

use crate::cipher::des::sequence::ContinuousBitSequence;

/// A compile-time validated DES permutation table.
///
/// # Type Parameters
/// - `INPUT_BITS` (u8): the number of bits in the input domain. This is also
///   the maximum valid position allowed in the table. Table entries must be
///   in the range `1..=INPUT_BITS`. Positions are 1-based and count from the
///   MSB (most-significant bit) in accordance with the DES specification.
/// - `OUTPUT_BITS` (usize): the number of entries in the permutation table —
///   equivalently, the number of bits produced by the permutation.
pub struct PermutationTable<const INPUT_BITS: u8, const OUTPUT_BITS: usize>([u8; OUTPUT_BITS]);

/// Helper macro to define a compile-time validated permutation table.
///
/// Macro form:
/// ```ignore
/// perm_table!(NAME, INPUT_BITS = <n>, [ a, b, c, ... ]);
/// ```
///
/// - `NAME`: identifier for the public `const` to be created.
/// - `INPUT_BITS`: number of bits in the input space (this is also the maximum
///   valid position allowed in the table). Positions in the table are 1-based
///   and count from the MSB (most-significant bit) as per the DES
///   specification. The macro validates at compile time that every entry is in
///   the range `1..=INPUT_BITS`.
/// - The list `[ ... ]` defines the permutation table values (u8 each).
///
/// # Example
/// ```ignore
/// perm_table!(IP, INPUT_BITS = 64, [58, 50, 42, ...]);
/// ```
macro_rules! perm_table {
	($name:ident, INPUT_BITS = $input_bits:expr, [ $($val:expr),* $(,)? ] ) => {
		pub const $name: $crate::cipher::des::permutation::PermutationTable<
			$input_bits,
			{ const OUTPUT_BITS: usize = [$($val),*].len(); OUTPUT_BITS }
		> = $crate::cipher::des::permutation::PermutationTable::new([$($val),*]);
	};
}

pub(crate) use perm_table;

impl<const INPUT_BITS: u8, const OUTPUT_BITS: usize> PermutationTable<INPUT_BITS, OUTPUT_BITS> {
	/// Creates a new `PermutationTable`, validating its contents at compile-time.
	pub const fn new(table: [u8; OUTPUT_BITS]) -> Self {
		let mut i = 0;
		while i < table.len() {
			let pos = table[i];
			assert!(
				1 <= pos && pos <= INPUT_BITS,
				"Permutation table position out of range!"
			);

			i += 1;
		}
		Self(table)
	}
}

/// Implements the `permute` method for a `PermutationTable` with specified input and output bit sizes.
/// # Type Parameters
/// - `INPUT_BITS`: The number of bits given as input to the permutation.
/// - `OUTPUT_BITS`: The number of bits produced as output from the permutation.
macro_rules! perm_table_permute_impl {
	(INPUT_BITS = $INPUT_BITS:expr, OUTPUT_BITS = $OUTPUT_BITS:expr) => {
		impl PermutationTable<$INPUT_BITS, $OUTPUT_BITS> {
			const INPUT_BYTES: usize = $INPUT_BITS / 8;
			const OUTPUT_BYTES: usize = $OUTPUT_BITS / 8;

			/// Apply the permutation described by this table to `input`.
			///
			/// - `input`: fixed-size input array with length `INPUT_BITS/8`.
			/// - Returns: a fixed-size output array with length `OUTPUT_BITS/8`.
			///
			/// Semantics: for each output bit index `i` (0-based, MSB-first),
			/// the table contains a 1-based MSB position `p`. The output bit
			/// `i` is set to the value of the input bit at position `p - 1` (0-based,
			/// MSB-first). The macro-generated method performs this mapping for
			/// every table entry and returns the packed output bytes.
			pub fn permute(&self, input: &[u8; Self::INPUT_BYTES]) -> [u8; Self::OUTPUT_BYTES] {
				let input_bits = ContinuousBitSequence::from(input);
				let mut output_bits = ContinuousBitSequence::from([0u8; Self::OUTPUT_BYTES]);

				for (bit_num, pos) in self.0.iter().map(to_0_based_pos).enumerate() {
					let bit_value = input_bits.get_msb_bit(pos).is_set(0);
					output_bits.set_msb_bit_exact(bit_num as u8, bit_value);
				}

				output_bits.into_inner()
			}
		}
	};
}

fn to_0_based_pos(pos: &u8) -> u8 {
	pos - 1
}

perm_table_permute_impl!(INPUT_BITS = 32, OUTPUT_BITS = 32);
perm_table_permute_impl!(INPUT_BITS = 56, OUTPUT_BITS = 48);
perm_table_permute_impl!(INPUT_BITS = 32, OUTPUT_BITS = 48);
perm_table_permute_impl!(INPUT_BITS = 64, OUTPUT_BITS = 56);
perm_table_permute_impl!(INPUT_BITS = 64, OUTPUT_BITS = 64);
