pub trait PermuteExt<const N: usize> {
	fn permute(&self, input: &[u8]) -> PermutedBytes<N>;
}

pub struct PermutedBytes<const N: usize>([u8; N]);

impl<const N: usize> PermutedBytes<N> {
	pub fn into_inner(self) -> [u8; N] {
		self.0
	}
}

impl PermuteExt<6> for [u8; 48] {
	fn permute(&self, input: &[u8]) -> PermutedBytes<6> {
		let mut output = [0u8; 6];

		for (i, &pos) in self.iter().enumerate() {
			let b_in = (pos - 1) / 8;
			let k_in = 7 - ((pos - 1) % 8);
			let bit = (input[b_in as usize] >> k_in) & 1;
			let b_out = i / 8;
			let k_out = 7 - (i % 8);
			output[b_out] |= bit << k_out;
		}

		PermutedBytes(output)
	}
}

impl PermuteExt<7> for [u8; 56] {
	fn permute(&self, input: &[u8]) -> PermutedBytes<7> {
		let mut output = [0u8; 7];

		for (i, &pos) in self.iter().enumerate() {
			let b_in = (pos - 1) / 8;
			let k_in = 7 - ((pos - 1) % 8);
			let bit = (input[b_in as usize] >> k_in) & 1;
			let b_out = i / 8;
			let k_out = 7 - (i % 8);
			output[b_out] |= bit << k_out;
		}

		PermutedBytes(output)
	}
}

impl PermuteExt<8> for [u8; 64] {
	fn permute(&self, input: &[u8]) -> PermutedBytes<8> {
		let mut output = [0u8; 8];

		for (i, &pos) in self.iter().enumerate() {
			let b_in = (pos - 1) / 8;
			let k_in = 7 - ((pos - 1) % 8);
			let bit = (input[b_in as usize] >> k_in) & 1;
			let b_out = i / 8;
			let k_out = 7 - (i % 8);
			output[b_out] |= bit << k_out;
		}

		PermutedBytes(output)
	}
}
