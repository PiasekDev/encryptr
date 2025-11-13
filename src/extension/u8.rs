pub trait PermuteExt {
	fn permute(&self, input: &[u8]) -> Vec<u8>;
}

impl PermuteExt for [u8] {
	fn permute(&self, input: &[u8]) -> Vec<u8> {
		let mut output = vec![0u8; self.len().div_ceil(8)];

		for (i, &pos) in self.iter().enumerate() {
			let b_in = (pos - 1) / 8;
			let k_in = 7 - ((pos - 1) % 8);
			let bit = (input[b_in as usize] >> k_in) & 1;
			let b_out = i / 8;
			let k_out = 7 - (i % 8);
			output[b_out] |= bit << k_out;
		}

		output
	}
}
