use std::iter;

use itertools::Itertools;

pub struct PKCS7PaddedInput<const CHUNK_SIZE: usize>(Vec<[u8; CHUNK_SIZE]>);

impl<const CHUNK_SIZE: usize> From<&[u8]> for PKCS7PaddedInput<CHUNK_SIZE> {
	fn from(value: &[u8]) -> Self {
		let padding_len = CHUNK_SIZE - (value.len() % CHUNK_SIZE);
		let padding = iter::repeat_n(padding_len as u8, padding_len);

		value
			.iter()
			.copied()
			.chain(padding)
			.chunks(CHUNK_SIZE)
			.into_iter()
			.map(|chunk_iter| chunk_iter.collect_array())
			.collect::<Option<_>>()
			.map(Self)
			.expect("the padding to pad correctly")
	}
}

impl<const CHUNK_SIZE: usize> IntoIterator for PKCS7PaddedInput<CHUNK_SIZE> {
	type Item = [u8; CHUNK_SIZE];
	type IntoIter = std::vec::IntoIter<[u8; CHUNK_SIZE]>;

	fn into_iter(self) -> Self::IntoIter {
		self.0.into_iter()
	}
}
