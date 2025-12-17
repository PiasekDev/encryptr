use std::iter;

use itertools::Itertools;

pub struct PKCS7PaddedData<const CHUNK_SIZE: usize>(Vec<[u8; CHUNK_SIZE]>);

#[derive(Debug)]
pub enum PaddingParseError {
	InvalidDataLength,
	InsufficientDataLength,
	InvalidPaddingByte,
}

impl<const CHUNK_SIZE: usize> PKCS7PaddedData<CHUNK_SIZE> {
	pub fn pad(input: &[u8]) -> Self {
		let padding_len = CHUNK_SIZE - (input.len() % CHUNK_SIZE);
		let padding = iter::repeat_n(padding_len as u8, padding_len);

		input
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

	pub fn try_from_blocks(blocks: Vec<[u8; CHUNK_SIZE]>) -> Result<Self, PaddingParseError> {
		let padding_block = blocks
			.last()
			.ok_or(PaddingParseError::InsufficientDataLength)?;
		let padding_length = padding_block
			.last()
			.map(|&byte| byte as usize)
			.ok_or(PaddingParseError::InsufficientDataLength)?;

		if !(1..=CHUNK_SIZE).contains(&padding_length) {
			return Err(PaddingParseError::InvalidPaddingByte);
		}

		let padding_bytes = padding_block
			.get(CHUNK_SIZE - padding_length..)
			.ok_or(PaddingParseError::InsufficientDataLength)?;

		if !padding_bytes.iter().all(|&x| x as usize == padding_length) {
			return Err(PaddingParseError::InvalidPaddingByte);
		}

		Ok(Self(blocks))
	}

	pub fn into_unpadded(self) -> Vec<u8> {
		let mut data = self.0.into_iter().flatten().collect_vec();
		let padding_length = data
			.last()
			.map(|&byte| byte as usize)
			.expect("the padding to exist");

		data.truncate(data.len() - padding_length);
		data
	}
}

impl<const CHUNK_SIZE: usize> IntoIterator for PKCS7PaddedData<CHUNK_SIZE> {
	type Item = [u8; CHUNK_SIZE];
	type IntoIter = std::vec::IntoIter<[u8; CHUNK_SIZE]>;

	fn into_iter(self) -> Self::IntoIter {
		self.0.into_iter()
	}
}
