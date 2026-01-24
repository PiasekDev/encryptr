use std::iter;

use itertools::Itertools;

pub struct PKCS7PaddedData<const CHUNK_SIZE: usize>(Vec<[u8; CHUNK_SIZE]>);

#[derive(Debug)]
pub enum PaddingParseError {
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

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn pad_empty_input() {
		let padded = PKCS7PaddedData::<8>::pad(&[]);
		let blocks: Vec<_> = padded.into_iter().collect();
		assert_eq!(blocks.len(), 1);
		assert_eq!(blocks[0], [8, 8, 8, 8, 8, 8, 8, 8]); // full block of 0x08
	}

	#[test]
	fn pad_partial_block() {
		let padded = PKCS7PaddedData::<8>::pad(&[1, 2, 3]);
		let blocks: Vec<_> = padded.into_iter().collect();
		assert_eq!(blocks.len(), 1);
		assert_eq!(blocks[0], [1, 2, 3, 5, 5, 5, 5, 5]); // 5 bytes of padding
	}

	#[test]
	fn pad_exact_block() {
		let padded = PKCS7PaddedData::<8>::pad(&[1, 2, 3, 4, 5, 6, 7, 8]);
		let blocks: Vec<_> = padded.into_iter().collect();
		assert_eq!(blocks.len(), 2);
		assert_eq!(blocks[0], [1, 2, 3, 4, 5, 6, 7, 8]);
		assert_eq!(blocks[1], [8, 8, 8, 8, 8, 8, 8, 8]); // full padding block
	}

	#[test]
	fn pad_one_byte_short() {
		let padded = PKCS7PaddedData::<8>::pad(&[1, 2, 3, 4, 5, 6, 7]);
		let blocks: Vec<_> = padded.into_iter().collect();
		assert_eq!(blocks.len(), 1);
		assert_eq!(blocks[0], [1, 2, 3, 4, 5, 6, 7, 1]); // 1 byte of padding
	}

	#[test]
	fn try_from_blocks_valid() {
		let blocks = vec![[1, 2, 3, 4, 5, 3, 3, 3]]; // 3 bytes padding
		let result = PKCS7PaddedData::<8>::try_from_blocks(blocks);
		assert!(result.is_ok());
	}

	#[test]
	fn try_from_blocks_empty() {
		let blocks: Vec<[u8; 8]> = vec![];
		let result = PKCS7PaddedData::<8>::try_from_blocks(blocks);
		assert!(matches!(
			result,
			Err(PaddingParseError::InsufficientDataLength)
		));
	}

	#[test]
	fn try_from_blocks_invalid_padding_zero() {
		let blocks = vec![[1, 2, 3, 4, 5, 6, 7, 0]]; // 0 is invalid
		let result = PKCS7PaddedData::<8>::try_from_blocks(blocks);
		assert!(matches!(result, Err(PaddingParseError::InvalidPaddingByte)));
	}

	#[test]
	fn try_from_blocks_invalid_padding_too_large() {
		let blocks = vec![[1, 2, 3, 4, 5, 6, 7, 9]]; // 9 > CHUNK_SIZE
		let result = PKCS7PaddedData::<8>::try_from_blocks(blocks);
		assert!(matches!(result, Err(PaddingParseError::InvalidPaddingByte)));
	}

	#[test]
	fn try_from_blocks_inconsistent_padding() {
		let blocks = vec![[1, 2, 3, 4, 5, 3, 2, 3]]; // should be [3, 3, 3] but middle is 2
		let result = PKCS7PaddedData::<8>::try_from_blocks(blocks);
		assert!(matches!(result, Err(PaddingParseError::InvalidPaddingByte)));
	}

	#[test]
	fn into_unpadded_removes_padding() {
		let padded = PKCS7PaddedData::<8>::pad(&[1, 2, 3, 4, 5]);
		let unpadded = padded.into_unpadded();
		assert_eq!(unpadded, vec![1, 2, 3, 4, 5]);
	}

	#[test]
	fn into_unpadded_empty_input() {
		let padded = PKCS7PaddedData::<8>::pad(&[]);
		let unpadded = padded.into_unpadded();
		assert_eq!(unpadded, vec![]);
	}

	#[test]
	fn roundtrip_via_blocks() {
		let input = b"hello world";
		let padded = PKCS7PaddedData::<8>::pad(input);
		let blocks: Vec<_> = padded.into_iter().collect();

		let reparsed = PKCS7PaddedData::<8>::try_from_blocks(blocks).unwrap();
		assert_eq!(reparsed.into_unpadded(), input.to_vec());
	}

	#[test]
	fn roundtrip_various_lengths() {
		for len in 0..=24 {
			let input: Vec<u8> = (0..len).map(|i| i as u8).collect();
			let padded = PKCS7PaddedData::<8>::pad(&input);
			let blocks: Vec<_> = padded.into_iter().collect();

			let reparsed = PKCS7PaddedData::<8>::try_from_blocks(blocks).unwrap();
			assert_eq!(reparsed.into_unpadded(), input, "failed for len={}", len);
		}
	}
}
