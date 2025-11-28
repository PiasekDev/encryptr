use bit_ops::BitOps;

pub struct ContinuousBitSequence<R>(R)
where
	R: AsRef<[u8]>;

impl<R> ContinuousBitSequence<R>
where
	R: AsRef<[u8]>,
{
	pub fn new(sequence_bytes: R) -> Self {
		Self(sequence_bytes)
	}

	/// Get bit at position `pos`, counting from MSB as position 0
	/// # Examples
	/// ```rust
	/// use encryptr::cipher::des::sequence::ContinuousBitSequence;
	///
	/// let bits = ContinuousBitSequence::new(&[0b10100000, 0b00010000]);
	/// assert_eq!(bits.get_msb_bit(0), 1);
	/// assert_eq!(bits.get_msb_bit(3), 0);
	/// assert_eq!(bits.get_msb_bit(8), 0);
	/// assert_eq!(bits.get_msb_bit(11), 1);
	/// ```
	pub fn get_msb_bit(&self, pos: u8) -> u8 {
		let byte_index = pos / 8;
		let lsb_bit_index = 7 - (pos % 8);
		self.0.as_ref()[byte_index as usize].get_bit(lsb_bit_index)
	}

	pub fn get_msb_bits(&self, value_bits: u8, value_shift: u8) -> u8 {
		let start_byte_index = value_shift / 8;
		let end_byte_index = (value_shift + value_bits - 1) / 8;

		if start_byte_index == end_byte_index {
			// one byte
			// let start_msb_bit = value_shift % 8;
			let end_msb_bit = (value_shift + value_bits) % 8;
			// let start_lsb_bit = 8 - end_msb_bit;
			let end_lsb_bit = (8 - end_msb_bit) % 8;
			self.0.as_ref()[start_byte_index as usize].get_bits(value_bits, end_lsb_bit)
		} else {
			let start_msb_bit = value_shift % 8;
			let end_msb_bit = (value_shift + value_bits) % 8;
			let start_lsb_bit = 8 - end_msb_bit;
			let end_lsb_bit = 8 - start_msb_bit;
			let upper_value = self.0.as_ref()[start_byte_index as usize].get_bits(end_lsb_bit, 0);
			let lower_value =
				self.0.as_ref()[end_byte_index as usize].get_bits(end_msb_bit, start_lsb_bit);
			upper_value << end_msb_bit | lower_value
		}
	}

	pub fn into_inner(self) -> R {
		self.0
	}
}

impl<R> ContinuousBitSequence<R>
where
	R: AsRef<[u8]> + AsMut<[u8]>,
{
	/// Set bit at position `pos`, counting from MSB as position 0
	/// # Examples
	/// ```rust
	/// use encryptr::cipher::des::sequence::ContinuousBitSequence;
	///
	/// let mut bytes = [0b00011111, 0b00000000];
	/// let mut bits = ContinuousBitSequence::new(&mut bytes);
	/// bits.set_msb_bit_exact(0, true);
	/// bits.set_msb_bit_exact(3, false);
	/// bits.set_msb_bit_exact(8, true);
	/// bits.set_msb_bit_exact(11, true);
	/// assert_eq!(bytes, [0b10001111, 0b10010000]);
	/// ```
	pub fn set_msb_bit_exact(&mut self, pos: u8, value: bool) {
		let byte_index = pos / 8;
		let lsb_bit_index = 7 - (pos % 8);

		let mut target_byte = self.0.as_mut()[byte_index as usize];
		target_byte = target_byte.set_bit_exact(lsb_bit_index, value);
		self.0.as_mut()[byte_index as usize] = target_byte;
	}
}

impl<R> From<R> for ContinuousBitSequence<R>
where
	R: AsRef<[u8]>,
{
	fn from(value: R) -> Self {
		Self::new(value)
	}
}

#[cfg(test)]
mod tests {
	use super::ContinuousBitSequence;

	#[test]
	fn test_get_msb_bits() {
		let bits = ContinuousBitSequence::new(&[
			0b01100001, 0b00010111, 0b10111010, 0b10000110, 0b01100101, 0b00100111,
		]);
		assert_eq!(bits.get_msb_bits(6, 0),  0b011000);
		assert_eq!(bits.get_msb_bits(6, 6),  0b010001);
		assert_eq!(bits.get_msb_bits(6, 12), 0b011110);
		assert_eq!(bits.get_msb_bits(6, 18), 0b111010);
		assert_eq!(bits.get_msb_bits(6, 24), 0b100001);
		assert_eq!(bits.get_msb_bits(6, 30), 0b100110);
		assert_eq!(bits.get_msb_bits(6, 36), 0b010100);
		assert_eq!(bits.get_msb_bits(6, 42), 0b100111);
	}
}
