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

	/// Get `count` bits starting at MSB position `offset`, returned as an LSB-aligned u8
	///
	/// # Examples
	/// ```rust
	/// use encryptr::cipher::des::sequence::ContinuousBitSequence;
	///
	/// let bits = ContinuousBitSequence::new(&[
	///     0b01100001, 0b00010111, 0b10111010, 0b10000110, 0b01100101, 0b00100111,
	/// ]);
	/// assert_eq!(bits.get_msb_bits(6, 0),  0b011000);
	/// assert_eq!(bits.get_msb_bits(6, 6),  0b010001);
	/// assert_eq!(bits.get_msb_bits(6, 12), 0b011110);
	/// assert_eq!(bits.get_msb_bits(6, 18), 0b111010);
	/// assert_eq!(bits.get_msb_bits(6, 24), 0b100001);
	/// assert_eq!(bits.get_msb_bits(6, 30), 0b100110);
	/// assert_eq!(bits.get_msb_bits(6, 36), 0b010100);
	/// assert_eq!(bits.get_msb_bits(6, 42), 0b100111);
	/// ```
	pub fn get_msb_bits(&self, count: u8, offset: u8) -> u8 {
		let bytes = self.0.as_ref();
		let first_byte_index = (offset / 8) as usize;
		let last_byte_index = ((offset + count - 1) / 8) as usize;

		let value_end_msb_pos = (offset + count) % 8;
		let value_end_lsb_pos = (8 - value_end_msb_pos) % 8; // Need to % 8 this, since when value_end_msb_pos is 0, the value ends exactly at a byte boundary and so we want to read from lsb bit 0

		if first_byte_index == last_byte_index {
			// All bits are within a single byte
			bytes[first_byte_index].get_bits(count, value_end_lsb_pos)
		} else {
			// Bits span two bytes
			let bits_in_first_byte = 8 - (offset % 8);
			let bits_in_last_byte = value_end_msb_pos;

			let upper_bits = bytes[first_byte_index].get_bits(bits_in_first_byte, 0);
			let lower_bits = bytes[last_byte_index].get_bits(bits_in_last_byte, value_end_lsb_pos);

			(upper_bits << bits_in_last_byte) | lower_bits
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
