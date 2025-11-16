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
