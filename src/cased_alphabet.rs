use crate::alphabet::Alphabet;

pub struct CasedAlphabet {
	upper: Alphabet,
	lower: Alphabet,
}

#[derive(Debug)]
pub enum CasedAlphabetError {
	UnsupportedMultiCharacterWideCasing,
}

impl TryFrom<Alphabet> for CasedAlphabet {
	type Error = CasedAlphabetError;

	fn try_from(value: Alphabet) -> Result<Self, Self::Error> {
		let upper = value
			.iter()
			.map(|c| c.to_uppercase())
			.map(to_single_case_character)
			.collect::<Result<Alphabet, _>>()?;

		let lower = value
			.iter()
			.map(|c| c.to_lowercase())
			.map(to_single_case_character)
			.collect::<Result<Alphabet, _>>()?;

		Ok(CasedAlphabet { upper, lower })
	}
}

fn to_single_case_character(
	mut it: impl Iterator<Item = char>,
) -> Result<char, CasedAlphabetError> {
	match (it.next(), it.next()) {
		(Some(ch), None) => Ok(ch),
		_ => Err(CasedAlphabetError::UnsupportedMultiCharacterWideCasing),
	}
}

pub enum Case {
	Upper,
	Lower,
}

impl CasedAlphabet {
	pub fn iter(&self) -> impl Iterator<Item = ((char, Case), (char, Case))> {
		self.into_iter()
	}

	// pub fn index_of(&self, c: char) -> Option<usize> {
	// 	self.0.iter().position(|&x| x == c)
	// }

	// pub fn char_at(&self, index: usize) -> Option<char> {
	// 	self.0.get(index).copied()
	// }
}

impl IntoIterator for CasedAlphabet {
	type Item = ((char, Case), (char, Case));
	type IntoIter = impl Iterator<Item = Self::Item>;

	fn into_iter(self) -> Self::IntoIter {
		self.upper
			.into_iter()
			.map(|c| (c, Case::Upper))
			.zip(self.lower.into_iter().map(|c| (c, Case::Lower)))
	}
}

impl<'a> IntoIterator for &'a CasedAlphabet {
	type Item = ((char, Case), (char, Case));
	type IntoIter = impl Iterator<Item = Self::Item>;

	#[inline]
	fn into_iter(self) -> Self::IntoIter {
		self.upper
			.iter()
			.map(|&c| (c, Case::Upper))
			.zip(self.lower.iter().map(|&c| (c, Case::Lower)))
	}
}
