use crate::extension::char::{CaseConversionError, CharCase, CharExt};

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct CasedChar {
	upper: char,
	lower: char,
}

impl PartialEq<char> for CasedChar {
	fn eq(&self, other: &char) -> bool {
		self.upper == *other || self.lower == *other
	}
}

impl CasedChar {
	pub fn at_case(&self, case: &CharCase) -> char {
		match case {
			CharCase::Upper => self.upper,
			CharCase::Lower => self.lower,
		}
	}
}

impl TryFrom<char> for CasedChar {
	type Error = CaseConversionError;

	fn try_from(value: char) -> Result<Self, Self::Error> {
		let upper = value.to_uppercase_char()?;
		let lower = value.to_lowercase_char()?;

		Ok(CasedChar { upper, lower })
	}
}
