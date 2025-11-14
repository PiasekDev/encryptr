#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CharCase {
	Upper,
	Lower,
}

pub trait CharExt {
	type ConversionError;

	fn case(&self) -> Option<CharCase>;

	fn to_uppercase_char(&self) -> Result<char, Self::ConversionError>;

	fn to_lowercase_char(&self) -> Result<char, Self::ConversionError>;
}

#[derive(Debug)]
pub enum CaseConversionError {
	MultipleCharacters,
	NoCase,
}

impl CharExt for char {
	type ConversionError = CaseConversionError;

	/// Returns the case of the character if it is cased (upper or lower).
	fn case(&self) -> Option<CharCase> {
		match self {
			c if c.is_uppercase() && c.to_uppercase_char().is_ok() => Some(CharCase::Upper),
			c if c.is_lowercase() && c.to_lowercase_char().is_ok() => Some(CharCase::Lower),
			_ => None,
		}
	}

	fn to_uppercase_char(&self) -> Result<char, Self::ConversionError> {
		if has_case(self) {
			self.to_uppercase()
				.to_single_character()
				.ok_or(CaseConversionError::MultipleCharacters)
		} else {
			Err(CaseConversionError::NoCase)
		}
	}

	fn to_lowercase_char(&self) -> Result<char, Self::ConversionError> {
		if has_case(self) {
			self.to_lowercase()
				.to_single_character()
				.ok_or(CaseConversionError::MultipleCharacters)
		} else {
			Err(CaseConversionError::NoCase)
		}
	}
}

fn has_case(c: &char) -> bool {
	c.is_uppercase() || c.is_lowercase()
}

pub trait CharIteratorExt {
	fn to_single_character(&mut self) -> Option<char>;
}

impl<T: Iterator<Item = char>> CharIteratorExt for T {
	fn to_single_character(&mut self) -> Option<char> {
		match (self.next(), self.next()) {
			(Some(c), None) => Some(c),
			_ => None,
		}
	}
}
