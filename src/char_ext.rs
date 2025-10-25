pub enum CharCase {
	Upper,
	Lower,
}

pub trait CharExt {
	fn case(&self) -> Option<CharCase>;

	fn at_case(&self, case: &CharCase) -> Option<char>;

	fn to_uppercase_char(&self) -> Option<char>;

	fn to_lowercase_char(&self) -> Option<char>;
}

impl CharExt for char {
	/// Returns the case of the character if it is cased (upper or lower).
	fn case(&self) -> Option<CharCase> {
		match self {
			c if c.is_uppercase() && c.to_uppercase_char().is_some() => Some(CharCase::Upper),
			c if c.is_lowercase() && c.to_lowercase_char().is_some() => Some(CharCase::Lower),
			_ => None,
		}
	}

	/// Returns the character in the specified case if possible.
	fn at_case(&self, case: &CharCase) -> Option<char> {
		match case {
			CharCase::Upper => self.to_uppercase_char(),
			CharCase::Lower => self.to_lowercase_char(),
		}
	}

	/// Converts the character to uppercase if it results in a single character.
	/// Returns `None` if the uppercase conversion results in multiple characters.
	/// Similarly for `to_lowercase_char`.
	/// If the character does not have a case mapping, returns `None`.
	fn to_uppercase_char(&self) -> Option<char> {
		self.to_uppercase().to_single_character()
	}

	fn to_lowercase_char(&self) -> Option<char> {
		self.to_lowercase().to_single_character()
	}
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

// fn to_single_character_case(mut it: impl Iterator<Item = char>) -> Option<char> {
// 	match (it.next(), it.next()) {
// 		(Some(c), None) => Some(c),
// 		_ => None,
// 	}
// }

// pub fn is_single_character_case(mut it: impl Iterator<Item = char>) -> bool {
// 	matches!((it.next(), it.next()), (Some(_), None))
// }
