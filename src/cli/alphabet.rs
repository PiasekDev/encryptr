//! Alphabet type selection for CLI
//!
//! Provides an enum for selecting between different alphabet types.

use clap::ValueEnum;
use encryptr::alphabet::{Alphabet, CasedChar};

/// Available alphabet types for string ciphers
#[derive(ValueEnum, Clone, Copy, Default, Debug, PartialEq, Eq)]
pub enum AlphabetType {
	/// Standard ASCII uppercase (A-Z, 26 characters)
	#[default]
	Ascii,
	/// Polish alphabet uppercase (32 characters including Polish diacritics)
	Polish,
	/// Case-preserving ASCII alphabet (preserves upper/lower case)
	Cased,
}

impl AlphabetType {
	/// Get the standard (char) alphabet for this type
	///
	/// Note: For Cased alphabet, use `to_cased_alphabet()` instead
	pub fn to_char_alphabet(self) -> Alphabet<char> {
		match self {
			AlphabetType::Ascii | AlphabetType::Cased => Alphabet::ascii_uppercase(),
			AlphabetType::Polish => Alphabet::polish_uppercase(),
		}
	}

	/// Get the cased alphabet
	pub fn to_cased_alphabet(self) -> Alphabet<CasedChar> {
		Alphabet::ascii_cased()
	}

	/// Check if this is the case-preserving alphabet
	pub fn is_cased(self) -> bool {
		matches!(self, AlphabetType::Cased)
	}
}
