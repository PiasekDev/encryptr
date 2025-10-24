#![feature(impl_trait_in_assoc_type)]

pub mod cipher {
	pub mod caesar;
	pub mod affine;
	pub mod substitution;
	pub mod vigenere;
}

pub mod alphabet;
pub mod cased_alphabet;
