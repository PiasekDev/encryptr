mod r#static;
pub use r#static::*;

mod dynamic;
pub use dynamic::*;

mod cased_char;
pub use cased_char::*;

mod index;
pub use index::*;

pub trait Alphabet: IntoIterator<Item = Self::Character> {
	type Character;

	fn len(&self) -> usize;

	fn is_empty(&self) -> bool;

	fn iter(&self) -> impl Iterator<Item = &Self::Character>;

	fn position_of(&self, char: char) -> Option<usize>;

	fn char_at(&self, index: usize) -> Option<&Self::Character>;
}
