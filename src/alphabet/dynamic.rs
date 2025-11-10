use crate::alphabet::Alphabet;

pub struct DynamicAlphabet<T>(Vec<T>);

impl<T: PartialEq<char>> Alphabet for DynamicAlphabet<T> {
	type Character = T;

	fn len(&self) -> usize {
		self.0.len()
	}

	fn is_empty(&self) -> bool {
		self.0.is_empty()
	}

	fn iter(&self) -> impl Iterator<Item = &Self::Character> {
		self.0.iter()
	}

	fn index_of(&self, char: char) -> Option<usize> {
		self.0.iter().position(|x| *x == char)
	}

	fn char_at(&self, index: usize) -> Option<&Self::Character> {
		self.0.get(index)
	}
}

impl<T> IntoIterator for DynamicAlphabet<T> {
	type Item = T;
	type IntoIter = std::vec::IntoIter<T>;

	fn into_iter(self) -> Self::IntoIter {
		self.0.into_iter()
	}
}

impl<'a, T> IntoIterator for &'a DynamicAlphabet<T> {
	type Item = &'a T;
	type IntoIter = std::slice::Iter<'a, T>;

	fn into_iter(self) -> Self::IntoIter {
		self.0.iter()
	}
}
