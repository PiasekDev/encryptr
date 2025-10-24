pub struct Alphabet(Vec<char>);

impl Default for Alphabet {
	fn default() -> Self {
		Self::new("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	}
}

impl Alphabet {
	pub fn new(s: &str) -> Self {
		Alphabet(s.chars().collect())
	}

	pub fn polish() -> Self {
		Self::new("AĄBCĆDEĘFGHIJKLŁMNŃOÓPRSŚTUWYZŹŻ")
	}

	pub fn len(&self) -> usize {
		self.0.len()
	}

	pub fn is_empty(&self) -> bool {
		self.0.is_empty()
	}

	pub fn iter(&self) -> std::slice::Iter<'_, char> {
		self.0.iter()
	}

	pub fn index_of(&self, c: char) -> Option<usize> {
		self.0.iter().position(|&x| x == c)
	}

	pub fn char_at(&self, index: usize) -> Option<char> {
		self.0.get(index).copied()
	}
}

impl IntoIterator for Alphabet {
	type Item = char;
	type IntoIter = std::vec::IntoIter<char>;

	fn into_iter(self) -> Self::IntoIter {
		self.0.into_iter()
	}
}

impl<'a> IntoIterator for &'a Alphabet {
	type Item = &'a char;
	type IntoIter = std::slice::Iter<'a, char>;

	fn into_iter(self) -> Self::IntoIter {
		self.iter()
	}
}
