pub trait Alphabet<C> {
	fn len(&self) -> usize;

	fn is_empty(&self) -> bool;

	fn iter<'a>(&'a self) -> impl Iterator<Item = &'a C> where C: 'a;

	fn index_of(&self, char: char) -> Option<usize>;

	fn char_at(&self, index: usize) -> Option<C>;
}

pub struct UncasedAlphabet(Vec<char>);

impl Alphabet<char> for UncasedAlphabet {
	fn len(&self) -> usize {
		self.len()
	}

	fn is_empty(&self) -> bool {
		self.is_empty()
	}

	fn iter<'a>(&'a self) -> impl Iterator<Item = &'a char> where char: 'a {
		self.iter()
	}

	fn index_of(&self, c: char) -> Option<usize> {
		self.index_of(c)
	}

	fn char_at(&self, index: usize) -> Option<char> {
		self.char_at(index)
	}
}

impl Default for UncasedAlphabet {
	fn default() -> Self {
		Self::new("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	}
}

impl UncasedAlphabet {
	pub fn new(s: &str) -> Self {
		UncasedAlphabet(s.chars().collect())
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

	pub fn iter(&self) -> impl Iterator<Item = &char> {
		self.into_iter()
	}

	pub fn index_of(&self, c: char) -> Option<usize> {
		self.0.iter().position(|&x| x == c)
	}

	pub fn char_at(&self, index: usize) -> Option<char> {
		self.0.get(index).copied()
	}
}

impl IntoIterator for UncasedAlphabet {
	type Item = char;
	type IntoIter = std::vec::IntoIter<char>;

	fn into_iter(self) -> Self::IntoIter {
		self.0.into_iter()
	}
}

impl<'a> IntoIterator for &'a UncasedAlphabet {
	type Item = &'a char;
	type IntoIter = std::slice::Iter<'a, char>;

	#[inline]
	fn into_iter(self) -> Self::IntoIter {
		self.0.iter()
	}
}

pub struct CasedAlphabet(Vec<CasedChar>);

#[derive(Debug, Copy, Clone)]
pub struct CasedChar {
	upper: char,
	lower: char,
}

impl Alphabet<CasedChar> for CasedAlphabet {
	fn len(&self) -> usize {
		self.0.len()
	}

	fn is_empty(&self) -> bool {
		self.0.is_empty()
	}

	fn iter<'a>(&'a self) -> impl Iterator<Item = &'a CasedChar> where CasedChar: 'a {
		self.0.iter()
	}

	fn index_of(&self, char: char) -> Option<usize> {
		self.0.iter().position(|x| x.upper == char || x.lower == char)
	}

	fn char_at(&self, index: usize) -> Option<CasedChar> {
		self.0.get(index).copied()
	}
}

// impl ten alphabet<alphabet char dla tego> + impl dwie wersja algorytmu dla caesar cipher. use impl <Alphavbet<AlphavbetChar> for CasedAlphabet> blocks for tow impl blocks
