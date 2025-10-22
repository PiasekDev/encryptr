pub struct Alphabet(pub String);

impl Default for Alphabet {
	fn default() -> Self {
		Self::new("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	}
}

impl Alphabet {
	pub fn new(s: &str) -> Self {
		Alphabet(s.to_owned())
	}

	pub fn polish() -> Self {
		Self::new("AĄBCĆDEĘFGHIJKLŁMNŃOÓPRSŚTUWYZŹŻ")
	}
}
