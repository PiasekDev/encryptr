pub struct Alphabet(pub String);

impl Default for Alphabet {
	fn default() -> Self {
		Self::new("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	}
}

impl Alphabet {
	pub fn new(s: &str) -> Self {
		Alphabet(s.chars().flat_map(|c| c.to_uppercase()).collect()) // TODO: error on multichar?
	}

	pub fn polish() -> Self {
		Self::new("AĄBCĆDEĘFGHIJKLŁMNŃOÓPRSŚTUWYZŹŻ")
	}
}
