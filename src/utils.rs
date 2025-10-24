pub fn flip_ascii_case(char: char) -> Option<char> {
	ascii_xor(char, b'_')
}

pub fn ascii_xor(char: char, key: u8) -> Option<char> {
	if char.is_ascii() {
		let xored = (char as u8) ^ key;
		Some(xored as char)
	} else {
		None
	}
}
