use encryptr::char_ext::CharExt;

fn main() {
	println!("Hello, encryption!");

	let characters = ['@', 'A', 'a', '1', '!', 'ß', 'Σ'];
	for c in characters {
		let uppercase = c.to_uppercase_char();
		let lowercase = c.to_lowercase_char();
		let case = c.case();
		println!("Character: {}, Uppercase: {:?}, Lowercase: {:?}, Case: {:?}", c, uppercase, lowercase, case);
	}
}
