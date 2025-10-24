use itertools::Itertools;

pub fn index_of_coincidence(text: &str) -> f64 {
	let mut frequencies = std::collections::HashMap::new();
	let mut total_chars = 0;

	for c in text.chars().filter(|c| c.is_ascii_alphabetic()) {
		let counter = frequencies.entry(c.to_ascii_uppercase()).or_insert(0);
		*counter += 1;
		total_chars += 1;
	}

	let mut ic = 0.0;
	for &count in frequencies.values() {
		ic += (count * (count - 1)) as f64;
	}
	let ic_denominator = total_chars * (total_chars - 1);
	ic / ic_denominator as f64
}

pub fn index_of_coincidence_v2(text: &str) -> f64 {
	let counts = text
		.chars()
		.filter(|c| c.is_ascii_alphabetic())
		.map(|x| x.to_ascii_uppercase())
		.counts();

	let ic: usize = counts.values().map(|count| count * (count - 1)).sum();
	let ic_denominator = counts.values().sum::<usize>() * (counts.values().sum::<usize>() - 1);

	ic as f64 / ic_denominator as f64
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_index_of_coincidence() {
		let text = "THERE ARETW OWAYS OFCON STRUC TINGA SOFTW AREDE SIGNO NEWAY
ISTOM AKEIT SOSIM PLETH ATTHE REARE OBVIO USLYN ODEFI CIENC
IESAN DTHEO THERW AYIST OMAKE ITSOC OMPLI CATED THATT HEREA
RENOO BVIOU SDEFI CIENC IESTH EFIRS TMETH ODISF ARMOR EDIFF
ICULT";
		let ic = index_of_coincidence(text);
		dbg!(ic);
		let i2 = index_of_coincidence_v2(text);
		dbg!(i2);
		dbg!(ic == i2);
		assert!((ic - i2).abs() < f64::EPSILON);
	}
}
