//! Cryptanalysis utilities for cracking classical ciphers
//!
//! This module provides educational tools for breaking classical ciphers
//! using techniques like:
//! - Brute-force attacks (Caesar)
//! - Frequency analysis (Substitution, Caesar)
//! - Kasiski examination (Vigenere)

use std::collections::HashMap;

use clap::{Args, Subcommand};
use encryptr::alphabet::Alphabet;
use encryptr::cipher::Cipher;

use super::alphabet::AlphabetType;
use super::input::get_text;

/// English letter frequencies (approximate)
const ENGLISH_FREQUENCIES: [f64; 26] = [
	0.0817, // A
	0.0149, // B
	0.0278, // C
	0.0425, // D
	0.1270, // E
	0.0223, // F
	0.0202, // G
	0.0609, // H
	0.0697, // I
	0.0015, // J
	0.0077, // K
	0.0403, // L
	0.0241, // M
	0.0675, // N
	0.0751, // O
	0.0193, // P
	0.0010, // Q
	0.0599, // R
	0.0633, // S
	0.0906, // T
	0.0276, // U
	0.0098, // V
	0.0236, // W
	0.0015, // X
	0.0197, // Y
	0.0007, // Z
];

#[derive(Subcommand)]
pub enum CrackAction {
	/// Crack a Caesar cipher using brute-force
	Caesar(CrackCaesarArgs),
	/// Analyze letter frequencies in ciphertext
	Frequency(FrequencyArgs),
	/// Attempt to crack a Vigenere cipher
	Vigenere(CrackVigenereArgs),
}

#[derive(Args)]
pub struct CrackCaesarArgs {
	/// Ciphertext to crack (reads from stdin if not provided)
	ciphertext: Option<String>,

	/// Read ciphertext from file
	#[arg(short, long)]
	file: Option<String>,

	/// Alphabet to use
	#[arg(short, long, value_enum, default_value = "ascii")]
	alphabet: AlphabetType,

	/// Show all 26 possibilities instead of best guess
	#[arg(long)]
	all: bool,

	/// Number of top results to show (default: 5)
	#[arg(short = 'n', long, default_value = "5")]
	top: usize,
}

#[derive(Args)]
pub struct FrequencyArgs {
	/// Text to analyze (reads from stdin if not provided)
	text: Option<String>,

	/// Read text from file
	#[arg(short, long)]
	file: Option<String>,

	/// Show comparison with English frequencies
	#[arg(long)]
	compare: bool,
}

#[derive(Args)]
pub struct CrackVigenereArgs {
	/// Ciphertext to crack (reads from stdin if not provided)
	ciphertext: Option<String>,

	/// Read ciphertext from file
	#[arg(short, long)]
	file: Option<String>,

	/// Maximum key length to try (default: 20)
	#[arg(short, long, default_value = "20")]
	max_key_length: usize,

	/// Number of top key length candidates to show (default: 5)
	#[arg(short = 'n', long, default_value = "5")]
	top: usize,
}

pub fn run(action: CrackAction) -> anyhow::Result<()> {
	match action {
		CrackAction::Caesar(args) => crack_caesar(args),
		CrackAction::Frequency(args) => analyze_frequency(args),
		CrackAction::Vigenere(args) => crack_vigenere(args),
	}
}

/// Calculate letter frequencies in text
fn calculate_frequencies(text: &str) -> HashMap<char, usize> {
	let mut counts: HashMap<char, usize> = HashMap::new();
	for c in text.chars() {
		if c.is_ascii_alphabetic() {
			let upper = c.to_ascii_uppercase();
			*counts.entry(upper).or_default() += 1;
		}
	}
	counts
}

/// Calculate chi-squared statistic comparing observed frequencies to English
fn chi_squared_score(text: &str) -> f64 {
	let counts = calculate_frequencies(text);
	let total: usize = counts.values().sum();
	if total == 0 {
		return f64::MAX;
	}

	let total_f64 = total as f64;
	let mut chi_sq = 0.0;

	for (i, &expected_freq) in ENGLISH_FREQUENCIES.iter().enumerate() {
		let letter = (b'A' + i as u8) as char;
		let observed = *counts.get(&letter).unwrap_or(&0) as f64 / total_f64;
		let diff = observed - expected_freq;
		chi_sq += (diff * diff) / expected_freq;
	}

	chi_sq
}

fn crack_caesar(args: CrackCaesarArgs) -> anyhow::Result<()> {
	let ciphertext = get_text(
		args.ciphertext.as_deref(),
		args.file.as_ref().map(std::path::PathBuf::from).as_ref(),
	)?;
	let alphabet = args.alphabet.to_char_alphabet();
	let alphabet_len = alphabet.len();

	println!("Cracking Caesar cipher...\n");

	// Try all possible offsets
	let mut results: Vec<(usize, f64, String)> = Vec::new();

	for offset in 0..alphabet_len {
		let caesar = encryptr::cipher::caesar::CaesarCipher::new(alphabet.clone(), offset);
		let decrypted = caesar.decipher(&ciphertext);
		let score = chi_squared_score(&decrypted);
		results.push((offset, score, decrypted));
	}

	// Sort by chi-squared score (lower is better)
	results.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

	let display_count = if args.all { alphabet_len } else { args.top };

	println!(
		"Top {} results (lower score = better match to English):\n",
		display_count
	);
	println!("{:>6} {:>10} Plaintext", "Offset", "Score");
	println!("{}", "-".repeat(60));

	for (offset, score, plaintext) in results.iter().take(display_count) {
		let preview: String = plaintext.chars().take(40).collect();
		let preview = if plaintext.len() > 40 {
			format!("{}...", preview)
		} else {
			preview
		};
		println!("{:>6} {:>10.4} {}", offset, score, preview);
	}

	if !args.all {
		println!("\nMost likely key offset: {}", results[0].0);
		println!("\nDecrypted message:");
		println!("{}", results[0].2);
	}

	Ok(())
}

fn analyze_frequency(args: FrequencyArgs) -> anyhow::Result<()> {
	let text = get_text(
		args.text.as_deref(),
		args.file.as_ref().map(std::path::PathBuf::from).as_ref(),
	)?;

	let counts = calculate_frequencies(&text);
	let total: usize = counts.values().sum();

	if total == 0 {
		println!("No alphabetic characters found in input.");
		return Ok(());
	}

	println!("Letter Frequency Analysis\n");
	println!("Total letters: {}\n", total);

	// Sort by frequency (descending)
	let mut freq_list: Vec<(char, usize)> = counts.into_iter().collect();
	freq_list.sort_by(|a, b| b.1.cmp(&a.1));

	if args.compare {
		println!(
			"{:>6} {:>8} {:>10} {:>10}",
			"Letter", "Count", "Observed", "English"
		);
		println!("{}", "-".repeat(40));

		for (letter, count) in &freq_list {
			let observed = *count as f64 / total as f64;
			let idx = (*letter as u8 - b'A') as usize;
			let expected = ENGLISH_FREQUENCIES[idx];
			println!(
				"{:>6} {:>8} {:>10.2}% {:>10.2}%",
				letter,
				count,
				observed * 100.0,
				expected * 100.0
			);
		}

		// Show most common English letters
		println!("\nMost common in English: E T A O I N S H R");
		println!(
			"Most common in text:    {}",
			freq_list
				.iter()
				.take(9)
				.map(|(c, _)| *c)
				.collect::<String>()
		);
	} else {
		println!("{:>6} {:>8} {:>10}", "Letter", "Count", "Frequency");
		println!("{}", "-".repeat(30));

		for (letter, count) in &freq_list {
			let freq = *count as f64 / total as f64 * 100.0;
			// Visual bar
			let bar_len = (freq * 2.0) as usize;
			let bar: String = "█".repeat(bar_len);
			println!("{:>6} {:>8} {:>6.2}% {}", letter, count, freq, bar);
		}
	}

	// Show Index of Coincidence
	let ioc = index_of_coincidence(&text);
	println!("\nIndex of Coincidence: {:.4}", ioc);
	println!("(English ~0.067, Random ~0.038)");

	Ok(())
}

/// Calculate Index of Coincidence
fn index_of_coincidence(text: &str) -> f64 {
	let counts = calculate_frequencies(text);
	let n: usize = counts.values().sum();
	if n <= 1 {
		return 0.0;
	}

	let sum: usize = counts.values().map(|&c| c * c.saturating_sub(1)).sum();
	sum as f64 / (n * (n - 1)) as f64
}

fn crack_vigenere(args: CrackVigenereArgs) -> anyhow::Result<()> {
	let ciphertext = get_text(
		args.ciphertext.as_deref(),
		args.file.as_ref().map(std::path::PathBuf::from).as_ref(),
	)?;

	// Extract only alphabetic characters for analysis
	let clean: String = ciphertext
		.chars()
		.filter(|c| c.is_ascii_alphabetic())
		.map(|c| c.to_ascii_uppercase())
		.collect();

	if clean.len() < 20 {
		anyhow::bail!("Ciphertext too short for reliable analysis (need at least 20 letters)");
	}

	println!("Vigenere Cipher Analysis\n");
	println!("Ciphertext length: {} letters\n", clean.len());

	// Step 1: Estimate key length using Kasiski examination
	println!("=== Key Length Analysis ===\n");

	let mut key_length_scores: Vec<(usize, f64)> = Vec::new();

	for key_len in 2..=args.max_key_length.min(clean.len() / 3) {
		// Calculate average IoC for columns
		let mut total_ioc = 0.0;
		for col in 0..key_len {
			let column: String = clean
				.chars()
				.enumerate()
				.filter(|(i, _)| i % key_len == col)
				.map(|(_, c)| c)
				.collect();
			total_ioc += index_of_coincidence(&column);
		}
		let avg_ioc = total_ioc / key_len as f64;
		key_length_scores.push((key_len, avg_ioc));
	}

	// Sort by IoC (higher is better - closer to English)
	key_length_scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

	println!(
		"Top {} likely key lengths (by Index of Coincidence):\n",
		args.top
	);
	println!("{:>10} {:>12}", "Key Length", "Avg IoC");
	println!("{}", "-".repeat(25));

	for (key_len, ioc) in key_length_scores.iter().take(args.top) {
		let marker = if *ioc > 0.060 { " *" } else { "" };
		println!("{:>10} {:>12.4}{}", key_len, ioc, marker);
	}

	println!("\n(* = likely candidate, English IoC ~0.067)\n");

	// Step 2: For the most likely key length, attempt to find the key
	let best_key_len = key_length_scores[0].0;
	println!(
		"=== Attempting Key Recovery (length {}) ===\n",
		best_key_len
	);

	let mut probable_key = String::new();

	for col in 0..best_key_len {
		let column: String = clean
			.chars()
			.enumerate()
			.filter(|(i, _)| i % best_key_len == col)
			.map(|(_, c)| c)
			.collect();

		// Try each possible shift and find best chi-squared match
		let mut best_shift = 0;
		let mut best_score = f64::MAX;

		for shift in 0..26 {
			let decrypted: String = column
				.chars()
				.map(|c| {
					let idx = (c as u8 - b'A') as i32;
					let new_idx = (idx - shift + 26) % 26;
					(b'A' + new_idx as u8) as char
				})
				.collect();
			let score = chi_squared_score(&decrypted);
			if score < best_score {
				best_score = score;
				best_shift = shift;
			}
		}

		let key_char = (b'A' + best_shift as u8) as char;
		probable_key.push(key_char);
	}

	println!("Probable key: {}\n", probable_key);

	// Decrypt with the probable key
	let alphabet = Alphabet::ascii_uppercase();
	let vigenere = encryptr::cipher::vigenere::VigenereCipher::new(alphabet, &probable_key)
		.expect("Probable key should be valid uppercase ASCII");
	let decrypted = vigenere.decode(&ciphertext);

	println!("=== Decrypted Message (first 200 chars) ===\n");
	let preview: String = decrypted.chars().take(200).collect();
	println!("{}", preview);
	if decrypted.len() > 200 {
		println!("...\n");
	}

	println!("\nNote: Results may be inaccurate for short texts or non-English plaintexts.");
	println!("Try different key lengths if the result doesn't look right.");

	Ok(())
}
