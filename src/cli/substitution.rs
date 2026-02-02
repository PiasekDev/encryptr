//! Substitution cipher CLI command
//!
//! Implements the `encryptr substitution` subcommand for encoding/decoding with a simple substitution cipher.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};

use super::alphabet::AlphabetType;
use super::input;
use super::output;
use encryptr::alphabet::Alphabet;
use encryptr::cipher::substitution::SubstitutionCipher;

/// Substitution cipher actions
#[derive(Subcommand)]
pub enum SubstitutionAction {
	/// Encode (encipher) text using substitution cipher
	Encode(SubstitutionArgs),
	/// Decode (decipher) text using substitution cipher
	Decode(SubstitutionArgs),
}

/// Arguments for Substitution cipher operations
#[derive(Args)]
pub struct SubstitutionArgs {
	/// Substitution mapping (e.g., "QWERTYUIOPASDFGHJKLZXCVBNM" for 26-char alphabet)
	///
	/// Must be exactly the same length as the source alphabet.
	#[arg(short, long)]
	pub mapping: String,

	/// Source alphabet to use (note: cased alphabet not supported)
	#[arg(short, long, default_value = "ascii")]
	pub alphabet: AlphabetType,

	/// Text to process (reads from stdin if not provided)
	pub text: Option<String>,

	/// Read input from file
	#[arg(long, value_name = "FILE")]
	pub input_file: Option<PathBuf>,

	/// Write output to file
	#[arg(long, value_name = "FILE")]
	pub output_file: Option<PathBuf>,
}

/// Run the Substitution cipher command
pub fn run(action: SubstitutionAction) -> Result<()> {
	match action {
		SubstitutionAction::Encode(args) => encode(args),
		SubstitutionAction::Decode(args) => decode(args),
	}
}

fn create_cipher(args: &SubstitutionArgs) -> Result<SubstitutionCipher> {
	if args.alphabet.is_cased() {
		anyhow::bail!(
			"Substitution cipher does not support case-preserving alphabet. Use 'ascii' or 'polish'."
		);
	}

	let source_alphabet = args.alphabet.to_char_alphabet();
	let mapping_alphabet: Alphabet<char> = args.mapping.chars().collect();

	let expected_len = source_alphabet.len();
	let actual_len = mapping_alphabet.len();

	SubstitutionCipher::new(source_alphabet, mapping_alphabet).map_err(|_| {
		anyhow::anyhow!(
			"Invalid mapping length: expected {} characters, got {}",
			expected_len,
			actual_len
		)
	})
}

fn encode(args: SubstitutionArgs) -> Result<()> {
	let input = input::get_text(args.text.as_deref(), args.input_file.as_ref())?;
	let cipher = create_cipher(&args)?;
	let result = cipher.encode(&input);
	output::write_text(&result, args.output_file.as_ref())
}

fn decode(args: SubstitutionArgs) -> Result<()> {
	let input = input::get_text(args.text.as_deref(), args.input_file.as_ref())?;
	let cipher = create_cipher(&args)?;
	let result = cipher.decode(&input);
	output::write_text(&result, args.output_file.as_ref())
}
