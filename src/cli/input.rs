//! Input handling utilities for the CLI
//!
//! Provides unified input handling from positional arguments, stdin, or files.

use std::io::{self, IsTerminal, Read};
use std::path::PathBuf;

use anyhow::{Context, Result, bail};

use super::output::Encoding;

/// Get text input from one of three sources: positional argument, file, or stdin
pub fn get_text(text: Option<&str>, input_file: Option<&PathBuf>) -> Result<String> {
	match (text, input_file) {
		(Some(t), None) => Ok(t.to_string()),
		(None, Some(path)) => std::fs::read_to_string(path)
			.with_context(|| format!("Failed to read file: {}", path.display())),
		(None, None) => {
			// Read from stdin
			if io::stdin().is_terminal() {
				bail!(
					"No input provided. Provide TEXT argument, --input-file, or pipe data to stdin."
				);
			}
			let mut buffer = String::new();
			io::stdin()
				.read_to_string(&mut buffer)
				.context("Failed to read from stdin")?;
			// Trim trailing newline that's typically added by echo/pipes
			Ok(buffer.trim_end_matches('\n').to_string())
		}
		(Some(_), Some(_)) => {
			bail!("Cannot specify both TEXT argument and --input-file")
		}
	}
}

/// Get binary input, decoding from the specified encoding if reading from text sources
pub fn get_binary(
	text: Option<&str>,
	input_file: Option<&PathBuf>,
	encoding: Encoding,
) -> Result<Vec<u8>> {
	match (text, input_file) {
		(Some(t), None) => decode_bytes(t, encoding),
		(None, Some(path)) => {
			std::fs::read(path).with_context(|| format!("Failed to read file: {}", path.display()))
		}
		(None, None) => {
			// Read from stdin
			if io::stdin().is_terminal() {
				bail!(
					"No input provided. Provide TEXT argument, --input-file, or pipe data to stdin."
				);
			}
			let mut buffer = Vec::new();
			io::stdin()
				.read_to_end(&mut buffer)
				.context("Failed to read from stdin")?;
			Ok(buffer)
		}
		(Some(_), Some(_)) => {
			bail!("Cannot specify both TEXT argument and --input-file")
		}
	}
}

/// Get binary input where the text argument is expected to be encoded (hex/base64)
pub fn get_encoded_binary(
	text: Option<&str>,
	input_file: Option<&PathBuf>,
	encoding: Encoding,
) -> Result<Vec<u8>> {
	let data = get_text(text, input_file)?;
	decode_bytes(&data, encoding)
}

/// Decode bytes from a string using the specified encoding
fn decode_bytes(s: &str, encoding: Encoding) -> Result<Vec<u8>> {
	let s = s.trim();
	match encoding {
		Encoding::Hex => hex::decode(s).context("Invalid hex encoding"),
		Encoding::Base64 => {
			use base64::prelude::*;
			BASE64_STANDARD.decode(s).context("Invalid base64 encoding")
		}
	}
}
