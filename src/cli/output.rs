//! Output handling utilities for the CLI
//!
//! Provides encoding options and output formatting for binary data.

use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::ValueEnum;

/// Encoding format for binary data
#[derive(ValueEnum, Clone, Copy, Default, Debug, PartialEq, Eq)]
pub enum Encoding {
	/// Hexadecimal encoding
	Hex,
	/// Base64 encoding
	#[default]
	Base64,
}

/// Encode bytes to a string using the specified encoding
pub fn encode_bytes(data: &[u8], encoding: Encoding) -> String {
	match encoding {
		Encoding::Hex => hex::encode(data),
		Encoding::Base64 => {
			use base64::prelude::*;
			BASE64_STANDARD.encode(data)
		}
	}
}

/// Write text output to stdout or a file
pub fn write_text(text: &str, output_file: Option<&PathBuf>) -> Result<()> {
	match output_file {
		Some(path) => std::fs::write(path, text)
			.with_context(|| format!("Failed to write to file: {}", path.display())),
		None => {
			println!("{}", text);
			Ok(())
		}
	}
}

/// Write binary output to stdout or a file
pub fn write_binary(data: &[u8], output_file: Option<&PathBuf>) -> Result<()> {
	match output_file {
		Some(path) => std::fs::write(path, data)
			.with_context(|| format!("Failed to write to file: {}", path.display())),
		None => {
			io::stdout()
				.write_all(data)
				.context("Failed to write to stdout")?;
			io::stdout().flush().context("Failed to flush stdout")
		}
	}
}

/// Write encoded binary data as text (hex or base64)
pub fn write_encoded(data: &[u8], encoding: Encoding, output_file: Option<&PathBuf>) -> Result<()> {
	let encoded = encode_bytes(data, encoding);
	write_text(&encoded, output_file)
}
