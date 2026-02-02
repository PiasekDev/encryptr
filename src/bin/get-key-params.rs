use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;

use encryptr::cipher::rsa::key::{RSAKeyPair, RSAPrivateKey, RSAPublicKey};

/// Print parameters of an RSA key (public, private or key pair) stored in PEM/DER.
#[derive(Parser)]
struct Cli {
	/// Path to key file (PEM or DER)
	#[arg(value_name = "FILE")]
	file: PathBuf,
}

fn main() -> Result<()> {
	let cli = Cli::parse();
	run(cli)
}

fn run(cli: Cli) -> Result<()> {
	let content = std::fs::read_to_string(&cli.file)
		.with_context(|| format!("Failed to read key file: {}", cli.file.display()))?;

	// Try key pair first
	if let Ok(kp) = RSAKeyPair::from_pem(&content) {
		print_key_pair(&kp);
		return Ok(());
	}

	// Try public key
	if let Ok(pubk) = RSAPublicKey::from_pem(&content) {
		print_public_key(&pubk);
		return Ok(());
	}

	// Try private key
	if let Ok(privk) = RSAPrivateKey::from_pem(&content) {
		print_private_key(&privk);
		return Ok(());
	}

	anyhow::bail!("Failed to parse key file: not a recognized RSA public/private/key-pair PEM")
}

fn print_public_key(k: &RSAPublicKey) {
	println!("Key type: public");
	let bits = k.n.bits();
	println!("Modulus (bits): {}", bits);
	println!("Modulus byte length: {}", k.byte_length());
	println!("Public exponent (dec): {}", k.e.to_str_radix(10));
	println!("Public exponent (hex): 0x{}", k.e.to_str_radix(16));
	println!("Modulus (hex): 0x{}", k.n.to_str_radix(16));
}

fn print_private_key(k: &RSAPrivateKey) {
	println!("Key type: private");
	let bits = k.n.bits();
	println!("Modulus (bits): {}", bits);
	println!("Modulus byte length: {}", k.byte_length());
	println!("Private exponent (dec): {}", k.d.to_str_radix(10));
	println!("Private exponent (hex): 0x{}", k.d.to_str_radix(16));
	println!("Modulus (hex): 0x{}", k.n.to_str_radix(16));
}

fn print_key_pair(kp: &RSAKeyPair) {
	println!("Key type: key pair");
	print_public_key(&kp.public_key);
	// print private exponent as well
	println!("--- private key ---");
	print_private_key(&kp.private_key);
}
