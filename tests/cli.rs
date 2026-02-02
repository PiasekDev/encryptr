//! Integration tests for the encryptr CLI
//!
//! These tests verify the end-to-end behavior of the CLI application.

use assert_cmd::Command;
use predicates::prelude::*;

fn encryptr() -> Command {
	Command::cargo_bin("encryptr").unwrap()
}

mod caesar {
	use super::*;

	#[test]
	fn encode_basic() {
		encryptr()
			.args(["caesar", "encode", "--offset", "3", "HELLO WORLD"])
			.assert()
			.success()
			.stdout("KHOOR ZRUOG\n");
	}

	#[test]
	fn decode_basic() {
		encryptr()
			.args(["caesar", "decode", "--offset", "3", "KHOOR ZRUOG"])
			.assert()
			.success()
			.stdout("HELLO WORLD\n");
	}

	#[test]
	fn roundtrip() {
		let plaintext = "THE QUICK BROWN FOX";
		let offset = "13";

		// Encode
		let output = encryptr()
			.args(["caesar", "encode", "--offset", offset, plaintext])
			.output()
			.unwrap();
		let ciphertext = String::from_utf8(output.stdout).unwrap();
		let ciphertext = ciphertext.trim();

		// Decode
		encryptr()
			.args(["caesar", "decode", "--offset", offset, ciphertext])
			.assert()
			.success()
			.stdout(format!("{plaintext}\n"));
	}

	#[test]
	fn preserves_non_alpha() {
		encryptr()
			.args(["caesar", "encode", "--offset", "1", "A1B2C3!"])
			.assert()
			.success()
			.stdout("B1C2D3!\n");
	}

	#[test]
	fn cased_alphabet() {
		encryptr()
			.args([
				"caesar",
				"encode",
				"--offset",
				"3",
				"--alphabet",
				"cased",
				"Hello World",
			])
			.assert()
			.success()
			.stdout("Khoor Zruog\n");
	}

	#[test]
	fn stdin_input() {
		encryptr()
			.args(["caesar", "encode", "--offset", "3"])
			.write_stdin("HELLO\n")
			.assert()
			.success()
			.stdout("KHOOR\n");
	}
}

mod vigenere {
	use super::*;

	#[test]
	fn encode_basic() {
		encryptr()
			.args(["vigenere", "encode", "--keyword", "LEMON", "ATTACKATDAWN"])
			.assert()
			.success()
			.stdout("LXFOPVEFRNHR\n");
	}

	#[test]
	fn decode_basic() {
		encryptr()
			.args(["vigenere", "decode", "--keyword", "LEMON", "LXFOPVEFRNHR"])
			.assert()
			.success()
			.stdout("ATTACKATDAWN\n");
	}

	#[test]
	fn roundtrip() {
		let plaintext = "SECRETMESSAGE";
		let keyword = "KEY";

		let output = encryptr()
			.args(["vigenere", "encode", "--keyword", keyword, plaintext])
			.output()
			.unwrap();
		let ciphertext = String::from_utf8(output.stdout).unwrap();
		let ciphertext = ciphertext.trim();

		encryptr()
			.args(["vigenere", "decode", "--keyword", keyword, ciphertext])
			.assert()
			.success()
			.stdout(format!("{plaintext}\n"));
	}
}

mod affine {
	use super::*;

	#[test]
	fn encode_basic() {
		encryptr()
			.args(["affine", "encode", "--a", "5", "--b", "8", "HELLO"])
			.assert()
			.success()
			.stdout("RCLLA\n");
	}

	#[test]
	fn decode_basic() {
		encryptr()
			.args(["affine", "decode", "--a", "5", "--b", "8", "RCLLA"])
			.assert()
			.success()
			.stdout("HELLO\n");
	}

	#[test]
	fn roundtrip() {
		let plaintext = "CRYPTOGRAPHY";
		let a = "7";
		let b = "3";

		let output = encryptr()
			.args(["affine", "encode", "--a", a, "--b", b, plaintext])
			.output()
			.unwrap();
		let ciphertext = String::from_utf8(output.stdout).unwrap();
		let ciphertext = ciphertext.trim();

		encryptr()
			.args(["affine", "decode", "--a", a, "--b", b, ciphertext])
			.assert()
			.success()
			.stdout(format!("{plaintext}\n"));
	}

	#[test]
	fn invalid_a_not_coprime() {
		// a=2 is not coprime with 26
		encryptr()
			.args(["affine", "encode", "--a", "2", "--b", "0", "HELLO"])
			.assert()
			.failure()
			.stderr(predicate::str::contains("coprime").or(predicate::str::contains("error")));
	}
}

mod substitution {
	use super::*;

	#[test]
	fn encode_basic() {
		encryptr()
			.args([
				"substitution",
				"encode",
				"--mapping",
				"QWERTYUIOPASDFGHJKLZXCVBNM",
				"HELLO",
			])
			.assert()
			.success()
			.stdout("ITSSG\n");
	}

	#[test]
	fn decode_basic() {
		encryptr()
			.args([
				"substitution",
				"decode",
				"--mapping",
				"QWERTYUIOPASDFGHJKLZXCVBNM",
				"ITSSG",
			])
			.assert()
			.success()
			.stdout("HELLO\n");
	}

	#[test]
	fn roundtrip() {
		let plaintext = "THEQUICKBROWNFOX";
		let mapping = "ZYXWVUTSRQPONMLKJIHGFEDCBA"; // Reverse alphabet

		let output = encryptr()
			.args(["substitution", "encode", "--mapping", mapping, plaintext])
			.output()
			.unwrap();
		let ciphertext = String::from_utf8(output.stdout).unwrap();
		let ciphertext = ciphertext.trim();

		encryptr()
			.args(["substitution", "decode", "--mapping", mapping, ciphertext])
			.assert()
			.success()
			.stdout(format!("{plaintext}\n"));
	}
}

mod des {
	use super::*;

	#[test]
	fn encode_decode_roundtrip() {
		let plaintext = "Hello!";
		let key = "0123456789ABCDEF";

		// Encode
		let output = encryptr()
			.args(["des", "encode", "--key", key, plaintext])
			.output()
			.unwrap();
		let ciphertext = String::from_utf8(output.stdout).unwrap();
		let ciphertext = ciphertext.trim();

		// Decode
		encryptr()
			.args(["des", "decode", "--key", key, ciphertext])
			.assert()
			.success()
			.stdout(format!("{plaintext}\n"));
	}

	#[test]
	fn hex_output() {
		encryptr()
			.args([
				"des",
				"encode",
				"--key",
				"0123456789ABCDEF",
				"--encoding",
				"hex",
				"Hello!",
			])
			.assert()
			.success()
			.stdout(predicate::str::is_match("^[0-9a-f]+\n$").unwrap());
	}

	#[test]
	fn base64_output() {
		encryptr()
			.args([
				"des",
				"encode",
				"--key",
				"0123456789ABCDEF",
				"--encoding",
				"base64",
				"Hello!",
			])
			.assert()
			.success()
			.stdout(predicate::str::is_match("^[A-Za-z0-9+/]+=*\n$").unwrap());
	}

	#[test]
	fn invalid_key_length() {
		encryptr()
			.args(["des", "encode", "--key", "SHORTKEY", "Hello"])
			.assert()
			.failure();
	}
}

mod rsa {
	use super::*;
	use std::fs;

	#[test]
	fn generate_keypair() {
		let temp_dir = tempfile::tempdir().unwrap();
		let key_path = temp_dir.path().join("test.pem");

		encryptr()
			.args([
				"rsa",
				"generate",
				"--bits",
				"512",
				"--output",
				key_path.to_str().unwrap(),
			])
			.assert()
			.success();

		// Verify file exists and contains PEM data
		let content = fs::read_to_string(&key_path).unwrap();
		assert!(content.contains("BEGIN ENCRYPTR RSA KEY PAIR"));
		assert!(content.contains("END ENCRYPTR RSA KEY PAIR"));
	}

	#[test]
	fn export_public_key() {
		let temp_dir = tempfile::tempdir().unwrap();
		let private_path = temp_dir.path().join("private.pem");
		let public_path = temp_dir.path().join("public.pem");

		// Generate keypair
		encryptr()
			.args([
				"rsa",
				"generate",
				"--bits",
				"512",
				"--output",
				private_path.to_str().unwrap(),
			])
			.assert()
			.success();

		// Export public key
		encryptr()
			.args([
				"rsa",
				"export-public",
				"--key-pair",
				private_path.to_str().unwrap(),
				"--output",
				public_path.to_str().unwrap(),
			])
			.assert()
			.success();

		// Verify public key file
		let content = fs::read_to_string(&public_path).unwrap();
		assert!(content.contains("BEGIN ENCRYPTR RSA PUBLIC KEY"));
		assert!(content.contains("END ENCRYPTR RSA PUBLIC KEY"));
	}

	#[test]
	fn encrypt_decrypt_roundtrip() {
		let temp_dir = tempfile::tempdir().unwrap();
		let key_path = temp_dir.path().join("keypair.pem");
		let plaintext = "Secret";

		// Generate keypair
		encryptr()
			.args([
				"rsa",
				"generate",
				"--bits",
				"512",
				"--output",
				key_path.to_str().unwrap(),
			])
			.assert()
			.success();

		// Encrypt
		let output = encryptr()
			.args([
				"rsa",
				"encrypt",
				"--public-key",
				key_path.to_str().unwrap(),
				plaintext,
			])
			.output()
			.unwrap();
		let ciphertext = String::from_utf8(output.stdout).unwrap();
		let ciphertext = ciphertext.trim();

		// Decrypt
		encryptr()
			.args([
				"rsa",
				"decrypt",
				"--private-key",
				key_path.to_str().unwrap(),
				ciphertext,
			])
			.assert()
			.success()
			.stdout(format!("{plaintext}\n"));
	}

	#[test]
	fn export_private_key() {
		let temp_dir = tempfile::tempdir().unwrap();
		let keypair_path = temp_dir.path().join("keypair.pem");
		let private_path = temp_dir.path().join("private.pem");

		// Generate keypair
		encryptr()
			.args([
				"rsa",
				"generate",
				"--bits",
				"512",
				"--output",
				keypair_path.to_str().unwrap(),
			])
			.assert()
			.success();

		// Export private key
		encryptr()
			.args([
				"rsa",
				"export-private",
				"--key-pair",
				keypair_path.to_str().unwrap(),
				"--output",
				private_path.to_str().unwrap(),
			])
			.assert()
			.success();

		// Verify private key file
		let content = fs::read_to_string(&private_path).unwrap();
		assert!(content.contains("BEGIN ENCRYPTR RSA PRIVATE KEY"));
		assert!(content.contains("END ENCRYPTR RSA PRIVATE KEY"));
	}

	#[test]
	fn generate_separate_files() {
		let temp_dir = tempfile::tempdir().unwrap();
		let public_path = temp_dir.path().join("pub.pem");
		let private_path = temp_dir.path().join("priv.pem");

		// Generate to separate files
		encryptr()
			.args([
				"rsa",
				"generate",
				"--bits",
				"512",
				"--public-key",
				public_path.to_str().unwrap(),
				"--private-key",
				private_path.to_str().unwrap(),
			])
			.assert()
			.success();

		// Verify both files exist with correct content
		let pub_content = fs::read_to_string(&public_path).unwrap();
		assert!(pub_content.contains("BEGIN ENCRYPTR RSA PUBLIC KEY"));

		let priv_content = fs::read_to_string(&private_path).unwrap();
		assert!(priv_content.contains("BEGIN ENCRYPTR RSA PRIVATE KEY"));
	}

	#[test]
	fn generate_public_only() {
		let temp_dir = tempfile::tempdir().unwrap();
		let public_path = temp_dir.path().join("pub.pem");

		// Generate only public key
		encryptr()
			.args([
				"rsa",
				"generate",
				"--bits",
				"512",
				"--public-key",
				public_path.to_str().unwrap(),
			])
			.assert()
			.success();

		// Verify public key file exists
		let content = fs::read_to_string(&public_path).unwrap();
		assert!(content.contains("BEGIN ENCRYPTR RSA PUBLIC KEY"));
	}

	#[test]
	fn generate_private_only() {
		let temp_dir = tempfile::tempdir().unwrap();
		let private_path = temp_dir.path().join("priv.pem");

		// Generate only private key
		encryptr()
			.args([
				"rsa",
				"generate",
				"--bits",
				"512",
				"--private-key",
				private_path.to_str().unwrap(),
			])
			.assert()
			.success();

		// Verify private key file exists
		let content = fs::read_to_string(&private_path).unwrap();
		assert!(content.contains("BEGIN ENCRYPTR RSA PRIVATE KEY"));
	}

	#[test]
	fn split_keypair() {
		let temp_dir = tempfile::tempdir().unwrap();
		let keypair_path = temp_dir.path().join("keypair.pem");
		let public_path = temp_dir.path().join("split-pub.pem");
		let private_path = temp_dir.path().join("split-priv.pem");

		// Generate keypair
		encryptr()
			.args([
				"rsa",
				"generate",
				"--bits",
				"512",
				"--output",
				keypair_path.to_str().unwrap(),
			])
			.assert()
			.success();

		// Split with explicit paths
		encryptr()
			.args([
				"rsa",
				"split",
				"--key-pair",
				keypair_path.to_str().unwrap(),
				"--public-key",
				public_path.to_str().unwrap(),
				"--private-key",
				private_path.to_str().unwrap(),
			])
			.assert()
			.success();

		// Verify both files exist
		let pub_content = fs::read_to_string(&public_path).unwrap();
		assert!(pub_content.contains("BEGIN ENCRYPTR RSA PUBLIC KEY"));

		let priv_content = fs::read_to_string(&private_path).unwrap();
		assert!(priv_content.contains("BEGIN ENCRYPTR RSA PRIVATE KEY"));
	}

	#[test]
	fn split_keypair_auto_names() {
		let temp_dir = tempfile::tempdir().unwrap();
		let keypair_path = temp_dir.path().join("mykey.pem");

		// Generate keypair
		encryptr()
			.args([
				"rsa",
				"generate",
				"--bits",
				"512",
				"--output",
				keypair_path.to_str().unwrap(),
			])
			.assert()
			.success();

		// Split with auto-naming
		encryptr()
			.args(["rsa", "split", "--key-pair", keypair_path.to_str().unwrap()])
			.assert()
			.success();

		// Verify auto-named files exist
		let public_path = temp_dir.path().join("mykey.pub.pem");
		let private_path = temp_dir.path().join("mykey.priv.pem");

		let pub_content = fs::read_to_string(&public_path).unwrap();
		assert!(pub_content.contains("BEGIN ENCRYPTR RSA PUBLIC KEY"));

		let priv_content = fs::read_to_string(&private_path).unwrap();
		assert!(priv_content.contains("BEGIN ENCRYPTR RSA PRIVATE KEY"));
	}

	#[test]
	fn encrypt_decrypt_with_split_keys() {
		let temp_dir = tempfile::tempdir().unwrap();
		let keypair_path = temp_dir.path().join("keypair.pem");
		let public_path = temp_dir.path().join("pub.pem");
		let private_path = temp_dir.path().join("priv.pem");
		let plaintext = "TopSecret";

		// Generate and split
		encryptr()
			.args([
				"rsa",
				"generate",
				"--bits",
				"512",
				"--output",
				keypair_path.to_str().unwrap(),
			])
			.assert()
			.success();

		encryptr()
			.args([
				"rsa",
				"split",
				"--key-pair",
				keypair_path.to_str().unwrap(),
				"--public-key",
				public_path.to_str().unwrap(),
				"--private-key",
				private_path.to_str().unwrap(),
			])
			.assert()
			.success();

		// Encrypt with public key only
		let output = encryptr()
			.args([
				"rsa",
				"encrypt",
				"--public-key",
				public_path.to_str().unwrap(),
				plaintext,
			])
			.output()
			.unwrap();
		let ciphertext = String::from_utf8(output.stdout).unwrap();
		let ciphertext = ciphertext.trim();

		// Decrypt with private key only
		encryptr()
			.args([
				"rsa",
				"decrypt",
				"--private-key",
				private_path.to_str().unwrap(),
				ciphertext,
			])
			.assert()
			.success()
			.stdout(format!("{plaintext}\n"));
	}

	#[test]
	fn generate_conflicts_output_with_separate() {
		encryptr()
			.args([
				"rsa",
				"generate",
				"--bits",
				"512",
				"--output",
				"/tmp/out.pem",
				"--public-key",
				"/tmp/pub.pem",
			])
			.assert()
			.failure()
			.stderr(predicate::str::contains("cannot be used with"));
	}

	#[test]
	fn inspect_keypair() {
		let temp_dir = tempfile::tempdir().unwrap();
		let keypair_path = temp_dir.path().join("keypair.pem");

		// Generate keypair
		encryptr()
			.args([
				"rsa",
				"generate",
				"--bits",
				"512",
				"--output",
				keypair_path.to_str().unwrap(),
			])
			.assert()
			.success();

		// Inspect keypair
		encryptr()
			.args(["rsa", "inspect", "--key", keypair_path.to_str().unwrap()])
			.assert()
			.success()
			.stdout(predicate::str::contains("Key Type:            Key Pair"))
			.stdout(predicate::str::contains("Bit Length:          512 bits"))
			.stdout(predicate::str::contains("Modulus (n):         0x"))
			.stdout(predicate::str::contains("Public Exponent (e): 65537"))
			.stdout(predicate::str::contains("Private Exponent (d): 0x"));
	}

	#[test]
	fn inspect_public_key() {
		let temp_dir = tempfile::tempdir().unwrap();
		let keypair_path = temp_dir.path().join("keypair.pem");
		let public_path = temp_dir.path().join("public.pem");

		// Generate and export public key
		encryptr()
			.args([
				"rsa",
				"generate",
				"--bits",
				"512",
				"--output",
				keypair_path.to_str().unwrap(),
			])
			.assert()
			.success();

		encryptr()
			.args([
				"rsa",
				"export-public",
				"--key-pair",
				keypair_path.to_str().unwrap(),
				"--output",
				public_path.to_str().unwrap(),
			])
			.assert()
			.success();

		// Inspect public key
		encryptr()
			.args(["rsa", "inspect", "--key", public_path.to_str().unwrap()])
			.assert()
			.success()
			.stdout(predicate::str::contains("Key Type:            Public Key"))
			.stdout(predicate::str::contains("Bit Length:          512 bits"))
			.stdout(predicate::str::contains("Modulus (n):         0x"))
			.stdout(predicate::str::contains("Public Exponent (e): 65537"))
			// Should NOT contain private exponent
			.stdout(predicate::str::contains("Private Exponent").not());
	}

	#[test]
	fn inspect_private_key() {
		let temp_dir = tempfile::tempdir().unwrap();
		let keypair_path = temp_dir.path().join("keypair.pem");
		let private_path = temp_dir.path().join("private.pem");

		// Generate and export private key
		encryptr()
			.args([
				"rsa",
				"generate",
				"--bits",
				"512",
				"--output",
				keypair_path.to_str().unwrap(),
			])
			.assert()
			.success();

		encryptr()
			.args([
				"rsa",
				"export-private",
				"--key-pair",
				keypair_path.to_str().unwrap(),
				"--output",
				private_path.to_str().unwrap(),
			])
			.assert()
			.success();

		// Inspect private key
		encryptr()
			.args(["rsa", "inspect", "--key", private_path.to_str().unwrap()])
			.assert()
			.success()
			.stdout(predicate::str::contains("Key Type:            Private Key"))
			.stdout(predicate::str::contains("Bit Length:          512 bits"))
			.stdout(predicate::str::contains("Modulus (n):         0x"))
			.stdout(predicate::str::contains("Private Exponent (d): 0x"))
			// Should NOT contain public exponent
			.stdout(predicate::str::contains("Public Exponent").not());
	}

	#[test]
	fn inspect_invalid_file() {
		let temp_dir = tempfile::tempdir().unwrap();
		let invalid_path = temp_dir.path().join("invalid.pem");
		fs::write(&invalid_path, "not a valid key").unwrap();

		encryptr()
			.args(["rsa", "inspect", "--key", invalid_path.to_str().unwrap()])
			.assert()
			.failure()
			.stderr(predicate::str::contains("Failed to parse key file"));
	}
}

mod completions {
	use super::*;

	#[test]
	fn bash_completions() {
		encryptr()
			.args(["completions", "bash"])
			.assert()
			.success()
			.stdout(predicate::str::contains("_encryptr()"));
	}

	#[test]
	fn zsh_completions() {
		encryptr()
			.args(["completions", "zsh"])
			.assert()
			.success()
			.stdout(predicate::str::contains("#compdef encryptr"));
	}

	#[test]
	fn fish_completions() {
		encryptr()
			.args(["completions", "fish"])
			.assert()
			.success()
			.stdout(predicate::str::contains("complete"));
	}
}

mod help {
	use super::*;

	#[test]
	fn main_help() {
		encryptr()
			.arg("--help")
			.assert()
			.success()
			.stdout(predicate::str::contains("PiasekDev's cryptography toolkit"))
			.stdout(predicate::str::contains("caesar"))
			.stdout(predicate::str::contains("vigenere"))
			.stdout(predicate::str::contains("affine"))
			.stdout(predicate::str::contains("substitution"))
			.stdout(predicate::str::contains("des"))
			.stdout(predicate::str::contains("rsa"));
	}

	#[test]
	fn version() {
		encryptr()
			.arg("--version")
			.assert()
			.success()
			.stdout(predicate::str::contains("encryptr"));
	}

	#[test]
	fn caesar_help() {
		encryptr()
			.args(["caesar", "--help"])
			.assert()
			.success()
			.stdout(predicate::str::contains("encode"))
			.stdout(predicate::str::contains("decode"));
	}
}

mod crack {
	use super::*;

	#[test]
	fn caesar_crack() {
		// Encrypt "THE QUICK BROWN FOX" with offset 3
		encryptr()
			.args([
				"crack",
				"caesar",
				"WKH TXLFN EURZQ IRA MXPSV RYHU WKH ODCB GRJ",
			])
			.assert()
			.success()
			.stdout(predicate::str::contains("THE QUICK BROWN FOX"))
			.stdout(predicate::str::contains("Most likely key offset: 3"));
	}

	#[test]
	fn frequency_analysis() {
		encryptr()
			.args(["crack", "frequency", "HELLO WORLD"])
			.assert()
			.success()
			.stdout(predicate::str::contains("Letter Frequency Analysis"))
			.stdout(predicate::str::contains("Index of Coincidence"));
	}

	#[test]
	fn frequency_compare() {
		encryptr()
			.args(["crack", "frequency", "--compare", "HELLO WORLD"])
			.assert()
			.success()
			.stdout(predicate::str::contains("English"))
			.stdout(predicate::str::contains("Most common in English"));
	}

	#[test]
	fn vigenere_crack() {
		// Need a longer ciphertext for Vigenere analysis
		let ciphertext = "LXFOPVEFRNHRLXFOPVEFRNHRLXFOPVEFRNHRLXFOPVEFRNHR";
		encryptr()
			.args(["crack", "vigenere", ciphertext])
			.assert()
			.success()
			.stdout(predicate::str::contains("Vigenere Cipher Analysis"))
			.stdout(predicate::str::contains("Key Length Analysis"))
			.stdout(predicate::str::contains("Probable key"));
	}

	#[test]
	fn vigenere_too_short() {
		encryptr()
			.args(["crack", "vigenere", "SHORT"])
			.assert()
			.failure()
			.stderr(predicate::str::contains("too short"));
	}

	#[test]
	fn crack_help() {
		encryptr()
			.args(["crack", "--help"])
			.assert()
			.success()
			.stdout(predicate::str::contains("caesar"))
			.stdout(predicate::str::contains("frequency"))
			.stdout(predicate::str::contains("vigenere"));
	}
}
