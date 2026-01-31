use num_bigint::{BigUint, RandomBits};
use rand::prelude::Distribution;

pub struct RSAKeyPair {
	pub public_key: RSAPublicKey,
	pub private_key: RSAPrivateKey,
}

pub struct RSAPublicKey {
	pub n: BigUint,
	pub e: BigUint,
}

pub struct RSAPrivateKey {
	pub n: BigUint,
	pub d: BigUint,
}

impl RSAKeyPair {
	pub fn generate(bits: u64, rng: &mut impl rand::Rng) -> Self {
		let (p, q) = generate_pq(bits, rng);

		let n = &p * &q;
		let phi_n = (&p - BigUint::from(1u8)) * (&q - BigUint::from(1u8));
		let e = choose_e(&phi_n);
		let d = e.modinv(&phi_n).expect("e should be coprime to phi_n");

		let public_key = RSAPublicKey { n: n.clone(), e };
		let private_key = RSAPrivateKey { n, d };
		Self {
			public_key,
			private_key,
		}
	}
}

fn choose_e(phi_n: &BigUint) -> BigUint {
	const DEFAULT_PUBLIC_EXPONENT: u64 = 65537;
	let mut e = BigUint::from(DEFAULT_PUBLIC_EXPONENT);

	loop {
		if BigUint::from(1u8) < e && e < *phi_n && gcd(&e, phi_n) == BigUint::from(1u8) {
			return e;
		}

		e += BigUint::from(2u8);
	}
}

pub fn generate_pq(bits: u64, rng: &mut impl rand::Rng) -> (BigUint, BigUint) {
	let p_bits = bits / 2;
	let q_bits = bits - p_bits;

	loop {
		let p = generate_prime(p_bits, rng);
		let q = generate_prime(q_bits, rng);
		if p != q {
			return (p, q);
		}
	}
}

pub fn generate_prime(bits: u64, rng: &mut impl rand::Rng) -> BigUint {
	loop {
		let mut candidate: BigUint = RandomBits::new(bits).sample(rng);
		// Even candidates cannot be prime
		candidate.set_bit(0, true);

		// Force set the highest bit to ensure the number has the desired bit length (the random generator might set the highest bits to zero)
		candidate.set_bit(bits - 1, true);

		if miller_rabin::is_prime(&candidate, 40) {
			return candidate;
		}
	}
}

pub fn gcd(a: &BigUint, b: &BigUint) -> BigUint {
	let mut a = a.clone();
	let mut b = b.clone();

	while b != BigUint::ZERO {
		(b, a) = (a % &b, b);
	}

	a
}
