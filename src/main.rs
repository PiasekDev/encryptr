fn main() {
	let letter = '.';
	let xored = (letter as u8) ^ 0x20;
	println!("'{}' XOR 0x20 = '{}'", letter, xored as char);
	// xor spacji z literami da litery, w innym przypadku raczej coś co nie jest znakiem

	// 	let text = "QPWKA LVRXC QZIKG RBPFA EOMFL  JMSDZ VDHXC XJYEB IMTRQ WNMEA
	// IZRVK CVKVL XNEIC FZPZC ZZHKM  LVZVZ IZRRQ WDKEC HOSNY XXLSP
	// MYKVQ XJTDC IOMEE XDQVS RXLRL  KZHOV";

	// key length 10, ALANTURING
	let text = "IEIFGIKIYZOREGAYICAXELSBGUSTRZOOEFVLZJRJIRIGTFT
WZVUEEELUJJEGIYSSHLRVLUNPCNEWLTNZIZNGAYNPBREARB
VYUCEKTSAGMBVUNIHTNRBMKWTUTSRBNAYQFVLLNAXXFCGON
LDITHTMOEAXAGAYDIGOCTAAMBVTRYSOOHUNKPRXETSNUILB
JNAEIFZIZVTZOSACIYEBUKBPTGXLKPRSAEHRFUKQPOAYIFI
FVIFKDTTVLZRQEZODALMBRBGNEXAPACEMQUEDNGHLZOVTAE
ENGSKPVTGTFVMCJIPIEATRWNYIGXELLOKUZVFGSQOHGXZVN
TIXAYLUELVTPLRGBWLTNXIYMRGUIMNYOCTBYGRKUONPIGPC
CTSULWOJMBRBBAROITBNRTPUMAUGXLJCVZAMLLILFOEGMXE
QPCCTOKHLVRECBMNHRLIABNYQAQIEIFILFJNHLPFBKCEAGG
NNEGAUKIGZHPEAWIWBUKTHEAMCVBUIEYTHKSZBJOLWBRIIJ
AVHLPTBILFOEGMXENFUTPVTEEONGMNMEWUPSGBIEAVTSFCU
TQRGGNAEIGPCCTOKEITEXGVTLJIQFVVOCBGUGFEFLQYMGNE
CTUXUEAJKRDAEXVVQAMGTVRGVPIZGNZRORNYMZGCSIAX";
	let ic = encryptr::index::index_of_coincidence(text);
	println!("Index of Coincidence: {}", ic);

	let cleaned: Vec<char> = text.chars().filter(|c| c.is_ascii_alphabetic()).collect();
	let mut averages = Vec::new();
	for n in 1..=20 {
		let mut avg_ic = 0.0;
		for offset in 0..n {
			let column: String = cleaned.iter().skip(offset).step_by(n).collect::<String>();
			avg_ic += encryptr::index::index_of_coincidence(&column);
			// if encryptr::index::index_of_coincidence(&column) > 0.55 {
			// 	println!(
			// 		"[*] Chunk: {}, IC: {}",
			// 		&column,
			// 		encryptr::index::index_of_coincidence(&column)
			// 	);
			// } else {
			// 	println!(
			// 		"Chunk: {}, IC: {}",
			// 		&column,
			// 		encryptr::index::index_of_coincidence(&column)
			// 	);
			// }
		}
		avg_ic /= n as f64;
		println!("n = {n:2}: avg IC = {avg_ic}");
		averages.push((n, avg_ic));
	}

	averages.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
	println!("Top averages:");
	for (n, avg_ic) in averages.iter().take(5) {
		println!("n = {n:2}: avg IC = {avg_ic}");
		if avg_ic > &0.55 {
			println!("[*] Found promising chunk size: {n}");
		}
	}

	// let test_no_whitespace = text.replace(" ", "").replace("\n", "");
	// for n in 1..=20 {
	// 	let chunks: Vec<&str> = test_no_whitespace
	// 		.as_bytes()
	// 		.chunks(n)
	// 		.map(|chunk| std::str::from_utf8(chunk).unwrap())
	// 		.collect();
	// 	let mut sum_ic = 0.0;
	// 	for chunk in &chunks {
	// 		sum_ic += encryptr::index::index_of_coincidence(chunk);
	// 		if encryptr::index::index_of_coincidence(chunk) > 0.55 {
	// 			println!(
	// 				"[*] Chunk: {}, IC: {}",
	// 				chunk,
	// 				encryptr::index::index_of_coincidence(chunk)
	// 			);
	// 		} else {
	// 			println!(
	// 				"Chunk: {}, IC: {}",
	// 				chunk,
	// 				encryptr::index::index_of_coincidence(chunk)
	// 			);
	// 		}
	// 	}
	// 	// let avg_ic = sum_ic / chunks.len() as f64;
	// 	// println!("n = {:2}: Average IC = {}", n, avg_ic);
	// }
}
